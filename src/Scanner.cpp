#include "Scanner.h"
#include "MaliciousHashLoader.h"
#include "DebugLog.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <fstream>
#include <iomanip>
#include <optional>
#include <regex>
#include <sstream>
#include <string_view>
#include <system_error>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    std::wstring ToLower(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        return value;
    }

    std::string ToLowerAscii(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    }

    std::wstring Trim(std::wstring value)
    {
        const auto notSpace = [](wchar_t ch) { return !std::iswspace(ch); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }

    std::string TrimAscii(std::string value)
    {
        const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }

    std::wstring NormalizePackageName(
        const std::wstring& ecosystem,
        std::wstring name)
    {
        name = ToLower(Trim(std::move(name)));
        if (ToLower(ecosystem) == L"pypi")
        {
            std::wstring canonical;
            canonical.reserve(name.size());
            bool separator = false;
            for (wchar_t ch : name)
            {
                if (ch == L'-' || ch == L'_' || ch == L'.')
                {
                    if (!separator)
                        canonical.push_back(L'-');
                    separator = true;
                }
                else
                {
                    canonical.push_back(ch);
                    separator = false;
                }
            }
            return canonical;
        }
        return name;
    }

    std::vector<std::string> ParseExactVersionList(std::string value)
    {
        // All supported feeds publish exact versions, but use different separators:
        // commas, "|" and "||", with optional leading "=".
        std::size_t pos = 0;
        while ((pos = value.find("||", pos)) != std::string::npos)
            value.replace(pos, 2, "|");

        std::replace(value.begin(), value.end(), ',', '|');

        std::vector<std::string> versions;
        std::stringstream stream(value);
        std::string version;
        while (std::getline(stream, version, '|'))
        {
            version = TrimAscii(version);
            while (!version.empty() &&
                   (version.front() == '=' || version.front() == '[' ||
                    version.front() == '\"' || version.front() == '\''))
            {
                version.erase(version.begin());
                version = TrimAscii(version);
            }
            while (!version.empty() &&
                   (version.back() == ']' || version.back() == '\"' ||
                    version.back() == '\''))
            {
                version.pop_back();
                version = TrimAscii(version);
            }
            if (!version.empty())
                versions.push_back(std::move(version));
        }
        return versions;
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty())
            return {};

        int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), nullptr, 0);
        UINT codePage = CP_UTF8;
        DWORD flags = MB_ERR_INVALID_CHARS;

        if (count <= 0)
        {
            codePage = CP_ACP;
            flags = 0;
            count = MultiByteToWideChar(codePage, flags, value.data(),
                static_cast<int>(value.size()), nullptr, 0);
        }
        if (count <= 0)
            return {};

        std::wstring result(static_cast<std::size_t>(count), L'\0');
        MultiByteToWideChar(codePage, flags, value.data(),
            static_cast<int>(value.size()), result.data(), count);
        return result;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};

        const int count = WideCharToMultiByte(CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (count <= 0)
            return {};

        std::string result(static_cast<std::size_t>(count), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()), result.data(), count, nullptr, nullptr);
        return result;
    }

    std::vector<std::string> ParseCsvLine(const std::string& line)
    {
        std::vector<std::string> fields;
        std::string current;
        bool quoted = false;

        for (std::size_t i = 0; i < line.size(); ++i)
        {
            const char ch = line[i];
            if (ch == '"')
            {
                if (quoted && i + 1 < line.size() && line[i + 1] == '"')
                {
                    current.push_back('"');
                    ++i;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (ch == ',' && !quoted)
            {
                fields.push_back(current);
                current.clear();
            }
            else
            {
                current.push_back(ch);
            }
        }

        fields.push_back(current);
        return fields;
    }

    std::unordered_map<std::string, std::size_t> HeaderMap(
        const std::vector<std::string>& fields)
    {
        std::unordered_map<std::string, std::size_t> result;
        for (std::size_t i = 0; i < fields.size(); ++i)
            result[ToLowerAscii(TrimAscii(fields[i]))] = i;
        return result;
    }

    std::string Field(
        const std::vector<std::string>& fields,
        const std::unordered_map<std::string, std::size_t>& headers,
        const char* name)
    {
        const auto it = headers.find(name);
        if (it == headers.end() || it->second >= fields.size())
            return {};
        return TrimAscii(fields[it->second]);
    }

    std::vector<std::wstring> SplitWide(const std::wstring& value, wchar_t delimiter)
    {
        std::vector<std::wstring> result;
        std::wstring current;
        std::wstringstream stream(value);
        while (std::getline(stream, current, delimiter))
        {
            current = Trim(current);
            if (!current.empty())
                result.push_back(current);
        }
        return result;
    }

    bool ReadFileLimited(
        const std::filesystem::path& path,
        std::uintmax_t maxBytes,
        std::string& output)
    {
        std::error_code ec;
        const auto size = std::filesystem::file_size(path, ec);
        if (ec || size > maxBytes)
            return false;

        std::ifstream input(path, std::ios::binary);
        if (!input)
            return false;

        output.resize(static_cast<std::size_t>(size));
        if (size != 0)
            input.read(output.data(), static_cast<std::streamsize>(size));
        return input.good() || input.eof();
    }

    std::optional<std::string> ExtractJsonString(
        const std::string& text,
        const std::string& key)
    {
        const std::string token = "\"" + key + "\"";
        std::size_t pos = text.find(token);
        if (pos == std::string::npos)
            return std::nullopt;

        pos = text.find(':', pos + token.size());
        if (pos == std::string::npos)
            return std::nullopt;

        ++pos;
        while (pos < text.size() &&
               std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        if (pos >= text.size() || text[pos] != '"')
            return std::nullopt;

        ++pos;
        std::string result;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (escaped)
            {
                switch (ch)
                {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                default: result.push_back(ch); break;
                }
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                return result;
            }
            else
            {
                result.push_back(ch);
            }
        }

        return std::nullopt;
    }

    bool ExtractPythonMetadata(
        const std::string& text,
        std::string& name,
        std::string& version)
    {
        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            const std::string lower = ToLowerAscii(line);
            if (name.empty() && lower.rfind("name:", 0) == 0)
                name = TrimAscii(line.substr(5));
            else if (version.empty() && lower.rfind("version:", 0) == 0)
                version = TrimAscii(line.substr(8));
            if (!name.empty() && !version.empty())
                return true;
        }
        return false;
    }

    std::string NormalizeRegistryText(std::string text)
    {
        text = ToLowerAscii(std::move(text));
        const std::pair<const char*, const char*> replacements[] =
        {
            { "%40", "@" },
            { "%2f", "/" },
            { "\\u0040", "@" },
            { "\\u002f", "/" }
        };

        for (const auto& replacement : replacements)
        {
            std::size_t pos = 0;
            while ((pos = text.find(replacement.first, pos)) != std::string::npos)
            {
                text.replace(pos, std::strlen(replacement.first), replacement.second);
                pos += std::strlen(replacement.second);
            }
        }
        return text;
    }

    std::vector<std::pair<std::string, std::string>> FindAffectedPairsInText(
        const IndicatorDatabase& database,
        const std::string& ecosystem,
        const std::string& original,
        std::size_t maximumMatches = 500)
    {
        const std::string text = NormalizeRegistryText(original);
        const std::string normalizedEcosystem = ToLowerAscii(ecosystem);
        std::vector<std::pair<std::string, std::string>> matches;
        std::unordered_set<std::string> seen;

        for (const auto& entry : database.TextEntries())
        {
            if (entry.ecosystem != normalizedEcosystem)
                continue;

            std::size_t namePos = text.find(entry.name);
            while (namePos != std::string::npos)
            {
                const std::size_t start = namePos > 384 ? namePos - 384 : 0;
                const std::size_t end = (std::min)(
                    text.size(), namePos + entry.name.size() + 1536);
                const std::string_view window(text.data() + start, end - start);

                for (const std::string& version : entry.versions)
                {
                    if (window.find(version) != std::string_view::npos)
                    {
                        const std::string key = entry.name + "\n" + version;
                        if (seen.insert(key).second)
                        {
                            matches.emplace_back(entry.name, version);
                            if (matches.size() >= maximumMatches)
                                return matches;
                        }
                    }
                }
                namePos = text.find(entry.name, namePos + entry.name.size());
            }
        }
        return matches;
    }

    bool CalculateHash(
        const std::filesystem::path& path,
        const wchar_t* algorithm,
        std::wstring& digest)
    {
        const wchar_t* providerName = nullptr;
        if (_wcsicmp(algorithm, L"SHA256") == 0)
            providerName = BCRYPT_SHA256_ALGORITHM;
        else if (_wcsicmp(algorithm, L"SHA1") == 0)
            providerName = BCRYPT_SHA1_ALGORITHM;
        else
            return false;

        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        BCRYPT_HASH_HANDLE hashHandle = nullptr;
        HANDLE fileHandle = INVALID_HANDLE_VALUE;
        std::vector<UCHAR> hashObject;
        std::vector<UCHAR> hashBytes;
        bool success = false;

        do
        {
            if (BCryptOpenAlgorithmProvider(
                    &algorithmHandle, providerName, nullptr, 0) < 0)
                break;

            DWORD objectLength = 0;
            DWORD hashLength = 0;
            DWORD resultLength = 0;
            if (BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                    &resultLength, 0) < 0)
                break;
            if (BCryptGetProperty(algorithmHandle, BCRYPT_HASH_LENGTH,
                    reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength),
                    &resultLength, 0) < 0)
                break;

            hashObject.resize(objectLength);
            hashBytes.resize(hashLength);
            if (BCryptCreateHash(algorithmHandle, &hashHandle,
                    hashObject.data(), static_cast<ULONG>(hashObject.size()),
                    nullptr, 0, 0) < 0)
                break;

            fileHandle = CreateFileW(path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
                break;

            std::vector<UCHAR> buffer(1024 * 1024);
            for (;;)
            {
                DWORD bytesRead = 0;
                if (!ReadFile(fileHandle, buffer.data(),
                        static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
                    break;

                if (bytesRead == 0)
                {
                    if (BCryptFinishHash(hashHandle, hashBytes.data(),
                            static_cast<ULONG>(hashBytes.size()), 0) < 0)
                        break;

                    std::wostringstream stream;
                    stream << std::hex << std::setfill(L'0');
                    for (UCHAR value : hashBytes)
                        stream << std::setw(2) << static_cast<unsigned int>(value);
                    digest = ToLower(stream.str());
                    success = true;
                    break;
                }

                if (BCryptHashData(hashHandle, buffer.data(), bytesRead, 0) < 0)
                    break;
            }
        } while (false);

        if (fileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(fileHandle);
        if (hashHandle)
            BCryptDestroyHash(hashHandle);
        if (algorithmHandle)
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return success;
    }

    bool IsNpmLockfileName(const std::wstring& lowerName)
    {
        return lowerName == L"package-lock.json" ||
            lowerName == L"npm-shrinkwrap.json" ||
            lowerName == L"yarn.lock" ||
            lowerName == L"pnpm-lock.yaml" ||
            lowerName == L"pnpm-lock.yml" ||
            lowerName == L"bun.lock" ||
            lowerName == L"bun.lockb";
    }

    bool IsPythonLockfileName(const std::wstring& lowerName)
    {
        return lowerName == L"poetry.lock" ||
            lowerName == L"uv.lock" ||
            lowerName == L"pdm.lock" ||
            lowerName == L"pipfile.lock" ||
            (lowerName.rfind(L"requirements", 0) == 0 &&
             lowerName.size() >= 4 &&
             lowerName.substr(lowerName.size() - 4) == L".txt");
    }

    bool IsGoDependencyFileName(const std::wstring& lowerName)
    {
        return lowerName == L"go.mod" || lowerName == L"go.sum";
    }

    bool IsScriptExtension(const std::wstring& extension)
    {
        return extension == L".js" || extension == L".mjs" ||
            extension == L".cjs" || extension == L".json" ||
            extension == L".yml" || extension == L".yaml" ||
            extension == L".ps1" || extension == L".sh" ||
            extension == L".py";
    }

    bool PathStartsWith(
        const std::filesystem::path& path,
        const std::filesystem::path& prefix)
    {
        if (prefix.empty())
            return false;

        std::wstring left = ToLower(path.lexically_normal().wstring());
        std::wstring right = ToLower(prefix.lexically_normal().wstring());
        while (!right.empty() && (right.back() == L'\\' || right.back() == L'/'))
            right.pop_back();

        if (left.size() < right.size() || left.compare(0, right.size(), right) != 0)
            return false;
        return left.size() == right.size() ||
            left[right.size()] == L'\\' || left[right.size()] == L'/';
    }

    bool HasAnyPathToken(
        const std::wstring& lowerPath,
        const std::vector<std::wstring>& tokens)
    {
        if (tokens.empty())
            return true;
        for (const auto& token : tokens)
        {
            if (!token.empty() &&
                lowerPath.find(ToLower(token)) != std::wstring::npos)
                return true;
        }
        return false;
    }

    bool IsNpmCachePath(const std::wstring& lowerPath)
    {
        return lowerPath.find(L"\\_cacache\\index-v5\\") != std::wstring::npos ||
            lowerPath.find(L"/_cacache/index-v5/") != std::wstring::npos ||
            lowerPath.find(L"\\npm-cache\\") != std::wstring::npos ||
            lowerPath.find(L"\\.npm\\") != std::wstring::npos ||
            lowerPath.find(L"\\pnpm\\store\\") != std::wstring::npos ||
            lowerPath.find(L"\\pnpm-store\\") != std::wstring::npos ||
            lowerPath.find(L"\\yarn\\cache\\") != std::wstring::npos ||
            lowerPath.find(L"\\corepack\\") != std::wstring::npos;
    }

    bool IsPythonCachePath(const std::wstring& lowerPath)
    {
        return lowerPath.find(L"\\pip\\cache\\") != std::wstring::npos ||
            lowerPath.find(L"\\pip-cache\\") != std::wstring::npos ||
            lowerPath.find(L"\\uv\\cache\\") != std::wstring::npos ||
            lowerPath.find(L"\\pypoetry\\cache\\") != std::wstring::npos;
    }

    bool IsPackageContext(const std::wstring& lowerPath)
    {
        return lowerPath.find(L"\\node_modules\\") != std::wstring::npos ||
            lowerPath.find(L"/node_modules/") != std::wstring::npos ||
            lowerPath.find(L"\\.pnpm\\") != std::wstring::npos ||
            lowerPath.find(L"/.pnpm/") != std::wstring::npos ||
            lowerPath.find(L"\\site-packages\\") != std::wstring::npos ||
            lowerPath.find(L"/site-packages/") != std::wstring::npos ||
            lowerPath.find(L"\\dist-packages\\") != std::wstring::npos ||
            lowerPath.find(L"/dist-packages/") != std::wstring::npos ||
            IsNpmCachePath(lowerPath) || IsPythonCachePath(lowerPath);
    }

    bool IsCandidateArtifactName(const std::wstring& lowerName)
    {
        const bool generatedMath =
            lowerName.rfind(L"math_", 0) == 0 &&
            lowerName.size() > 8 &&
            lowerName.ends_with(L".js");

        return lowerName == L"setup.mjs" ||
            lowerName == L"setup_bun.js" ||
            lowerName == L"bun_environment.js" ||
            lowerName == L"math_symbol.js" ||
            lowerName == L"math_init.js" ||
            lowerName == L"router_runtime.js" ||
            lowerName == L"gh-token-monitor.sh" ||
            lowerName == L"format-results.txt" ||
            lowerName == L"format.json" ||
            lowerName == L"cloud.json" ||
            lowerName == L"contents.json" ||
            lowerName == L"environment.json" ||
            lowerName == L"data.json" ||
            lowerName == L"trufflesecrets.json" ||
            lowerName == L"actionssecrets.json" ||
            lowerName == L"discussion.yaml" ||
            lowerName == L"discussion.yml" ||
            lowerName == L"bundle.js" ||
            generatedMath ||
            lowerName.rfind(L"formatter_", 0) == 0 ||
            lowerName.rfind(L"tmp.dpkg_", 0) == 0 ||
            lowerName.rfind(L"results-", 0) == 0 ||
            lowerName.find(L"bun-v1.3.13") != std::wstring::npos;
    }

    std::wstring JoinMarkers(const std::vector<std::wstring>& markers)
    {
        std::wstring joined;
        for (std::size_t i = 0; i < markers.size(); ++i)
        {
            if (i)
                joined += L", ";
            joined += markers[i];
        }
        return joined;
    }

    bool IsPermissionDenied(const std::error_code& ec)
    {
        return ec == std::errc::permission_denied ||
            ec.value() == ERROR_ACCESS_DENIED ||
            ec.value() == ERROR_SHARING_VIOLATION;
    }

    bool LooksLikePythonMetadata(const std::filesystem::path& path)
    {
        const std::wstring lowerName = ToLower(path.filename().wstring());
        if (lowerName != L"metadata" && lowerName != L"pkg-info")
            return false;
        const std::wstring parent = ToLower(path.parent_path().filename().wstring());
        return parent.find(L".dist-info") != std::wstring::npos ||
            parent.find(L".egg-info") != std::wstring::npos;
    }
}

IndicatorDatabase::IndicatorDatabase()
{
    ResetToBuiltIn();
}

void IndicatorDatabase::Clear()
{
    affected_.clear();
    textEntries_.clear();
    hashIndicators_.clear();
    textIndicators_.clear();
    hashKeys_.clear();
    hashTargetNames_.clear();
    textKeys_.clear();
    pairCount_ = 0;

    for (std::size_t i = 0; i < kKnownHashCount; ++i)
        AddHash(kKnownHashes[i].algorithm, kKnownHashes[i].digest,
            kKnownHashes[i].description);
    for (std::size_t i = 0; i < kKnownTextIndicatorCount; ++i)
        AddTextIndicator(kKnownTextIndicators[i].category,
            kKnownTextIndicators[i].value,
            kKnownTextIndicators[i].description,
            kKnownTextIndicators[i].highConfidence);
}

void IndicatorDatabase::ResetToBuiltIn(std::uint32_t sourceMask)
{
    Clear();
    AddBuiltIn(sourceMask);
}

void IndicatorDatabase::AddBuiltIn(std::uint32_t sourceMask)
{
    for (std::size_t i = 0; i < kAffectedPackageCount; ++i)
    {
        if ((kAffectedPackages[i].sourceMask & sourceMask) == 0)
            continue;
        AddPackage(kAffectedPackages[i].ecosystem,
            kAffectedPackages[i].name,
            kAffectedPackages[i].version);
    }
    RebuildTextEntries();
}

void IndicatorDatabase::AddPackage(
    const std::wstring& ecosystem,
    const std::wstring& name,
    const std::wstring& version)
{
    const std::wstring normalizedEcosystem = ToLower(Trim(ecosystem));
    const std::wstring normalizedName =
        NormalizePackageName(normalizedEcosystem, name);
    const std::wstring normalizedVersion = Trim(version);
    if (normalizedEcosystem.empty() || normalizedName.empty() ||
        normalizedVersion.empty())
        return;

    auto& versions = affected_[normalizedEcosystem][normalizedName];
    if (versions.insert(normalizedVersion).second)
        ++pairCount_;
}

void IndicatorDatabase::AddHash(
    const std::wstring& algorithm,
    const std::wstring& digest,
    const std::wstring& description,
    const std::vector<std::wstring>& filenames)
{
    const std::wstring normalizedAlgorithm = ToLower(Trim(algorithm));
    const std::wstring normalizedDigest = ToLower(Trim(digest));
    if (normalizedAlgorithm.empty() || normalizedDigest.empty())
        return;

    static const std::unordered_set<std::wstring> genericNames =
    {
        L"index.js", L"main.js", L"package.json", L"settings.json",
        L"tasks.json", L"bundle.js"
    };
    for (const auto& filename : filenames)
    {
        const std::wstring normalizedName = ToLower(Trim(filename));
        if (!normalizedName.empty() && !genericNames.contains(normalizedName))
            hashTargetNames_.insert(normalizedName);
    }

    const std::wstring key = normalizedAlgorithm + L":" + normalizedDigest;
    if (!hashKeys_.insert(key).second)
        return;

    DynamicHashIndicator indicator;
    indicator.algorithm = normalizedAlgorithm == L"sha1" ? L"SHA1" : L"SHA256";
    indicator.digest = normalizedDigest;
    indicator.description = description;
    indicator.filenames.reserve(filenames.size());
    for (const auto& filename : filenames)
    {
        const std::wstring normalizedName = ToLower(Trim(filename));
        if (!normalizedName.empty())
            indicator.filenames.push_back(normalizedName);
    }
    hashIndicators_.push_back(std::move(indicator));
}

void IndicatorDatabase::AddTextIndicator(
    const std::wstring& category,
    const std::wstring& value,
    const std::wstring& description,
    bool highConfidence)
{
    const std::wstring normalizedCategory = ToLower(Trim(category));
    const std::wstring normalizedValue = ToLower(Trim(value));
    if (normalizedCategory.empty() || normalizedValue.empty())
        return;

    const std::wstring key = normalizedCategory + L":" + normalizedValue;
    if (!textKeys_.insert(key).second)
        return;

    DynamicTextIndicator indicator;
    indicator.category = normalizedCategory;
    indicator.value = normalizedValue;
    indicator.description = description;
    indicator.highConfidence = highConfidence;
    textIndicators_.push_back(std::move(indicator));
}

bool IndicatorDatabase::MergeCsv(
    const std::filesystem::path& csvPath,
    std::wstring& error,
    std::size_t* addedPairs,
    std::size_t* parsedRows)
{
    std::ifstream input(csvPath, std::ios::binary);
    if (!input)
    {
        error = L"Could not open " + csvPath.wstring();
        return false;
    }

    std::string headerLine;
    if (!std::getline(input, headerLine))
    {
        error = L"CSV is empty.";
        return false;
    }
    if (!headerLine.empty() && headerLine.back() == '\r')
        headerLine.pop_back();
    if (headerLine.size() >= 3 &&
        static_cast<unsigned char>(headerLine[0]) == 0xEF &&
        static_cast<unsigned char>(headerLine[1]) == 0xBB &&
        static_cast<unsigned char>(headerLine[2]) == 0xBF)
        headerLine.erase(0, 3);

    const auto headers = HeaderMap(ParseCsvLine(headerLine));
    const bool socketSchema =
        headers.contains("ecosystem") && headers.contains("name") &&
        headers.contains("version");
    const bool safeDepSchema =
        headers.contains("item_type") && headers.contains("category") &&
        headers.contains("identifier") && headers.contains("detail");
    const bool simpleSchema =
        (headers.contains("package") || headers.contains("package_name")) &&
        (headers.contains("versions") || headers.contains("version"));

    if (!socketSchema && !safeDepSchema && !simpleSchema)
    {
        error = L"Unrecognized feed schema. Expected Socket, SafeDep, Wiz, Datadog, StepSecurity, JFrog, or normalized community columns.";
        return false;
    }

    const std::size_t pairsBefore = pairCount_;
    std::size_t rows = 0;
    std::string line;
    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;

        const auto fields = ParseCsvLine(line);
        if (socketSchema)
        {
            const std::string ecosystem = ToLowerAscii(Field(fields, headers, "ecosystem"));
            if (ecosystem.empty())
                continue;
            const std::string namespaceValue = Field(fields, headers, "namespace");
            const std::string name = Field(fields, headers, "name");
            const std::string version = Field(fields, headers, "version");
            const std::string fullName = namespaceValue.empty()
                ? name : namespaceValue + "/" + name;
            if (!fullName.empty() && !version.empty())
            {
                AddPackage(Utf8ToWide(ecosystem), Utf8ToWide(fullName),
                    Utf8ToWide(version));
                ++rows;
            }
        }
        else if (safeDepSchema)
        {
            const std::string itemType = ToLowerAscii(Field(fields, headers, "item_type"));
            const std::string category = ToLowerAscii(Field(fields, headers, "category"));
            const std::string identifier = Field(fields, headers, "identifier");
            const std::string detail = Field(fields, headers, "detail");

            if (itemType == "package" &&
                (category == "npm" || category == "pypi" ||
                 category == "golang"))
            {
                const std::string lowerDetail = ToLowerAscii(detail);
                const std::size_t marker = lowerDetail.rfind("versions:");
                if (marker != std::string::npos)
                {
                    const std::string versions = detail.substr(marker + 9);
                    std::stringstream stream(versions);
                    std::string version;
                    while (std::getline(stream, version, ','))
                    {
                        version = TrimAscii(version);
                        if (!identifier.empty() && !version.empty())
                            AddPackage(Utf8ToWide(category), Utf8ToWide(identifier),
                                Utf8ToWide(version));
                    }
                    ++rows;
                }
            }
            else if (itemType == "indicator" && !identifier.empty())
            {
                if (category == "sha256" &&
                    identifier.size() == 64)
                {
                    AddHash(L"SHA256", Utf8ToWide(identifier), Utf8ToWide(detail));
                    ++rows;
                }
                else if (category == "sha1" && identifier.size() == 40 &&
                         ToLowerAscii(detail).find("commit-like") == std::string::npos)
                {
                    AddHash(L"SHA1", Utf8ToWide(identifier), Utf8ToWide(detail));
                    ++rows;
                }
                else if (category == "domain" || category == "ipv4" ||
                         category == "wallet" || category == "url")
                {
                    const std::string lowerValue = ToLowerAscii(identifier);
                    const bool generic = lowerValue == "1.1.1.1" ||
                        lowerValue == "8.8.8.8" ||
                        lowerValue == "169.254.169.254" ||
                        lowerValue == "169.254.170.2" ||
                        lowerValue == "www.youtube.com";
                    const bool highConfidence = !generic &&
                        (category == "domain" || category == "wallet" ||
                         category == "url");
                    AddTextIndicator(Utf8ToWide(category), Utf8ToWide(identifier),
                        Utf8ToWide(detail), highConfidence);
                    ++rows;
                }
            }
        }
        else
        {
            const std::string package = Field(fields, headers,
                headers.contains("package") ? "package" : "package_name");
            std::string versions = Field(fields, headers,
                headers.contains("versions") ? "versions" : "version");
            std::string ecosystem = headers.contains("ecosystem")
                ? ToLowerAscii(Field(fields, headers, "ecosystem"))
                : headers.contains("package_type")
                    ? ToLowerAscii(Field(fields, headers, "package_type"))
                    : "npm";
            if (ecosystem.empty())
                ecosystem = "npm";

            std::string name = package;
            // Support a generic unscoped "name@version" fallback without
            // splitting scoped npm names such as @scope/package.
            const std::size_t at = package.rfind('@');
            if (at != std::string::npos && at > 0 && package[0] != '@')
            {
                name = package.substr(0, at);
                if (versions.empty())
                    versions = package.substr(at + 1);
            }

            bool added = false;
            for (const auto& version : ParseExactVersionList(versions))
            {
                if (!name.empty())
                {
                    AddPackage(Utf8ToWide(ecosystem), Utf8ToWide(name),
                        Utf8ToWide(version));
                    added = true;
                }
            }
            if (added)
                ++rows;
        }
    }

    RebuildTextEntries();
    if (addedPairs)
        *addedPairs = pairCount_ - pairsBefore;
    if (parsedRows)
        *parsedRows = rows;

    if (rows == 0)
    {
        error = L"Recognized CSV schema, but no usable package or IOC rows were found.";
        return false;
    }

    std::wostringstream status;
    status << L"parsed " << rows << L" rows; added "
           << (pairCount_ - pairsBefore) << L" new package/version pairs";
    error = status.str();
    return true;
}

bool IndicatorDatabase::MergeMaliciousHashesJson(
    const std::filesystem::path& jsonPath,
    std::wstring& message,
    std::size_t* loadedEntries,
    std::size_t* addedEntries,
    std::size_t* skippedEntries)
{
    if (loadedEntries) *loadedEntries = 0;
    if (addedEntries) *addedEntries = 0;
    if (skippedEntries) *skippedEntries = 0;

    MaliciousHashLoadResult result;
    std::string error;
    if (!LoadMaliciousHashesJson(jsonPath, result, error))
    {
        message = L"Could not load malicious_hashes.json: " + Utf8ToWide(error);
        DebugLog::Write("HASH/JSON", message);
        return false;
    }

    const std::size_t before = hashIndicators_.size();
    for (const auto& record : result.records)
    {
        std::vector<std::wstring> filenames;
        filenames.reserve(record.filenames.size());
        for (const auto& filename : record.filenames)
            filenames.push_back(Utf8ToWide(filename));

        std::wstring description;
        if (!record.campaign.empty())
            description = Utf8ToWide(record.campaign) + L": ";
        description += Utf8ToWide(record.description);
        if (!record.source.empty())
            description += L" [source: " + Utf8ToWide(record.source) + L"]";
        AddHash(Utf8ToWide(record.algorithm), Utf8ToWide(record.digest),
            description, filenames);
    }

    if (loadedEntries) *loadedEntries = result.records.size();
    if (addedEntries) *addedEntries = hashIndicators_.size() - before;
    if (skippedEntries) *skippedEntries = result.skippedEntries;

    std::wostringstream summary;
    summary << L"Loaded malicious_hashes.json: " << result.records.size()
        << L" valid entries, " << (hashIndicators_.size() - before)
        << L" new hashes, " << result.skippedEntries << L" skipped.";
    if (!result.warnings.empty())
        summary << L" First warning: " << Utf8ToWide(result.warnings.front());
    message = summary.str();
    DebugLog::Write("HASH/JSON", message);
    for (const auto& warning : result.warnings)
        DebugLog::Write("HASH/JSON", L"Warning: " + Utf8ToWide(warning));
    return true;
}

bool IndicatorDatabase::IsAffected(
    const std::wstring& ecosystem,
    const std::wstring& name,
    const std::wstring& version) const
{
    const auto ecosystemIt = affected_.find(ToLower(Trim(ecosystem)));
    if (ecosystemIt == affected_.end())
        return false;
    const auto packageIt = ecosystemIt->second.find(
        NormalizePackageName(ecosystemIt->first, name));
    if (packageIt == ecosystemIt->second.end())
        return false;
    return packageIt->second.contains(Trim(version));
}

std::size_t IndicatorDatabase::PairCount() const noexcept
{
    return pairCount_;
}

std::size_t IndicatorDatabase::PackageCount() const noexcept
{
    std::size_t total = 0;
    for (const auto& ecosystem : affected_)
        total += ecosystem.second.size();
    return total;
}

const std::vector<TextSearchEntry>& IndicatorDatabase::TextEntries() const noexcept
{
    return textEntries_;
}

const std::vector<DynamicHashIndicator>&
IndicatorDatabase::HashIndicators() const noexcept
{
    return hashIndicators_;
}

const std::vector<DynamicTextIndicator>&
IndicatorDatabase::TextIndicators() const noexcept
{
    return textIndicators_;
}


bool IndicatorDatabase::ShouldHashFileName(
    const std::wstring& lowerFileName) const noexcept
{
    return hashTargetNames_.contains(lowerFileName);
}

std::size_t IndicatorDatabase::HashIndicatorCount() const noexcept
{
    return hashIndicators_.size();
}

void IndicatorDatabase::RebuildTextEntries()
{
    textEntries_.clear();
    for (const auto& ecosystem : affected_)
    {
        for (const auto& package : ecosystem.second)
        {
            TextSearchEntry entry;
            entry.ecosystem = ToLowerAscii(WideToUtf8(ecosystem.first));
            entry.name = ToLowerAscii(WideToUtf8(package.first));
            entry.versions.reserve(package.second.size());
            for (const auto& version : package.second)
                entry.versions.push_back(ToLowerAscii(WideToUtf8(version)));
            std::sort(entry.versions.begin(), entry.versions.end(),
                [](const std::string& left, const std::string& right)
                {
                    if (left.size() != right.size())
                        return left.size() > right.size();
                    return left < right;
                });
            textEntries_.push_back(std::move(entry));
        }
    }

    std::sort(textEntries_.begin(), textEntries_.end(),
        [](const TextSearchEntry& left, const TextSearchEntry& right)
        {
            if (left.ecosystem != right.ecosystem)
                return left.ecosystem < right.ecosystem;
            if (left.name.size() != right.name.size())
                return left.name.size() > right.name.size();
            return left.name < right.name;
        });
}

Scanner::Scanner(const IndicatorDatabase& database)
    : database_(database)
{
}

void Scanner::Run(
    const ScanOptions& options,
    std::atomic_bool& cancelRequested,
    FindingCallback onFinding,
    PackageCallback onPackage,
    ProgressCallback onProgress,
    CompletedCallback onCompleted)
{
    struct AtomicStats
    {
        std::atomic_uint64_t directoriesVisited{0};
        std::atomic_uint64_t filesVisited{0};
        std::atomic_uint64_t npmManifests{0};
        std::atomic_uint64_t pythonMetadataFiles{0};
        std::atomic_uint64_t packagesInventoried{0};
        std::atomic_uint64_t npmLockfiles{0};
        std::atomic_uint64_t pythonLockfiles{0};
        std::atomic_uint64_t goDependencyFiles{0};
        std::atomic_uint64_t behaviorFiles{0};
        std::atomic_uint64_t hashesCalculated{0};
        std::atomic_uint64_t deepHashedScripts{0};
        std::atomic_uint64_t skippedReparsePoints{0};
        std::atomic_uint64_t accessDenied{0};
        std::atomic_uint64_t errors{0};
        std::atomic_uint64_t findings{0};
        std::atomic_uint64_t filesQueued{0};
        std::atomic_uint64_t rootsCompleted{0};
        std::atomic_uint64_t rootsTotal{0};
        std::atomic_uint64_t workerThreads{0};
        std::atomic_uint64_t activeWorkers{0};
        std::atomic_uint64_t peakQueueDepth{0};

        ScanStats Snapshot() const
        {
            ScanStats result;
            result.directoriesVisited = directoriesVisited.load(std::memory_order_relaxed);
            result.filesVisited = filesVisited.load(std::memory_order_relaxed);
            result.npmManifests = npmManifests.load(std::memory_order_relaxed);
            result.pythonMetadataFiles = pythonMetadataFiles.load(std::memory_order_relaxed);
            result.packagesInventoried = packagesInventoried.load(std::memory_order_relaxed);
            result.npmLockfiles = npmLockfiles.load(std::memory_order_relaxed);
            result.pythonLockfiles = pythonLockfiles.load(std::memory_order_relaxed);
            result.goDependencyFiles = goDependencyFiles.load(std::memory_order_relaxed);
            result.behaviorFiles = behaviorFiles.load(std::memory_order_relaxed);
            result.hashesCalculated = hashesCalculated.load(std::memory_order_relaxed);
            result.deepHashedScripts = deepHashedScripts.load(std::memory_order_relaxed);
            result.skippedReparsePoints = skippedReparsePoints.load(std::memory_order_relaxed);
            result.accessDenied = accessDenied.load(std::memory_order_relaxed);
            result.errors = errors.load(std::memory_order_relaxed);
            result.findings = findings.load(std::memory_order_relaxed);
            result.filesQueued = filesQueued.load(std::memory_order_relaxed);
            result.rootsCompleted = rootsCompleted.load(std::memory_order_relaxed);
            result.rootsTotal = rootsTotal.load(std::memory_order_relaxed);
            result.workerThreads = workerThreads.load(std::memory_order_relaxed);
            result.activeWorkers = activeWorkers.load(std::memory_order_relaxed);
            result.peakQueueDepth = peakQueueDepth.load(std::memory_order_relaxed);
            return result;
        }
    } stats;

    class PathQueue
    {
    public:
        explicit PathQueue(std::size_t capacity)
            : capacity_((std::max)(std::size_t{256}, capacity))
        {
        }

        std::size_t Push(std::filesystem::path value, const std::atomic_bool& cancelled)
        {
            std::unique_lock lock(mutex_);
            while (!closed_ && !cancelled.load(std::memory_order_relaxed) &&
                   queue_.size() >= capacity_)
            {
                notFull_.wait_for(lock, std::chrono::milliseconds(100));
            }

            if (closed_ || cancelled.load(std::memory_order_relaxed))
                return 0;

            queue_.push_back(std::move(value));
            const std::size_t depth = queue_.size();
            notEmpty_.notify_one();
            return depth;
        }

        bool Pop(std::filesystem::path& value, const std::atomic_bool& cancelled)
        {
            std::unique_lock lock(mutex_);
            while (!closed_ && !cancelled.load(std::memory_order_relaxed) &&
                   queue_.empty())
            {
                notEmpty_.wait_for(lock, std::chrono::milliseconds(100));
            }

            if (cancelled.load(std::memory_order_relaxed))
                return false;
            if (queue_.empty())
                return false;

            value = std::move(queue_.front());
            queue_.pop_front();
            notFull_.notify_one();
            return true;
        }

        void Close()
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
            notEmpty_.notify_all();
            notFull_.notify_all();
        }

        void WakeAll()
        {
            std::lock_guard lock(mutex_);
            notEmpty_.notify_all();
            notFull_.notify_all();
        }

    private:
        std::mutex mutex_;
        std::condition_variable notEmpty_;
        std::condition_variable notFull_;
        std::deque<std::filesystem::path> queue_;
        std::size_t capacity_;
        bool closed_ = false;
    };

    const unsigned int hardwareThreads =
        (std::max)(2u, std::thread::hardware_concurrency());
    const unsigned int automaticThreads =
        (std::min)(16u, (std::max)(2u, hardwareThreads > 2 ? hardwareThreads - 1 : 2u));
    const unsigned int workerCount =
        options.workerThreads == 0
            ? automaticThreads
            : (std::clamp)(options.workerThreads, 1u, 32u);

    stats.rootsTotal.store(options.roots.size(), std::memory_order_relaxed);
    stats.workerThreads.store(workerCount, std::memory_order_relaxed);

    PathQueue queue(options.queueCapacity);
    std::unordered_set<std::wstring> findingKeys;
    std::mutex findingMutex;
    std::mutex progressMutex;
    auto lastProgress = std::chrono::steady_clock::now();

    const auto updatePeakQueue = [&](std::uint64_t depth)
    {
        auto current = stats.peakQueueDepth.load(std::memory_order_relaxed);
        while (depth > current &&
            !stats.peakQueueDepth.compare_exchange_weak(
                current, depth, std::memory_order_relaxed))
        {
        }
    };

    const auto reportFinding = [&](Finding finding)
    {
        std::wstring key = ToLower(finding.type + L"\n" + finding.path + L"\n" +
            finding.ecosystem + L"\n" + finding.indicator + L"\n" +
            finding.version);

        {
            std::lock_guard lock(findingMutex);
            if (!findingKeys.insert(std::move(key)).second)
                return;
        }

        stats.findings.fetch_add(1, std::memory_order_relaxed);
        if (onFinding)
            onFinding(finding);
    };

    const auto reportProgress = [&](const std::wstring& path, bool force)
    {
        std::lock_guard lock(progressMutex);
        const auto now = std::chrono::steady_clock::now();
        if (!force && now - lastProgress < std::chrono::milliseconds(250))
            return;
        lastProgress = now;
        if (onProgress)
            onProgress(stats.Snapshot(), path);
    };

    const auto inspectTextBehavior = [&](const std::filesystem::path& path,
                                         const std::string& original,
                                         bool persistenceContext)
    {
        const std::string text = ToLowerAscii(original);
        std::vector<std::wstring> markers;
        int highConfidenceIndicators = 0;

        const auto addMarker = [&](const char* needle, const wchar_t* label)
        {
            if (text.find(needle) != std::string::npos)
                markers.emplace_back(label);
        };

        addMarker("oven-sh/bun/releases/download", L"Bun release downloader");
        addMarker("bun-v1.3.13", L"Bun 1.3.13");
        addMarker("setup.mjs", L"setup.mjs");
        addMarker("setup_bun.js", L"setup_bun.js");
        addMarker("bun_environment.js", L"bun_environment.js");
        addMarker("math_symbol.js", L"Math_Symbol.js");
        addMarker("math_init.js", L"math_init.js");
        addMarker("router_runtime.js", L"router_runtime.js");
        addMarker("tmp.dpkg_", L"tmp.dpkg lock/beacon");
        addMarker(".truffler-cache", L"hidden TruffleHog cache");
        addMarker("trufflesecrets.json", L"truffleSecrets.json");
        addMarker("actionssecrets.json", L"actionsSecrets.json");
        addMarker("discussion.yaml", L"discussion workflow");
        addMarker("formatter_", L"formatter workflow");
        addMarker("thebeautifulmarchoftime", L"GitHub C2 search marker");
        addMarker("dontrevokeoritgoesboom", L"GitHub PAT discovery marker");
        addMarker("thebeautifulsandsoftime", L"GitHub JavaScript C2 marker");
        addMarker("thebeautifulsnadsoftime", L"GitHub fallback parser marker");
        addMarker("firedalazer", L"persistent monitor marker");
        addMarker("sha1-hulud: the second coming", L"Shai-Hulud 2 repository description");
        addMarker("sha1-hulud: the continued coming", L"Shai-Hulud 2 second-phase description");
        addMarker("shai-hulud: here we go again", L"ChainDrop repository description");
        addMarker("ifyoublockthisapikeyitwillcrashtheliveproductionserversofallthirdpartyclients",
            L"ChainDrop intimidation marker");

        if (text.find("runner.worker") != std::string::npos &&
            text.find("issecret") != std::string::npos)
            markers.emplace_back(L"Runner.Worker secret-memory scraping");
        if (text.find("/-/npm/v1/tokens") != std::string::npos &&
            text.find("oidc/token/exchange") != std::string::npos)
            markers.emplace_back(L"npm token/OIDC publishing engine");
        if (text.find("tojson(secrets)") != std::string::npos &&
            (text.find("format-results") != std::string::npos ||
             text.find("format.json") != std::string::npos ||
             text.find("actionssecrets.json") != std::string::npos))
            markers.emplace_back(L"workflow secret serialization");
        if (text.find("sessionstart") != std::string::npos &&
            text.find("setup.mjs") != std::string::npos)
            markers.emplace_back(L"Claude SessionStart persistence");
        if (text.find("folderopen") != std::string::npos &&
            text.find("setup.mjs") != std::string::npos)
            markers.emplace_back(L"VS Code folderOpen persistence");
        if (text.find("discussion:") != std::string::npos &&
            text.find("runs-on: self-hosted") != std::string::npos &&
            text.find("github.event.discussion.body") != std::string::npos)
            markers.emplace_back(L"discussion-triggered self-hosted runner backdoor");
        if ((text.find("\"preinstall\"") != std::string::npos ||
             text.find("\"postinstall\"") != std::string::npos) &&
            (text.find("setup_bun.js") != std::string::npos ||
             text.find("bun_environment.js") != std::string::npos ||
             text.find("setup.mjs") != std::string::npos))
            markers.emplace_back(L"malicious install lifecycle chain");

        for (const auto& indicator : database_.TextIndicators())
        {
            const std::string value = ToLowerAscii(WideToUtf8(indicator.value));
            if (!value.empty() && text.find(value) != std::string::npos)
            {
                markers.push_back(indicator.category + L":" + indicator.value);
                if (indicator.highConfidence)
                    ++highConfidenceIndicators;
            }
        }

        if (highConfidenceIndicators > 0 || markers.size() >= 2 ||
            (persistenceContext && !markers.empty()))
        {
            Finding finding;
            // CRITICAL is intentionally reserved for exact known-malware hash matches.
            finding.severity = Severity::High;
            finding.type = persistenceContext
                ? L"Persistence behavior" : L"Payload behavior";
            finding.indicator = path.filename().wstring();
            finding.path = path.wstring();
            finding.details = L"Strong behavior/IOC match; this is not cryptographic confirmation: " +
                JoinMarkers(markers);
            reportFinding(std::move(finding));
        }
    };

    const auto inspectKnownHashes = [&](const std::filesystem::path& path,
                                        bool deepHash)
    {
        bool needSha256 = false;
        bool needSha1 = false;
        for (const auto& indicator : database_.HashIndicators())
        {
            needSha256 = needSha256 || _wcsicmp(indicator.algorithm.c_str(), L"SHA256") == 0;
            needSha1 = needSha1 || _wcsicmp(indicator.algorithm.c_str(), L"SHA1") == 0;
        }

        const auto check = [&](const wchar_t* algorithm)
        {
            std::wstring digest;
            if (!CalculateHash(path, algorithm, digest))
                return;
            stats.hashesCalculated.fetch_add(1, std::memory_order_relaxed);
            if (deepHash)
                stats.deepHashedScripts.fetch_add(1, std::memory_order_relaxed);

            for (const auto& indicator : database_.HashIndicators())
            {
                if (_wcsicmp(indicator.algorithm.c_str(), algorithm) != 0 ||
                    digest != ToLower(indicator.digest))
                    continue;

                Finding finding;
                finding.severity = Severity::Critical;
                finding.type = L"Confirmed malware hash";
                finding.indicator = digest;
                finding.path = path.wstring();
                finding.details = L"Exact " + std::wstring(algorithm) +
                    L" match: " + indicator.description;
                reportFinding(std::move(finding));
            }
        };

        if (needSha256)
            check(L"SHA256");
        if (needSha1)
            check(L"SHA1");
    };

    const auto processFile = [&](const std::filesystem::path& path)
    {
        const std::wstring lowerPath = ToLower(path.wstring());
        const std::wstring lowerName = ToLower(path.filename().wstring());
        const std::wstring lowerExtension = ToLower(path.extension().wstring());
        std::error_code sizeError;
        const auto size = std::filesystem::file_size(path, sizeError);
        const bool packageContext = IsPackageContext(lowerPath);
        const bool persistenceContext =
            lowerPath.find(L"\\.vscode\\") != std::wstring::npos ||
            lowerPath.find(L"\\.claude\\") != std::wstring::npos ||
            lowerPath.find(L"\\.github\\workflows\\") != std::wstring::npos ||
            lowerPath.find(L"/.vscode/") != std::wstring::npos ||
            lowerPath.find(L"/.claude/") != std::wstring::npos ||
            lowerPath.find(L"/.github/workflows/") != std::wstring::npos;
        const bool candidateArtifact = IsCandidateArtifactName(lowerName);
        const bool persistenceHashCandidate =
            persistenceContext &&
            (lowerName == L"tasks.json" || lowerName == L"settings.json");
        const bool jsonHashCandidate = database_.ShouldHashFileName(lowerName);

        if (options.scanNpmPackages && lowerName == L"package.json")
        {
            std::string text;
            if (ReadFileLimited(path, options.maxTextFileBytes, text))
            {
                stats.npmManifests.fetch_add(1, std::memory_order_relaxed);
                const auto nameValue = ExtractJsonString(text, "name");
                const auto versionValue = ExtractJsonString(text, "version");
                if (nameValue && versionValue)
                {
                    PackageRecord record;
                    record.ecosystem = L"npm";
                    record.name = Utf8ToWide(*nameValue);
                    record.version = Utf8ToWide(*versionValue);
                    record.path = path.wstring();
                    record.affected = database_.IsAffected(
                        record.ecosystem, record.name, record.version);

                    if (options.createPackageInventory)
                    {
                        stats.packagesInventoried.fetch_add(1, std::memory_order_relaxed);
                        if (onPackage)
                            onPackage(record);
                    }

                    if (record.affected)
                    {
                        Finding finding;
                        finding.severity = Severity::High;
                        finding.type = L"Affected installed package";
                        finding.ecosystem = record.ecosystem;
                        finding.indicator = record.name;
                        finding.version = record.version;
                        finding.path = record.path;
                        finding.details = L"Exact installed name/version match in the merged campaign database. Exposure is confirmed; payload execution is not.";
                        reportFinding(std::move(finding));
                    }
                }

                const std::string lowerText = ToLowerAscii(text);
                const bool lifecycleHook =
                    lowerText.find("\"preinstall\"") != std::string::npos ||
                    lowerText.find("\"install\"") != std::string::npos ||
                    lowerText.find("\"postinstall\"") != std::string::npos;
                const bool chainDropLoader = lowerText.find("setup.mjs") != std::string::npos;
                const bool huludLoader =
                    lowerText.find("setup_bun.js") != std::string::npos ||
                    lowerText.find("bun_environment.js") != std::string::npos;
                const bool originalHuludLoader = lowerText.find("bundle.js") != std::string::npos;

                if (lifecycleHook && (chainDropLoader || huludLoader))
                {
                    Finding finding;
                    finding.severity = Severity::High;
                    finding.type = L"Malicious lifecycle pattern";
                    finding.ecosystem = L"npm";
                    finding.indicator = chainDropLoader
                        ? L"setup.mjs lifecycle hook"
                        : L"Shai-Hulud Bun lifecycle hook";
                    finding.path = path.wstring();
                    finding.details = L"Install lifecycle launches a known campaign loader. Strong compromise indicator; hash confirmation is reported separately as CRITICAL.";
                    reportFinding(std::move(finding));
                }
                else if (lifecycleHook && originalHuludLoader)
                {
                    Finding finding;
                    finding.severity = Severity::High;
                    finding.type = L"Suspicious lifecycle pattern";
                    finding.ecosystem = L"npm";
                    finding.indicator = L"bundle.js lifecycle hook";
                    finding.path = path.wstring();
                    finding.details = L"Lifecycle hook launches bundle.js, matching original Shai-Hulud tradecraft. Verify package provenance and hashes.";
                    reportFinding(std::move(finding));
                }

                if (lowerText.find("math_symbol.js") != std::string::npos ||
                    lowerText.find("math_init.js") != std::string::npos ||
                    lowerText.find("router_runtime.js") != std::string::npos ||
                    lowerText.find("setup_bun.js") != std::string::npos ||
                    lowerText.find("bun_environment.js") != std::string::npos)
                {
                    Finding finding;
                    finding.severity = Severity::High;
                    finding.type = L"Payload referenced by package";
                    finding.ecosystem = L"npm";
                    finding.indicator = L"Known campaign payload filename";
                    finding.path = path.wstring();
                    finding.details = L"package.json references a known campaign payload or loader filename.";
                    reportFinding(std::move(finding));
                }
            }
            else if (!sizeError && size <= options.maxTextFileBytes)
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (options.scanPythonPackages && LooksLikePythonMetadata(path))
        {
            std::string text;
            if (ReadFileLimited(path, options.maxTextFileBytes, text))
            {
                stats.pythonMetadataFiles.fetch_add(1, std::memory_order_relaxed);
                std::string name;
                std::string version;
                if (ExtractPythonMetadata(text, name, version))
                {
                    PackageRecord record;
                    record.ecosystem = L"pypi";
                    record.name = Utf8ToWide(name);
                    record.version = Utf8ToWide(version);
                    record.path = path.wstring();
                    record.affected = database_.IsAffected(
                        record.ecosystem, record.name, record.version);

                    if (options.createPackageInventory)
                    {
                        stats.packagesInventoried.fetch_add(1, std::memory_order_relaxed);
                        if (onPackage)
                            onPackage(record);
                    }

                    if (record.affected)
                    {
                        Finding finding;
                        finding.severity = Severity::High;
                        finding.type = L"Affected installed package";
                        finding.ecosystem = record.ecosystem;
                        finding.indicator = record.name;
                        finding.version = record.version;
                        finding.path = record.path;
                        finding.details = L"Exact installed PyPI name/version match. Exposure is confirmed; infection is not cryptographically confirmed.";
                        reportFinding(std::move(finding));
                    }
                }
            }
            else if (!sizeError && size <= options.maxTextFileBytes)
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (options.scanNpmLockfiles && IsNpmLockfileName(lowerName))
        {
            stats.npmLockfiles.fetch_add(1, std::memory_order_relaxed);
            std::string text;
            if (ReadFileLimited(path, options.maxLockfileBytes, text))
            {
                for (const auto& match : FindAffectedPairsInText(database_, "npm", text))
                {
                    Finding finding;
                    finding.severity = Severity::Medium;
                    finding.type = L"Affected lockfile dependency";
                    finding.ecosystem = L"npm";
                    finding.indicator = Utf8ToWide(match.first);
                    finding.version = Utf8ToWide(match.second);
                    finding.path = path.wstring();
                    finding.details = L"Affected npm pair is referenced by a lockfile. This does not prove installation or execution.";
                    reportFinding(std::move(finding));
                }
            }
            else
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (options.scanPythonLockfiles && IsPythonLockfileName(lowerName))
        {
            stats.pythonLockfiles.fetch_add(1, std::memory_order_relaxed);
            std::string text;
            if (ReadFileLimited(path, options.maxLockfileBytes, text))
            {
                for (const auto& match : FindAffectedPairsInText(database_, "pypi", text))
                {
                    Finding finding;
                    finding.severity = Severity::Medium;
                    finding.type = L"Affected lockfile dependency";
                    finding.ecosystem = L"pypi";
                    finding.indicator = Utf8ToWide(match.first);
                    finding.version = Utf8ToWide(match.second);
                    finding.path = path.wstring();
                    finding.details = L"Affected PyPI pair is referenced by a requirements or lock file. This does not prove installation or execution.";
                    reportFinding(std::move(finding));
                }
            }
            else
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (options.scanGoDependencies && IsGoDependencyFileName(lowerName))
        {
            stats.goDependencyFiles.fetch_add(1, std::memory_order_relaxed);
            std::string text;
            if (ReadFileLimited(path, options.maxLockfileBytes, text))
            {
                for (const auto& match : FindAffectedPairsInText(database_, "golang", text))
                {
                    Finding finding;
                    finding.severity = Severity::Medium;
                    finding.type = L"Affected Go module dependency";
                    finding.ecosystem = L"golang";
                    finding.indicator = Utf8ToWide(match.first);
                    finding.version = Utf8ToWide(match.second);
                    finding.path = path.wstring();
                    finding.details = L"Affected module/version is referenced in go.mod or go.sum. This does not prove execution.";
                    reportFinding(std::move(finding));
                }
            }
            else
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        bool hashed = false;
        if (options.scanKnownArtifacts && (candidateArtifact || persistenceHashCandidate || jsonHashCandidate))
        {
            if (lowerName.rfind(L"tmp.dpkg_", 0) == 0)
            {
                Finding finding;
                finding.severity = Severity::High;
                finding.type = L"State/beacon file";
                finding.indicator = path.filename().wstring();
                finding.path = path.wstring();
                finding.details = L"Filename matches the campaign lock/beacon pattern. Hash result determines whether it is CRITICAL.";
                reportFinding(std::move(finding));
            }
            else if (lowerName == L"math_symbol.js" ||
                     lowerName == L"math_init.js" ||
                     lowerName == L"router_runtime.js" ||
                     lowerName == L"setup_bun.js" ||
                     lowerName == L"bun_environment.js" ||
                     (lowerName.rfind(L"math_", 0) == 0 && lowerName.ends_with(L".js")))
            {
                Finding finding;
                finding.severity = Severity::Medium;
                finding.type = L"Known payload filename";
                finding.indicator = path.filename().wstring();
                finding.path = path.wstring();
                finding.details = L"Known campaign filename found. Filename alone is not proof; hash and behavior checks were applied.";
                reportFinding(std::move(finding));
            }
            else if (lowerName == L"gh-token-monitor.sh")
            {
                Finding finding;
                finding.severity = Severity::High;
                finding.type = L"Token monitor persistence";
                finding.indicator = path.filename().wstring();
                finding.path = path.wstring();
                finding.details = L"Known token-monitor persistence filename found. Hash confirmation is reported separately.";
                reportFinding(std::move(finding));
            }
            else if (lowerName.find(L"bun-v1.3.13") != std::wstring::npos)
            {
                Finding finding;
                finding.severity = Severity::Medium;
                finding.type = L"Bun staging artifact";
                finding.indicator = path.filename().wstring();
                finding.path = path.wstring();
                finding.details = L"Bun 1.3.13 artifact found. Verify whether Bun was intentionally installed.";
                reportFinding(std::move(finding));
            }

            inspectKnownHashes(path, false);
            hashed = true;
        }

        if (options.deepHashPackageScripts && packageContext &&
            IsScriptExtension(lowerExtension) && !hashed)
        {
            inspectKnownHashes(path, true);
            hashed = true;
        }

        if ((options.scanBehaviorVariants || options.scanEditorPersistence) &&
            IsScriptExtension(lowerExtension) && !sizeError &&
            size <= options.maxTextFileBytes &&
            (packageContext || persistenceContext || candidateArtifact))
        {
            std::string text;
            if (ReadFileLimited(path, options.maxTextFileBytes, text))
            {
                stats.behaviorFiles.fetch_add(1, std::memory_order_relaxed);
                inspectTextBehavior(path, text,
                    options.scanEditorPersistence && persistenceContext);
            }
        }

        if (options.scanPackageCaches &&
            (IsNpmCachePath(lowerPath) || IsPythonCachePath(lowerPath)) &&
            !sizeError && size <= options.maxTextFileBytes)
        {
            std::string text;
            if (ReadFileLimited(path, options.maxTextFileBytes, text))
            {
                if (IsNpmCachePath(lowerPath))
                {
                    for (const auto& match : FindAffectedPairsInText(database_, "npm", text, 100))
                    {
                        Finding finding;
                        finding.severity = Severity::Medium;
                        finding.type = L"Affected package in package-manager cache";
                        finding.ecosystem = L"npm";
                        finding.indicator = Utf8ToWide(match.first);
                        finding.version = Utf8ToWide(match.second);
                        finding.path = path.wstring();
                        finding.details = L"Cache metadata contains an affected npm pair. This shows exposure, not execution.";
                        reportFinding(std::move(finding));
                    }
                }
                if (IsPythonCachePath(lowerPath))
                {
                    for (const auto& match : FindAffectedPairsInText(database_, "pypi", text, 100))
                    {
                        Finding finding;
                        finding.severity = Severity::Medium;
                        finding.type = L"Affected package in package-manager cache";
                        finding.ecosystem = L"pypi";
                        finding.indicator = Utf8ToWide(match.first);
                        finding.version = Utf8ToWide(match.second);
                        finding.path = path.wstring();
                        finding.details = L"Cache metadata contains an affected PyPI pair. This shows exposure, not execution.";
                        reportFinding(std::move(finding));
                    }
                }
            }
        }
    };

    const auto shouldQueueFile = [&](const std::filesystem::path& path,
                                     const std::wstring& lowerPath,
                                     const std::wstring& lowerName,
                                     const std::wstring& lowerExtension)
    {
        const bool packageContext = IsPackageContext(lowerPath);
        const bool persistenceContext =
            lowerPath.find(L"\\.vscode\\") != std::wstring::npos ||
            lowerPath.find(L"\\.claude\\") != std::wstring::npos ||
            lowerPath.find(L"\\.github\\workflows\\") != std::wstring::npos ||
            lowerPath.find(L"/.vscode/") != std::wstring::npos ||
            lowerPath.find(L"/.claude/") != std::wstring::npos ||
            lowerPath.find(L"/.github/workflows/") != std::wstring::npos;
        const bool candidateArtifact = IsCandidateArtifactName(lowerName);
        const bool persistenceHashCandidate =
            persistenceContext &&
            (lowerName == L"tasks.json" || lowerName == L"settings.json");
        const bool jsonHashCandidate = database_.ShouldHashFileName(lowerName);

        return
            (options.scanNpmPackages && lowerName == L"package.json") ||
            (options.scanPythonPackages && LooksLikePythonMetadata(path)) ||
            (options.scanNpmLockfiles && IsNpmLockfileName(lowerName)) ||
            (options.scanPythonLockfiles && IsPythonLockfileName(lowerName)) ||
            (options.scanGoDependencies && IsGoDependencyFileName(lowerName)) ||
            (options.scanKnownArtifacts && (candidateArtifact || persistenceHashCandidate || jsonHashCandidate)) ||
            (options.deepHashPackageScripts && packageContext && IsScriptExtension(lowerExtension)) ||
            ((options.scanBehaviorVariants || options.scanEditorPersistence) &&
                IsScriptExtension(lowerExtension) &&
                (packageContext || persistenceContext || candidateArtifact)) ||
            (options.scanPackageCaches &&
                (IsNpmCachePath(lowerPath) || IsPythonCachePath(lowerPath)));
    };

    std::vector<std::thread> workers;
    workers.reserve(workerCount);
    for (unsigned int index = 0; index < workerCount; ++index)
    {
        workers.emplace_back([&, index]
        {
            (void)index;
            std::filesystem::path path;
            while (queue.Pop(path, cancelRequested))
            {
                stats.activeWorkers.fetch_add(1, std::memory_order_relaxed);
                try
                {
                    processFile(path);
                }
                catch (...)
                {
                    stats.errors.fetch_add(1, std::memory_order_relaxed);
                }
                stats.activeWorkers.fetch_sub(1, std::memory_order_relaxed);

                const auto processed = stats.filesQueued.load(std::memory_order_relaxed);
                if ((processed % 512) == 0)
                    reportProgress(path.wstring(), false);
            }
        });
    }

    std::vector<std::thread> producers;
    producers.reserve(options.roots.size());
    for (const auto& root : options.roots)
    {
        producers.emplace_back([&, root]
        {
            std::error_code rootError;
            if (!std::filesystem::exists(root, rootError))
            {
                stats.errors.fetch_add(1, std::memory_order_relaxed);
                reportProgress(L"Missing root: " + root.wstring(), true);
                stats.rootsCompleted.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            auto directoryOptions = std::filesystem::directory_options::skip_permission_denied;
            if (options.followReparsePoints)
                directoryOptions |= std::filesystem::directory_options::follow_directory_symlink;

            std::error_code ec;
            std::filesystem::recursive_directory_iterator iterator(root, directoryOptions, ec);
            std::filesystem::recursive_directory_iterator end;
            if (ec)
            {
                if (IsPermissionDenied(ec))
                    stats.accessDenied.fetch_add(1, std::memory_order_relaxed);
                else
                    stats.errors.fetch_add(1, std::memory_order_relaxed);
                reportProgress(L"Cannot open root: " + root.wstring(), true);
                stats.rootsCompleted.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            while (iterator != end && !cancelRequested.load(std::memory_order_relaxed))
            {
                const auto entry = *iterator;
                const std::filesystem::path path = entry.path();
                const std::wstring lowerPath = ToLower(path.wstring());
                std::error_code typeError;
                const bool isDirectory = entry.is_directory(typeError);
                if (typeError)
                {
                    if (IsPermissionDenied(typeError))
                        stats.accessDenied.fetch_add(1, std::memory_order_relaxed);
                    else
                        stats.errors.fetch_add(1, std::memory_order_relaxed);
                    ec.clear();
                    iterator.increment(ec);
                    continue;
                }

                if (isDirectory)
                {
                    stats.directoriesVisited.fetch_add(1, std::memory_order_relaxed);
                    const std::wstring lowerName = ToLower(path.filename().wstring());
                    bool skip = false;

                    // Do not exclude the scanner's own directory. A user-selected root
                    // must be scanned completely, including test or incident artifacts
                    // placed beside the executable. Scanner-owned files are not queued
                    // unless they independently match a configured candidate rule.

                    for (const auto& excluded : options.excludedDirectoryNames)
                    {
                        if (lowerName == ToLower(excluded))
                        {
                            skip = true;
                            break;
                        }
                    }

                    if (options.skipWindowsDirectory && lowerName == L"windows" &&
                        path.parent_path() == path.root_path())
                        skip = true;

                    const DWORD attributes = GetFileAttributesW(path.c_str());
                    if (!options.followReparsePoints &&
                        attributes != INVALID_FILE_ATTRIBUTES &&
                        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        skip = true;
                        stats.skippedReparsePoints.fetch_add(1, std::memory_order_relaxed);
                    }

                    if (options.scanKnownArtifacts && lowerName.rfind(L"bun-dl-", 0) == 0)
                    {
                        Finding finding;
                        finding.severity = Severity::Medium;
                        finding.type = L"Staging directory";
                        finding.indicator = path.filename().wstring();
                        finding.path = path.wstring();
                        finding.details = L"Directory matches the campaign Bun staging pattern. This is not hash confirmation.";
                        reportFinding(std::move(finding));
                    }

                    if (skip)
                        iterator.disable_recursion_pending();
                }
                else
                {
                    const bool isRegular = entry.is_regular_file(typeError);
                    if (typeError)
                    {
                        if (IsPermissionDenied(typeError))
                            stats.accessDenied.fetch_add(1, std::memory_order_relaxed);
                        else
                            stats.errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (isRegular)
                    {
                        stats.filesVisited.fetch_add(1, std::memory_order_relaxed);
                        if (HasAnyPathToken(lowerPath, options.includePathTokens))
                        {
                            const std::wstring lowerName = ToLower(path.filename().wstring());
                            const std::wstring lowerExtension = ToLower(path.extension().wstring());
                            if (shouldQueueFile(path, lowerPath, lowerName, lowerExtension))
                            {
                                const std::size_t depth = queue.Push(path, cancelRequested);
                                if (depth == 0)
                                    break;
                                stats.filesQueued.fetch_add(1, std::memory_order_relaxed);
                                updatePeakQueue(depth);
                            }
                        }
                    }
                }

                const auto visited = stats.filesVisited.load(std::memory_order_relaxed);
                if ((visited % 4096) == 0)
                    reportProgress(path.wstring(), false);

                ec.clear();
                iterator.increment(ec);
                if (ec)
                {
                    if (IsPermissionDenied(ec))
                        stats.accessDenied.fetch_add(1, std::memory_order_relaxed);
                    else
                        stats.errors.fetch_add(1, std::memory_order_relaxed);
                    ec.clear();
                }
            }

            stats.rootsCompleted.fetch_add(1, std::memory_order_relaxed);
            reportProgress(L"Completed root: " + root.wstring(), true);
        });
    }

    for (auto& producer : producers)
        producer.join();

    queue.Close();
    for (auto& worker : workers)
        worker.join();

    const ScanStats finalStats = stats.Snapshot();
    reportProgress(cancelRequested.load(std::memory_order_relaxed)
        ? L"Scan cancelled." : L"Scan complete.", true);
    if (onCompleted)
        onCompleted(finalStats, cancelRequested.load(std::memory_order_relaxed));
}
