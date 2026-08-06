#include "StepSecurityExtractor.h"
#include "DebugLog.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <regex>
#include <sstream>
#include <string_view>
#include <utility>

namespace
{
    void SkipAsciiWhitespace(const std::string& text, std::size_t& position)
    {
        while (position < text.size() &&
               std::isspace(static_cast<unsigned char>(text[position])))
            ++position;
    }

    int HexValue(char value)
    {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    }

    void AppendUtf8(std::string& output, unsigned int codePoint)
    {
        if (codePoint <= 0x7F)
        {
            output.push_back(static_cast<char>(codePoint));
        }
        else if (codePoint <= 0x7FF)
        {
            output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0xFFFF)
        {
            output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0x10FFFF)
        {
            output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    bool ParseJavaScriptString(
        const std::string& text,
        std::size_t& position,
        std::string& output)
    {
        SkipAsciiWhitespace(text, position);
        if (position >= text.size() ||
            (text[position] != '\'' && text[position] != '"' &&
             text[position] != '`'))
            return false;

        const char quote = text[position++];
        output.clear();
        while (position < text.size())
        {
            const char value = text[position++];
            if (value == quote)
                return true;
            if (value != '\\')
            {
                output.push_back(value);
                continue;
            }

            if (position >= text.size())
                return false;
            const char escaped = text[position++];
            switch (escaped)
            {
            case '\\': output.push_back('\\'); break;
            case '\'': output.push_back('\''); break;
            case '"': output.push_back('"'); break;
            case '`': output.push_back('`'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'v': output.push_back('\v'); break;
            case '\n': break;
            case '\r':
                if (position < text.size() && text[position] == '\n')
                    ++position;
                break;
            case 'x':
            {
                if (position + 2 > text.size())
                    return false;
                const int high = HexValue(text[position]);
                const int low = HexValue(text[position + 1]);
                if (high < 0 || low < 0)
                    return false;
                output.push_back(static_cast<char>((high << 4) | low));
                position += 2;
                break;
            }
            case 'u':
            {
                if (position + 4 > text.size())
                    return false;
                unsigned int codePoint = 0;
                for (int index = 0; index < 4; ++index)
                {
                    const int digit = HexValue(text[position + index]);
                    if (digit < 0)
                        return false;
                    codePoint = (codePoint << 4) |
                        static_cast<unsigned int>(digit);
                }
                position += 4;
                AppendUtf8(output, codePoint);
                break;
            }
            default:
                output.push_back(escaped);
                break;
            }
        }
        return false;
    }

    bool ConsumeCharacter(
        const std::string& text,
        std::size_t& position,
        char expected)
    {
        SkipAsciiWhitespace(text, position);
        if (position >= text.size() || text[position] != expected)
            return false;
        ++position;
        return true;
    }

    std::string CsvField(const std::string& value)
    {
        if (value.find_first_of(",\"\r\n") == std::string::npos)
            return value;

        std::string output = "\"";
        for (const char character : value)
        {
            if (character == '"')
                output += "\"\"";
            else
                output.push_back(character);
        }
        output.push_back('"');
        return output;
    }

    std::string TrimAscii(std::string value)
    {
        const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }

    bool LooksLikePackageName(const std::string& value)
    {
        if (value.empty() || value.size() > 260 ||
            value.find("http://") != std::string::npos ||
            value.find("https://") != std::string::npos ||
            value.find_first_of(" \t\r\n,;{}[]()<>\\\"") != std::string::npos)
            return false;

        bool hasAlphaNumeric = false;
        for (const unsigned char ch : value)
        {
            if (std::isalnum(ch))
                hasAlphaNumeric = true;
            else if (ch != '@' && ch != '/' && ch != '-' && ch != '_' && ch != '.')
                return false;
        }
        return hasAlphaNumeric;
    }

    bool LooksLikeVersion(const std::string& value)
    {
        if (value.empty() || value.size() > 128 ||
            value.find_first_of(" \t\r\n,;{}[]()<>\\\"") != std::string::npos)
            return false;

        std::size_t start = value.front() == 'v' || value.front() == 'V' ? 1 : 0;
        if (start >= value.size() || !std::isdigit(static_cast<unsigned char>(value[start])))
            return false;

        bool hasDotOrQualifier = false;
        for (std::size_t index = start; index < value.size(); ++index)
        {
            const unsigned char ch = static_cast<unsigned char>(value[index]);
            if (std::isalnum(ch))
                continue;
            if (ch == '.' || ch == '-' || ch == '_' || ch == '+' || ch == '~')
            {
                hasDotOrQualifier = true;
                continue;
            }
            return false;
        }
        return hasDotOrQualifier || value.size() - start == 1;
    }

    void AddRowIfPlausible(
        std::set<std::pair<std::string, std::string>>& rows,
        std::string packageName,
        std::string version)
    {
        packageName = TrimAscii(std::move(packageName));
        version = TrimAscii(std::move(version));
        if (!packageName.empty() && packageName.front() == '`' && packageName.back() == '`')
            packageName = packageName.substr(1, packageName.size() - 2);
        if (!version.empty() && version.front() == '`' && version.back() == '`')
            version = version.substr(1, version.size() - 2);
        if (LooksLikePackageName(packageName) && LooksLikeVersion(version))
            rows.emplace(std::move(packageName), std::move(version));
    }

    bool ParseArray(
        const std::string& html,
        std::size_t position,
        std::set<std::pair<std::string, std::string>>& rows)
    {
        if (!ConsumeCharacter(html, position, '['))
            return false;

        for (;;)
        {
            SkipAsciiWhitespace(html, position);
            if (position >= html.size())
                return false;
            if (html[position] == ']')
            {
                ++position;
                return !rows.empty();
            }

            if (!ConsumeCharacter(html, position, '['))
                return false;

            std::string packageName;
            if (!ParseJavaScriptString(html, position, packageName) ||
                packageName.empty() ||
                !ConsumeCharacter(html, position, ',') ||
                !ConsumeCharacter(html, position, '['))
                return false;

            bool foundVersion = false;
            for (;;)
            {
                SkipAsciiWhitespace(html, position);
                if (position >= html.size())
                    return false;
                if (html[position] == ']')
                {
                    ++position;
                    break;
                }

                std::string version;
                if (!ParseJavaScriptString(html, position, version) ||
                    version.empty())
                    return false;
                const std::size_t before = rows.size();
                AddRowIfPlausible(rows, packageName, version);
                foundVersion = foundVersion || rows.size() > before;

                SkipAsciiWhitespace(html, position);
                if (position < html.size() && html[position] == ',')
                {
                    ++position;
                    continue;
                }
                if (position < html.size() && html[position] == ']')
                {
                    ++position;
                    break;
                }
                return false;
            }

            if (!foundVersion || !ConsumeCharacter(html, position, ']'))
                return false;

            SkipAsciiWhitespace(html, position);
            if (position < html.size() && html[position] == ',')
            {
                ++position;
                continue;
            }
            if (position < html.size() && html[position] == ']')
            {
                ++position;
                return !rows.empty();
            }
            return false;
        }
    }

    std::string DecodeBasicHtmlEntities(std::string value)
    {
        const std::pair<std::string_view, std::string_view> replacements[] =
        {
            { "&quot;", "\"" },
            { "&#34;", "\"" },
            { "&#39;", "'" },
            { "&#x27;", "'" },
            { "&apos;", "'" },
            { "&lt;", "<" },
            { "&gt;", ">" },
            { "&#x2F;", "/" },
            { "&amp;", "&" }
        };

        for (const auto& [encoded, decoded] : replacements)
        {
            std::size_t position = 0;
            while ((position = value.find(encoded, position)) !=
                   std::string::npos)
            {
                value.replace(position, encoded.size(), decoded);
                position += decoded.size();
            }
        }
        return value;
    }

    std::string StripHtml(std::string value)
    {
        value = std::regex_replace(value, std::regex(R"(<script[\s\S]*?</script>)",
            std::regex_constants::icase), " ");
        value = std::regex_replace(value, std::regex(R"(<style[\s\S]*?</style>)",
            std::regex_constants::icase), " ");
        value = std::regex_replace(value, std::regex(R"(<[^>]+>)"), " ");
        value = DecodeBasicHtmlEntities(std::move(value));
        value = std::regex_replace(value, std::regex(R"(\s+)"), " ");
        return TrimAscii(std::move(value));
    }

    void FindHtmlTableRows(
        const std::string& source,
        std::set<std::pair<std::string, std::string>>& rows)
    {
        const std::regex rowPattern(R"(<tr\b[^>]*>([\s\S]*?)</tr>)",
            std::regex_constants::icase);
        const std::regex cellPattern(R"(<t[dh]\b[^>]*>([\s\S]*?)</t[dh]>)",
            std::regex_constants::icase);

        for (std::sregex_iterator row(source.begin(), source.end(), rowPattern), end;
             row != end; ++row)
        {
            const std::string body = (*row)[1].str();
            std::vector<std::string> cells;
            for (std::sregex_iterator cell(body.begin(), body.end(), cellPattern);
                 cell != end; ++cell)
                cells.push_back(StripHtml((*cell)[1].str()));

            if (cells.size() < 2)
                continue;
            const std::string packageName = cells[0];
            std::string versions = cells[1];
            std::replace(versions.begin(), versions.end(), '|', ',');
            std::istringstream versionStream(versions);
            std::string version;
            while (std::getline(versionStream, version, ','))
                AddRowIfPlausible(rows, packageName, version);
        }
    }

    void FindJsonRecords(
        const std::string& source,
        std::set<std::pair<std::string, std::string>>& rows)
    {
        const std::regex singleVersion(
            R"REGEX("(?:package|packageName|name)"\s*:\s*"([^"]+)"[^{}]{0,700}"(?:version|maliciousVersion)"\s*:\s*"([^"]+)")REGEX",
            std::regex_constants::icase);
        for (std::sregex_iterator item(source.begin(), source.end(), singleVersion), end;
             item != end; ++item)
            AddRowIfPlausible(rows, (*item)[1].str(), (*item)[2].str());

        const std::regex versionFirst(
            R"REGEX("(?:version|maliciousVersion)"\s*:\s*"([^"]+)"[^{}]{0,700}"(?:package|packageName|name)"\s*:\s*"([^"]+)")REGEX",
            std::regex_constants::icase);
        for (std::sregex_iterator item(source.begin(), source.end(), versionFirst), end;
             item != end; ++item)
            AddRowIfPlausible(rows, (*item)[2].str(), (*item)[1].str());

        const std::regex versionArray(
            R"REGEX("(?:package|packageName|name)"\s*:\s*"([^"]+)"[^{}]{0,700}"versions"\s*:\s*\[([^\]]+)\])REGEX",
            std::regex_constants::icase);
        const std::regex quotedValue(R"(["']([^"']+)["'])");
        for (std::sregex_iterator item(source.begin(), source.end(), versionArray), end;
             item != end; ++item)
        {
            const std::string packageName = (*item)[1].str();
            const std::string list = (*item)[2].str();
            for (std::sregex_iterator version(list.begin(), list.end(), quotedValue);
                 version != end; ++version)
                AddRowIfPlausible(rows, packageName, (*version)[1].str());
        }

        // Some static site generators serialize the data as a package-name to
        // versions map rather than an array of records.
        const std::regex packageMap(R"REGEX("([@A-Za-z0-9_./-]+)"\s*:\s*\[([^\]]+)\])REGEX");
        for (std::sregex_iterator item(source.begin(), source.end(), packageMap), end;
             item != end; ++item)
        {
            const std::string packageName = (*item)[1].str();
            const std::string list = (*item)[2].str();
            for (std::sregex_iterator version(list.begin(), list.end(), quotedValue);
                 version != end; ++version)
                AddRowIfPlausible(rows, packageName, (*version)[1].str());
        }
    }

    bool FindRows(
        const std::string& source,
        std::set<std::pair<std::string, std::string>>& rows,
        const wchar_t* passName,
        std::wstring* method = nullptr)
    {
        const std::wstring pass = passName ? passName : L"unnamed";
        DebugLog::Write("STEPSECURITY/PARSER", L"Parser pass started: " + pass +
            L"; input bytes=" + std::to_wstring(source.size()));

        // Prefer the original Download CSV variable when it is still present.
        std::size_t dCharacters = 0;
        std::size_t dAssignments = 0;
        std::size_t largestDArray = 0;
        for (std::size_t candidate = source.find('D');
             candidate != std::string::npos;
             candidate = source.find('D', candidate + 1))
        {
            ++dCharacters;
            if (candidate > 0)
            {
                const unsigned char previous =
                    static_cast<unsigned char>(source[candidate - 1]);
                if (std::isalnum(previous) || previous == '_' || previous == '$')
                    continue;
            }

            std::size_t position = candidate + 1;
            SkipAsciiWhitespace(source, position);
            if (position >= source.size() || source[position] != '=')
                continue;
            ++dAssignments;
            ++position;
            SkipAsciiWhitespace(source, position);
            if (position >= source.size() || source[position] != '[')
                continue;

            std::set<std::pair<std::string, std::string>> parsed;
            const bool parsedArray = ParseArray(source, position, parsed);
            largestDArray = (std::max)(largestDArray, parsed.size());
            DebugLog::Write("STEPSECURITY/PARSER",
                L"Pass " + pass + L": candidate D assignment at byte " +
                std::to_wstring(candidate) + L"; parse=" +
                std::wstring(parsedArray ? L"success" : L"failure") +
                L"; plausible rows=" + std::to_wstring(parsed.size()));
            if (parsedArray && parsed.size() >= 400)
            {
                rows = std::move(parsed);
                if (method) *method = L"download-button package array";
                DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
                    L" accepted download-button array with " +
                    std::to_wstring(rows.size()) + L" rows.");
                return true;
            }
        }
        DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
            L": scanned " + std::to_wstring(dCharacters) +
            L" D characters, found " + std::to_wstring(dAssignments) +
            L" standalone D assignments; largest parsed array=" +
            std::to_wstring(largestDArray) + L" rows.");

        // The article generator may rename or inline the variable. Scan only
        // likely nested-array starts and keep the largest valid package list.
        std::set<std::pair<std::string, std::string>> best;
        std::size_t nestedCandidates = 0;
        std::size_t parsedNestedArrays = 0;
        for (std::size_t position = 0; position + 3 < source.size(); ++position)
        {
            if (source[position] != '[')
                continue;
            std::size_t probe = position + 1;
            SkipAsciiWhitespace(source, probe);
            if (probe >= source.size() || source[probe] != '[')
                continue;
            ++probe;
            SkipAsciiWhitespace(source, probe);
            if (probe >= source.size() ||
                (source[probe] != '\'' && source[probe] != '"' && source[probe] != '`'))
                continue;

            ++nestedCandidates;
            std::set<std::pair<std::string, std::string>> parsed;
            if (ParseArray(source, position, parsed))
            {
                ++parsedNestedArrays;
                if (parsed.size() > best.size())
                {
                    best = std::move(parsed);
                    DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
                        L": new largest inline array at byte " +
                        std::to_wstring(position) + L" with " +
                        std::to_wstring(best.size()) + L" rows.");
                }
            }
        }

        DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
            L": inline-array scan candidates=" +
            std::to_wstring(nestedCandidates) + L", parsed arrays=" +
            std::to_wstring(parsedNestedArrays) + L", largest rows=" +
            std::to_wstring(best.size()) + L".");
        if (best.size() >= 400)
        {
            rows = std::move(best);
            if (method) *method = L"inline package array";
            DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
                L" accepted inline package array with " +
                std::to_wstring(rows.size()) + L" rows.");
            return true;
        }

        const std::size_t beforeJson = best.size();
        FindJsonRecords(source, best);
        DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
            L": JSON record/map scan added " +
            std::to_wstring(best.size() - beforeJson) +
            L" rows; total plausible rows=" + std::to_wstring(best.size()) + L".");
        if (best.size() >= 400)
        {
            rows = std::move(best);
            if (method) *method = L"embedded JSON package records";
            DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
                L" accepted embedded JSON records with " +
                std::to_wstring(rows.size()) + L" rows.");
            return true;
        }

        const std::size_t beforeHtml = best.size();
        FindHtmlTableRows(source, best);
        DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
            L": HTML table scan added " +
            std::to_wstring(best.size() - beforeHtml) +
            L" rows; total plausible rows=" + std::to_wstring(best.size()) + L".");
        if (best.size() >= 400)
        {
            rows = std::move(best);
            if (method) *method = L"HTML package table";
            DebugLog::Write("STEPSECURITY/PARSER", L"Pass " + pass +
                L" accepted HTML package table with " +
                std::to_wstring(rows.size()) + L" rows.");
            return true;
        }

        DebugLog::Write("STEPSECURITY/PARSER", L"Parser pass failed: " + pass +
            L"; final plausible row count=" + std::to_wstring(best.size()) +
            L"; required minimum=400.");
        return false;
    }

    std::string DecodeEscapedScriptSource(const std::string& value)
    {
        std::string output;
        output.reserve(value.size());
        for (std::size_t index = 0; index < value.size(); ++index)
        {
            if (value[index] == '\\' && index + 1 < value.size())
            {
                const char next = value[index + 1];
                if (next == '"' || next == '\'' || next == '\\' || next == '/')
                {
                    output.push_back(next);
                    ++index;
                    continue;
                }
                if (next == 'n' || next == 'r' || next == 't')
                {
                    output.push_back(' ');
                    ++index;
                    continue;
                }
                if (next == 'x' && index + 3 < value.size())
                {
                    const int high = HexValue(value[index + 2]);
                    const int low = HexValue(value[index + 3]);
                    if (high >= 0 && low >= 0)
                    {
                        output.push_back(static_cast<char>((high << 4) | low));
                        index += 3;
                        continue;
                    }
                }
                if (next == 'u' && index + 5 < value.size())
                {
                    unsigned int codePoint = 0;
                    bool valid = true;
                    for (int digitIndex = 0; digitIndex < 4; ++digitIndex)
                    {
                        const int digit = HexValue(value[index + 2 + digitIndex]);
                        if (digit < 0) { valid = false; break; }
                        codePoint = (codePoint << 4) | static_cast<unsigned int>(digit);
                    }
                    if (valid)
                    {
                        AppendUtf8(output, codePoint);
                        index += 5;
                        continue;
                    }
                }
            }
            output.push_back(value[index]);
        }
        return output;
    }

}

bool StepSecurityExtractor::HtmlToCsv(
    const std::vector<unsigned char>& pageBytes,
    std::vector<unsigned char>& csvBytes,
    std::wstring& detail,
    std::size_t* rowCount)
{
    DebugLog::Write("STEPSECURITY/PARSER", L"HtmlToCsv started. Input bytes=" +
        std::to_wstring(pageBytes.size()));

    const std::string page(
        reinterpret_cast<const char*>(pageBytes.data()),
        pageBytes.size());

    DebugLog::Write("STEPSECURITY/PARSER", L"Direct CSV signature check started.");
    if (page.rfind("Package,Version", 0) == 0 ||
        page.rfind("\xEF\xBB\xBFPackage,Version", 0) == 0)
    {
        csvBytes = pageBytes;
        detail = L"StepSecurity returned Package,Version CSV directly.";
        DebugLog::Write("STEPSECURITY/PARSER", detail);
        return true;
    }

    DebugLog::Write("STEPSECURITY/PARSER", L"Direct CSV signature not present.");

    std::set<std::pair<std::string, std::string>> rows;
    std::wstring extractionMethod;
    if (!FindRows(page, rows, L"raw response", &extractionMethod))
    {
        const std::string decodedHtml = DecodeBasicHtmlEntities(page);
        DebugLog::Write("STEPSECURITY/PARSER", L"HTML entity decoding completed. Input bytes=" +
            std::to_wstring(page.size()) + L", output bytes=" +
            std::to_wstring(decodedHtml.size()));
        if (FindRows(decodedHtml, rows, L"HTML entity decoded", &extractionMethod))
        {
            extractionMethod = L"HTML-entity-decoded " + extractionMethod;
        }
        else
        {
            const std::string unescaped = DecodeEscapedScriptSource(decodedHtml);
            DebugLog::Write("STEPSECURITY/PARSER", L"Escaped application-data decoding completed. Input bytes=" +
                std::to_wstring(decodedHtml.size()) + L", output bytes=" +
                std::to_wstring(unescaped.size()));
            if (FindRows(unescaped, rows, L"escaped application data decoded", &extractionMethod))
                extractionMethod = L"escaped application-data " + extractionMethod;
        }
    }

    if (rows.size() < 400)
    {
        detail =
            L"The StepSecurity response did not contain a complete package/version dataset "
            L"in CSV, JavaScript-array, JSON-record, or HTML-table form. "
            L"The last validated snapshot will remain active.";
        DebugLog::Write("STEPSECURITY/PARSER", L"HtmlToCsv failed. Final row count=" +
            std::to_wstring(rows.size()) + L". " + detail);
        return false;
    }

    std::ostringstream csv;
    csv << "Package,Version\n";
    for (const auto& [packageName, version] : rows)
        csv << CsvField(packageName) << ',' << CsvField(version) << '\n';

    const std::string output = csv.str();
    csvBytes.assign(output.begin(), output.end());
    if (rowCount)
        *rowCount = rows.size();
    detail = L"Extracted " + std::to_wstring(rows.size()) +
        L" StepSecurity package/version rows from the " + extractionMethod + L".";
    DebugLog::Write("STEPSECURITY/PARSER", L"HtmlToCsv succeeded. " + detail +
        L" Normalized CSV bytes=" + std::to_wstring(csvBytes.size()));
    return true;
}

bool StepSecurityExtractor::ParseApiPage(
    const std::vector<unsigned char>& jsonBytes,
    std::vector<std::pair<std::string, std::string>>& rows,
    bool& hasMore,
    std::string& nextToken,
    std::wstring& detail)
{
    rows.clear();
    hasMore = false;
    nextToken.clear();

    const std::string json(
        reinterpret_cast<const char*>(jsonBytes.data()), jsonBytes.size());
    if (json.empty())
    {
        detail = L"StepSecurity API returned an empty response body.";
        return false;
    }

    std::set<std::pair<std::string, std::string>> uniqueRows;
    std::size_t search = 0;
    while ((search = json.find("\"package_name\"", search)) != std::string::npos)
    {
        std::size_t colon = json.find(':', search + 14);
        if (colon == std::string::npos)
            break;
        std::size_t valuePosition = colon + 1;
        std::string packageName;
        if (!ParseJavaScriptString(json, valuePosition, packageName))
        {
            search = colon + 1;
            continue;
        }

        const std::size_t objectEnd = json.find('}', valuePosition);
        const std::size_t versionKey = json.find("\"version\"", valuePosition);
        if (versionKey == std::string::npos ||
            (objectEnd != std::string::npos && versionKey > objectEnd))
        {
            search = valuePosition;
            continue;
        }

        colon = json.find(':', versionKey + 9);
        if (colon == std::string::npos)
            break;
        valuePosition = colon + 1;
        std::string version;
        if (ParseJavaScriptString(json, valuePosition, version))
            AddRowIfPlausible(uniqueRows, std::move(packageName), std::move(version));
        search = valuePosition;
    }

    rows.assign(uniqueRows.begin(), uniqueRows.end());

    const std::size_t hasMoreKey = json.find("\"has_more\"");
    if (hasMoreKey != std::string::npos)
    {
        const std::size_t colon = json.find(':', hasMoreKey + 10);
        if (colon != std::string::npos)
        {
            std::size_t value = colon + 1;
            SkipAsciiWhitespace(json, value);
            hasMore = json.compare(value, 4, "true") == 0;
        }
    }

    const std::size_t tokenKey = json.find("\"next_token\"");
    if (tokenKey != std::string::npos)
    {
        const std::size_t colon = json.find(':', tokenKey + 12);
        if (colon != std::string::npos)
        {
            std::size_t value = colon + 1;
            ParseJavaScriptString(json, value, nextToken);
        }
    }

    if (rows.empty())
    {
        detail = L"StepSecurity API page did not contain any valid package_name/version records.";
        return false;
    }
    if (hasMore && nextToken.empty())
    {
        detail = L"StepSecurity API reported has_more=true without a next_token.";
        return false;
    }

    detail = L"Parsed " + std::to_wstring(rows.size()) +
        L" package/version records from the StepSecurity API page.";
    return true;
}

