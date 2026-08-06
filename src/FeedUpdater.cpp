#include "FeedUpdater.h"
#include "StepSecurityExtractor.h"
#include "DebugLog.h"

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <shlobj.h>

#include <algorithm>
#include <chrono>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <set>
#include <string_view>
#include <system_error>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

namespace
{
    enum class FeedPayloadKind
    {
        Csv,
        StepSecurityApi,
        StepSecurityHtml,
        CommunityText
    };

    struct FeedDefinition
    {
        const wchar_t* name;
        const wchar_t* url;
        const wchar_t* fileName;
        std::uint32_t sourceMask;
        std::size_t minimumRows;
        FeedPayloadKind payloadKind;
    };

    constexpr FeedDefinition kFeeds[] =
    {
        {
            L"Socket Keyv campaign",
            L"https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv",
            L"socket-chaindrop.csv",
            BuiltInSocket,
            1000,
            FeedPayloadKind::Csv
        },
        {
            L"SafeDep Mini Shai-Hulud",
            L"https://safedep.io/ti/campaigns/mini-shai-hulud.csv",
            L"safedep-mini-shai-hulud.csv",
            BuiltInSafeDep,
            100,
            FeedPayloadKind::Csv
        },
        {
            L"Wiz Shai-Hulud 2",
            L"https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv",
            L"wiz-shai-hulud-2-packages.csv",
            BuiltInWiz,
            500,
            FeedPayloadKind::Csv
        },
        {
            L"Datadog Keyv campaign",
            L"https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/keyv-campaign/keyv-campaign/malicious-packages.csv",
            L"datadog-keyv-malicious-packages.csv",
            BuiltInDatadog,
            100,
            FeedPayloadKind::Csv
        },
        {
            L"StepSecurity OSS Critical Feed",
            L"https://agent.api.stepsecurity.io/v1/application/oss-packages/npm/ai-scan-results",
            L"chaindrop-compromised-packages.csv",
            BuiltInStepSecurity,
            100,
            FeedPayloadKind::StepSecurityApi
        },
        {
            L"JFrog Shai-Hulud 2",
            L"https://research.jfrog.com/shai_hulud_2_packages.csv",
            L"jfrog-shai-hulud-2-packages.csv",
            BuiltInJFrog,
            500,
            FeedPayloadKind::Csv
        },
        {
            L"Community campaign aggregate",
            L"https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt",
            L"community-shai-hulud-aggregate.csv",
            BuiltInCommunityAggregate,
            3000,
            FeedPayloadKind::CommunityText
        }
    };

    struct FeedMetadata
    {
        std::wstring etag;
        std::wstring lastModified;
        std::wstring sha256;
        std::wstring checkedUtc;
    };

    struct HttpResult
    {
        DWORD statusCode = 0;
        std::vector<unsigned char> bytes;
        std::wstring etag;
        std::wstring lastModified;
        std::wstring contentType;
        std::wstring contentEncoding;
        std::wstring contentLength;
        std::wstring rawResponseHeaders;
        std::wstring effectiveUrl;
        std::wstring error;
    };

    std::wstring ToLower(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        return value;
    }

    std::wstring Trim(std::wstring value)
    {
        const auto notSpace = [](wchar_t ch) { return !std::iswspace(ch); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};
        const int count = WideCharToMultiByte(CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (count <= 0)
            return {};
        std::string output(static_cast<std::size_t>(count), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()), output.data(), count, nullptr, nullptr);
        return output;
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
        std::wstring output(static_cast<std::size_t>(count), L'\0');
        MultiByteToWideChar(codePage, flags, value.data(),
            static_cast<int>(value.size()), output.data(), count);
        return output;
    }

    std::filesystem::path LocalFeedDirectory()
    {
        PWSTR localAppData = nullptr;
        std::filesystem::path result;
        if (SUCCEEDED(SHGetKnownFolderPath(
                FOLDERID_LocalAppData, 0, nullptr, &localAppData)))
        {
            result = std::filesystem::path(localAppData) /
                L"ShaiHulud2Scanner" / L"feeds";
            CoTaskMemFree(localAppData);
        }
        else
        {
            wchar_t temp[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, temp);
            result = std::filesystem::path(temp) /
                L"ShaiHulud2Scanner" / L"feeds";
        }
        return result;
    }

    std::wstring UtcNow()
    {
        SYSTEMTIME time = {};
        GetSystemTime(&time);
        wchar_t buffer[64] = {};
        swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
            time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond);
        return buffer;
    }

    bool HashBytes(
        const std::vector<unsigned char>& bytes,
        std::wstring& digest)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<UCHAR> object;
        std::vector<UCHAR> result;
        bool success = false;

        do
        {
            if (BCryptOpenAlgorithmProvider(
                    &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
                break;

            DWORD objectLength = 0;
            DWORD hashLength = 0;
            DWORD returned = 0;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectLength),
                    sizeof(objectLength), &returned, 0) < 0)
                break;
            if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                    reinterpret_cast<PUCHAR>(&hashLength),
                    sizeof(hashLength), &returned, 0) < 0)
                break;

            object.resize(objectLength);
            result.resize(hashLength);
            if (BCryptCreateHash(algorithm, &hash, object.data(),
                    static_cast<ULONG>(object.size()), nullptr, 0, 0) < 0)
                break;
            if (!bytes.empty() &&
                BCryptHashData(hash,
                    const_cast<PUCHAR>(bytes.data()),
                    static_cast<ULONG>(bytes.size()), 0) < 0)
                break;
            if (BCryptFinishHash(hash, result.data(),
                    static_cast<ULONG>(result.size()), 0) < 0)
                break;

            std::wostringstream stream;
            stream << std::hex << std::setfill(L'0');
            for (UCHAR value : result)
                stream << std::setw(2) << static_cast<unsigned int>(value);
            digest = ToLower(stream.str());
            success = true;
        } while (false);

        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
        return success;
    }

    bool ReadBytes(
        const std::filesystem::path& path,
        std::vector<unsigned char>& bytes)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
            return false;
        input.seekg(0, std::ios::end);
        const std::streamoff size = input.tellg();
        if (size < 0 || size > 64ll * 1024ll * 1024ll)
            return false;
        input.seekg(0, std::ios::beg);
        bytes.resize(static_cast<std::size_t>(size));
        if (size)
            input.read(reinterpret_cast<char*>(bytes.data()), size);
        return input.good() || input.eof();
    }

    std::wstring HashFile(const std::filesystem::path& path)
    {
        std::vector<unsigned char> bytes;
        std::wstring digest;
        if (ReadBytes(path, bytes))
            HashBytes(bytes, digest);
        return digest;
    }

    bool WriteAtomic(
        const std::filesystem::path& path,
        const std::vector<unsigned char>& bytes,
        std::wstring& error)
    {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec)
        {
            error = L"Cannot create cache directory: " +
                Utf8ToWide(ec.message());
            return false;
        }

        const std::filesystem::path temporary =
            std::filesystem::path(path.wstring() + L".tmp");
        {
            std::ofstream output(temporary,
                std::ios::binary | std::ios::trunc);
            if (!output)
            {
                error = L"Cannot create temporary cache file.";
                return false;
            }
            if (!bytes.empty())
                output.write(
                    reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
            if (!output)
            {
                error = L"Could not write the complete cache file.";
                return false;
            }
        }

        if (!MoveFileExW(temporary.c_str(), path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            error = L"Could not atomically replace the cache file. Win32 error " +
                std::to_wstring(GetLastError());
            DeleteFileW(temporary.c_str());
            return false;
        }
        return true;
    }

    bool WriteTextAtomic(
        const std::filesystem::path& path,
        const std::wstring& text,
        std::wstring& error)
    {
        const std::string utf8 = WideToUtf8(text);
        return WriteAtomic(path,
            std::vector<unsigned char>(utf8.begin(), utf8.end()), error);
    }

    FeedMetadata ReadMetadata(const std::filesystem::path& path)
    {
        FeedMetadata metadata;
        std::ifstream input(path, std::ios::binary);
        if (!input)
            return metadata;

        std::string line;
        while (std::getline(input, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            const std::size_t equals = line.find('=');
            if (equals == std::string::npos)
                continue;
            const std::string key = line.substr(0, equals);
            const std::wstring value = Utf8ToWide(line.substr(equals + 1));
            if (key == "etag")
                metadata.etag = value;
            else if (key == "last_modified")
                metadata.lastModified = value;
            else if (key == "sha256")
                metadata.sha256 = value;
            else if (key == "checked_utc")
                metadata.checkedUtc = value;
        }
        return metadata;
    }

    bool WriteMetadata(
        const std::filesystem::path& path,
        const FeedMetadata& metadata,
        std::wstring& error)
    {
        std::wstring text;
        text += L"etag=" + metadata.etag + L"\n";
        text += L"last_modified=" + metadata.lastModified + L"\n";
        text += L"sha256=" + metadata.sha256 + L"\n";
        text += L"checked_utc=" + metadata.checkedUtc + L"\n";
        return WriteTextAtomic(path, text, error);
    }

    std::wstring QueryHeaderString(
        HINTERNET request,
        DWORD query)
    {
        DWORD size = 0;
        WinHttpQueryHeaders(request, query,
            WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &size,
            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(wchar_t))
            return {};

        std::wstring value(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request, query,
                WINHTTP_HEADER_NAME_BY_INDEX,
                value.data(), &size,
                WINHTTP_NO_HEADER_INDEX))
            return {};

        value.resize(size / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0')
            value.pop_back();
        return Trim(std::move(value));
    }

    std::wstring QueryOptionString(HINTERNET handle, DWORD option)
    {
        DWORD size = 0;
        if (WinHttpQueryOption(handle, option, nullptr, &size) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(wchar_t))
        {
            return {};
        }

        std::wstring value(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryOption(handle, option, value.data(), &size))
            return {};

        value.resize(size / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0')
            value.pop_back();
        return Trim(std::move(value));
    }

    std::wstring DescribeError(const wchar_t* operation, DWORD errorCode)
    {
        return std::wstring(operation) + L" failed. WinHTTP/Win32 error " +
            std::to_wstring(errorCode) + L": " +
            DebugLog::FormatWin32Error(errorCode);
    }

    HttpResult ConditionalGet(
        const FeedDefinition& definition,
        const FeedMetadata& metadata)
    {
        HttpResult result;
        const std::wstring feedName = definition.name;
        const std::wstring url = definition.url;
        const bool stepSecurity =
            definition.payloadKind == FeedPayloadKind::StepSecurityHtml;

        DebugLog::Write("HTTP", L"------------------------------------------------------------");
        DebugLog::Write("HTTP", L"Beginning conditional GET for feed: " + feedName);
        DebugLog::Write("HTTP", L"Request URL: " + url);
        DebugLog::Write("HTTP", L"Cached ETag: " +
            (metadata.etag.empty() ? L"<none>" : metadata.etag));
        DebugLog::Write("HTTP", L"Cached Last-Modified: " +
            (metadata.lastModified.empty() ? L"<none>" : metadata.lastModified));
        DebugLog::Write("HTTP", L"Cached SHA-256: " +
            (metadata.sha256.empty() ? L"<none>" : metadata.sha256));

        URL_COMPONENTS components = {};
        components.dwStructSize = sizeof(components);
        components.dwSchemeLength = static_cast<DWORD>(-1);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);

        if (!WinHttpCrackUrl(url.c_str(),
                static_cast<DWORD>(url.size()), 0, &components))
        {
            const DWORD error = GetLastError();
            result.error = DescribeError(L"WinHttpCrackUrl", error);
            DebugLog::Write("HTTP", result.error);
            return result;
        }

        const std::wstring host(
            components.lpszHostName, components.dwHostNameLength);
        std::wstring path(
            components.lpszUrlPath, components.dwUrlPathLength);
        if (components.dwExtraInfoLength)
            path.append(components.lpszExtraInfo,
                components.dwExtraInfoLength);

        DebugLog::Write("HTTP", L"Parsed scheme: " +
            std::wstring(components.nScheme == INTERNET_SCHEME_HTTPS
                ? L"HTTPS" : L"HTTP"));
        DebugLog::Write("HTTP", L"Parsed host: " + host);
        DebugLog::Write("HTTP", L"Parsed port: " +
            std::to_wstring(components.nPort));
        DebugLog::Write("HTTP", L"Parsed request path: " + path);

        HINTERNET session = WinHttpOpen(
            L"ShaiHulud2Scanner/1.7.6",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session)
        {
            const DWORD error = GetLastError();
            result.error = DescribeError(L"WinHttpOpen", error);
            DebugLog::Write("HTTP", result.error);
            return result;
        }
        DebugLog::Write("HTTP", L"WinHttpOpen succeeded using automatic proxy discovery.");

        if (!WinHttpSetTimeouts(session, 8000, 8000, 15000, 30000))
        {
            DebugLog::Write("HTTP", DescribeError(
                L"WinHttpSetTimeouts", GetLastError()));
        }
        else
        {
            DebugLog::Write("HTTP",
                L"Timeouts configured: resolve=8000 ms, connect=8000 ms, "
                L"send=15000 ms, receive=30000 ms.");
        }

        DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_GZIP |
            WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
        if (!WinHttpSetOption(session, WINHTTP_OPTION_DECOMPRESSION,
                &decompression, sizeof(decompression)))
        {
            DebugLog::Write("HTTP", DescribeError(
                L"WINHTTP_OPTION_DECOMPRESSION", GetLastError()));
        }
        else
        {
            DebugLog::Write("HTTP", L"Automatic gzip/deflate decompression enabled.");
        }

        HINTERNET connection = WinHttpConnect(
            session, host.c_str(), components.nPort, 0);
        if (!connection)
        {
            const DWORD error = GetLastError();
            result.error = DescribeError(L"WinHttpConnect", error);
            DebugLog::Write("HTTP", result.error);
            WinHttpCloseHandle(session);
            return result;
        }
        DebugLog::Write("HTTP", L"WinHttpConnect succeeded.");

        HINTERNET request = WinHttpOpenRequest(
            connection, L"GET", path.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            components.nScheme == INTERNET_SCHEME_HTTPS
                ? WINHTTP_FLAG_SECURE : 0);
        if (!request)
        {
            const DWORD error = GetLastError();
            result.error = DescribeError(L"WinHttpOpenRequest", error);
            DebugLog::Write("HTTP", result.error);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return result;
        }
        DebugLog::Write("HTTP", L"WinHttpOpenRequest succeeded for GET.");

        std::wstring headers = definition.payloadKind == FeedPayloadKind::StepSecurityApi
            ? L"Accept: application/json,text/json;q=0.9,*/*;q=0.1\r\n"
            : L"Accept: text/csv,text/html,text/plain;q=0.9,*/*;q=0.1\r\n";
        headers +=
            L"Accept-Encoding: gzip, deflate\r\n"
            L"Cache-Control: no-cache\r\n"
            L"Pragma: no-cache\r\n";
        if (!metadata.etag.empty())
            headers += L"If-None-Match: " + metadata.etag + L"\r\n";
        if (!metadata.lastModified.empty())
            headers += L"If-Modified-Since: " +
                metadata.lastModified + L"\r\n";

        DebugLog::Write("HTTP", L"Request headers follow:\n" + headers);
        DebugLog::Write("HTTP", L"Request body: <none>");

        if (!WinHttpSendRequest(request,
                headers.c_str(),
                static_cast<DWORD>(headers.size()),
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        {
            const DWORD error = GetLastError();
            result.error = DescribeError(L"WinHttpSendRequest", error);
            DebugLog::Write("HTTP", result.error);
        }
        else
        {
            DebugLog::Write("HTTP", L"WinHttpSendRequest succeeded.");

            if (!WinHttpReceiveResponse(request, nullptr))
            {
                const DWORD error = GetLastError();
                result.error = DescribeError(L"WinHttpReceiveResponse", error);
                DebugLog::Write("HTTP", result.error);
            }
            else
            {
                DebugLog::Write("HTTP", L"WinHttpReceiveResponse succeeded.");

                DWORD statusSize = sizeof(result.statusCode);
                if (!WinHttpQueryHeaders(request,
                        WINHTTP_QUERY_STATUS_CODE |
                            WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &result.statusCode, &statusSize,
                        WINHTTP_NO_HEADER_INDEX))
                {
                    const DWORD error = GetLastError();
                    result.error = DescribeError(
                        L"WINHTTP_QUERY_STATUS_CODE", error);
                    DebugLog::Write("HTTP", result.error);
                }
                else
                {
                    result.etag = QueryHeaderString(
                        request, WINHTTP_QUERY_ETAG);
                    result.lastModified = QueryHeaderString(
                        request, WINHTTP_QUERY_LAST_MODIFIED);
                    result.contentType = QueryHeaderString(
                        request, WINHTTP_QUERY_CONTENT_TYPE);
                    result.contentEncoding = QueryHeaderString(
                        request, WINHTTP_QUERY_CONTENT_ENCODING);
                    result.contentLength = QueryHeaderString(
                        request, WINHTTP_QUERY_CONTENT_LENGTH);
                    result.rawResponseHeaders = QueryHeaderString(
                        request, WINHTTP_QUERY_RAW_HEADERS_CRLF);
                    result.effectiveUrl = QueryOptionString(
                        request, WINHTTP_OPTION_URL);

                    DebugLog::Write("HTTP", L"HTTP status: " +
                        std::to_wstring(result.statusCode));
                    DebugLog::Write("HTTP", L"Effective URL after redirects: " +
                        (result.effectiveUrl.empty() ? url : result.effectiveUrl));
                    DebugLog::Write("HTTP", L"Response Content-Type: " +
                        (result.contentType.empty() ? L"<not supplied>" : result.contentType));
                    DebugLog::Write("HTTP", L"Response Content-Encoding: " +
                        (result.contentEncoding.empty() ? L"<not supplied or already decompressed>" : result.contentEncoding));
                    DebugLog::Write("HTTP", L"Response Content-Length: " +
                        (result.contentLength.empty() ? L"<not supplied>" : result.contentLength));
                    DebugLog::Write("HTTP", L"Response ETag: " +
                        (result.etag.empty() ? L"<not supplied>" : result.etag));
                    DebugLog::Write("HTTP", L"Response Last-Modified: " +
                        (result.lastModified.empty() ? L"<not supplied>" : result.lastModified));
                    DebugLog::Write("HTTP", L"Raw response headers follow:\n" +
                        (result.rawResponseHeaders.empty()
                            ? L"<raw headers unavailable>"
                            : result.rawResponseHeaders));

                    if (result.statusCode != HTTP_STATUS_NOT_MODIFIED)
                    {
                        std::size_t readNumber = 0;
                        for (;;)
                        {
                            DWORD available = 0;
                            if (!WinHttpQueryDataAvailable(request, &available))
                            {
                                const DWORD error = GetLastError();
                                result.error = DescribeError(
                                    L"WinHttpQueryDataAvailable", error);
                                DebugLog::Write("HTTP", result.error);
                                result.bytes.clear();
                                break;
                            }

                            DebugLog::Write("HTTP", L"Read iteration " +
                                std::to_wstring(++readNumber) +
                                L": WinHTTP reports " +
                                std::to_wstring(available) +
                                L" bytes available.");

                            if (!available)
                                break;
                            if (result.bytes.size() + available >
                                64ull * 1024ull * 1024ull)
                            {
                                result.error =
                                    L"Feed exceeded the 64 MiB safety limit.";
                                DebugLog::Write("HTTP", result.error);
                                result.bytes.clear();
                                break;
                            }

                            const std::size_t offset = result.bytes.size();
                            result.bytes.resize(offset + available);
                            DWORD bytesRead = 0;
                            if (!WinHttpReadData(request,
                                    result.bytes.data() + offset,
                                    available, &bytesRead))
                            {
                                const DWORD error = GetLastError();
                                result.error = DescribeError(
                                    L"WinHttpReadData", error);
                                DebugLog::Write("HTTP", result.error);
                                result.bytes.clear();
                                break;
                            }
                            result.bytes.resize(offset + bytesRead);
                            DebugLog::Write("HTTP", L"Read iteration " +
                                std::to_wstring(readNumber) + L" completed: " +
                                std::to_wstring(bytesRead) +
                                L" bytes read; cumulative body size " +
                                std::to_wstring(result.bytes.size()) + L" bytes.");
                        }
                    }

                    DebugLog::Write("HTTP", L"Final response body size: " +
                        std::to_wstring(result.bytes.size()) + L" bytes.");

                    std::wstring bodyHash;
                    if (!result.bytes.empty() && HashBytes(result.bytes, bodyHash))
                        DebugLog::Write("HTTP", L"Response body SHA-256: " + bodyHash);

                    if (stepSecurity && !result.bytes.empty())
                    {
                        DebugLog::WriteBlob(
                            "STEPSECURITY/HTTP",
                            L"Complete StepSecurity HTTP response body",
                            result.bytes,
                            L"StepSecurity-response-latest.html");
                    }

                    if (result.statusCode != HTTP_STATUS_OK &&
                        result.statusCode != HTTP_STATUS_NOT_MODIFIED &&
                        result.error.empty())
                    {
                        result.error = L"Feed server returned HTTP " +
                            std::to_wstring(result.statusCode);
                        DebugLog::Write("HTTP", result.error);
                    }
                    else if (result.statusCode == HTTP_STATUS_OK &&
                             result.bytes.empty() && result.error.empty())
                    {
                        result.error = L"Feed response was empty.";
                        DebugLog::Write("HTTP", result.error);
                    }
                }
            }
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        DebugLog::Write("HTTP", L"Conditional GET completed for " + feedName +
            L". Status=" + std::to_wstring(result.statusCode) +
            L", bytes=" + std::to_wstring(result.bytes.size()) +
            L", error=" + (result.error.empty() ? L"<none>" : result.error));
        return result;
    }


    std::wstring UrlEncodeUtf8(std::string_view value)
    {
        static constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring encoded;
        encoded.reserve(value.size() * 3);
        for (const unsigned char byte : value)
        {
            const bool unreserved =
                (byte >= 'A' && byte <= 'Z') ||
                (byte >= 'a' && byte <= 'z') ||
                (byte >= '0' && byte <= '9') ||
                byte == '-' || byte == '_' || byte == '.' || byte == '~';
            if (unreserved)
            {
                encoded.push_back(static_cast<wchar_t>(byte));
            }
            else
            {
                encoded.push_back(L'%');
                encoded.push_back(hex[(byte >> 4) & 0x0F]);
                encoded.push_back(hex[byte & 0x0F]);
            }
        }
        return encoded;
    }

    std::string CsvEscapeField(const std::string& value)
    {
        if (value.find_first_of(",\"\r\n") == std::string::npos)
            return value;
        std::string output = "\"";
        for (const char ch : value)
        {
            if (ch == '\"')
                output += "\"\"";
            else
                output.push_back(ch);
        }
        output.push_back('\"');
        return output;
    }

    HttpResult FetchStepSecurityApi(const FeedDefinition& definition)
    {
        HttpResult aggregate;
        aggregate.statusCode = HTTP_STATUS_OK;
        aggregate.effectiveUrl = definition.url;

        std::set<std::pair<std::string, std::string>> allRows;
        std::set<std::string> seenTokens;
        std::string nextToken;
        constexpr std::size_t maximumPages = 250;
        bool completed = false;

        DebugLog::Write("STEPSECURITY/API",
            L"Beginning direct pagination of the public StepSecurity OSS Security Feed API.");
        DebugLog::Write("STEPSECURITY/API",
            L"Risk level: CRITICAL; page size: 100; maximum pages: " +
            std::to_wstring(maximumPages));

        for (std::size_t pageNumber = 1; pageNumber <= maximumPages; ++pageNumber)
        {
            std::wstring pageUrl = definition.url;
            pageUrl += L"?limit=100&risk_level=CRITICAL";
            if (!nextToken.empty())
                pageUrl += L"&next_token=" + UrlEncodeUtf8(nextToken);

            DebugLog::Write("STEPSECURITY/API", L"Requesting API page " +
                std::to_wstring(pageNumber) + L": " + pageUrl);

            const FeedDefinition pageDefinition =
            {
                definition.name,
                pageUrl.c_str(),
                definition.fileName,
                definition.sourceMask,
                definition.minimumRows,
                FeedPayloadKind::StepSecurityApi
            };
            const FeedMetadata noValidators;
            HttpResult page = ConditionalGet(pageDefinition, noValidators);
            if (page.statusCode != HTTP_STATUS_OK || !page.error.empty())
            {
                aggregate.statusCode = page.statusCode;
                aggregate.error = L"StepSecurity API page " +
                    std::to_wstring(pageNumber) + L" failed: " +
                    (page.error.empty()
                        ? L"HTTP " + std::to_wstring(page.statusCode)
                        : page.error);
                DebugLog::Write("STEPSECURITY/API", aggregate.error);
                return aggregate;
            }

            DebugLog::WriteBlob(
                "STEPSECURITY/API",
                L"Complete StepSecurity API response page " +
                    std::to_wstring(pageNumber),
                page.bytes,
                pageNumber == 1
                    ? L"StepSecurity-api-page-latest.json"
                    : L"");

            std::vector<std::pair<std::string, std::string>> pageRows;
            bool hasMore = false;
            std::string returnedToken;
            std::wstring parseDetail;
            if (!StepSecurityExtractor::ParseApiPage(
                    page.bytes, pageRows, hasMore, returnedToken, parseDetail))
            {
                aggregate.error = L"StepSecurity API page " +
                    std::to_wstring(pageNumber) + L" could not be parsed: " +
                    parseDetail;
                DebugLog::Write("STEPSECURITY/API", aggregate.error);
                return aggregate;
            }

            const std::size_t before = allRows.size();
            allRows.insert(pageRows.begin(), pageRows.end());
            DebugLog::Write("STEPSECURITY/API",
                L"Page " + std::to_wstring(pageNumber) + L": " +
                parseDetail + L" Added " +
                std::to_wstring(allRows.size() - before) +
                L" unique rows; total=" + std::to_wstring(allRows.size()) +
                L"; has_more=" + (hasMore ? L"true" : L"false") +
                L"; next_token=" +
                (returnedToken.empty() ? L"<none>" : Utf8ToWide(returnedToken)));

            if (!hasMore)
            {
                completed = true;
                break;
            }
            if (returnedToken.empty())
            {
                aggregate.error =
                    L"StepSecurity API pagination stopped because has_more was true but next_token was empty.";
                DebugLog::Write("STEPSECURITY/API", aggregate.error);
                return aggregate;
            }
            if (!seenTokens.insert(returnedToken).second)
            {
                aggregate.error =
                    L"StepSecurity API pagination returned a repeated next_token; refusing an infinite loop.";
                DebugLog::Write("STEPSECURITY/API", aggregate.error);
                return aggregate;
            }
            nextToken = std::move(returnedToken);
        }

        if (!completed)
        {
            aggregate.error = L"StepSecurity API exceeded the pagination safety limit of " +
                std::to_wstring(maximumPages) + L" pages.";
            DebugLog::Write("STEPSECURITY/API", aggregate.error);
            return aggregate;
        }
        if (allRows.empty())
        {
            aggregate.error = L"StepSecurity API completed but returned no CRITICAL package/version records.";
            DebugLog::Write("STEPSECURITY/API", aggregate.error);
            return aggregate;
        }

        std::ostringstream csv;
        csv << "Package,Version\n";
        for (const auto& [name, version] : allRows)
            csv << CsvEscapeField(name) << ',' << CsvEscapeField(version) << '\n';
        const std::string normalized = csv.str();
        aggregate.bytes.assign(normalized.begin(), normalized.end());
        aggregate.contentType = L"text/csv; charset=utf-8";
        aggregate.error.clear();

        DebugLog::Write("STEPSECURITY/API",
            L"StepSecurity API pagination completed successfully. Unique CRITICAL rows=" +
            std::to_wstring(allRows.size()) + L"; normalized bytes=" +
            std::to_wstring(aggregate.bytes.size()));
        DebugLog::WriteBlob(
            "STEPSECURITY/NORMALIZED",
            L"Complete normalized StepSecurity OSS Critical Feed CSV",
            aggregate.bytes,
            L"StepSecurity-normalized-latest.csv");
        return aggregate;
    }

    bool CommunityTextToCsv(
        const std::vector<unsigned char>& sourceBytes,
        std::vector<unsigned char>& csvBytes,
        std::wstring& detail)
    {
        std::string source(
            reinterpret_cast<const char*>(sourceBytes.data()),
            sourceBytes.size());
        std::istringstream input(source);
        std::ostringstream output;
        output << "Ecosystem,Package,Version\n";

        std::size_t rows = 0;
        std::string line;
        while (std::getline(input, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            const auto first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#')
                continue;
            line = line.substr(first);
            const auto lastNonSpace = line.find_last_not_of(" \t");
            if (lastNonSpace != std::string::npos)
                line.resize(lastNonSpace + 1);

            const std::size_t lastColon = line.rfind(':');
            if (lastColon == std::string::npos || lastColon == 0 ||
                lastColon + 1 >= line.size())
                continue;

            std::string ecosystem = "npm";
            std::string package = line.substr(0, lastColon);
            const std::string version = line.substr(lastColon + 1);
            const std::size_t firstColon = package.find(':');
            if (firstColon != std::string::npos)
            {
                std::string prefix = package.substr(0, firstColon);
                std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                    [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                if (prefix == "npm" || prefix == "pypi" ||
                    prefix == "golang" || prefix == "go" ||
                    prefix == "composer" || prefix == "crates")
                {
                    ecosystem = prefix == "go" ? "golang" : prefix;
                    package = package.substr(firstColon + 1);
                }
            }

            if (package.empty() || version.empty())
                continue;

            const auto csvEscape = [](const std::string& value)
            {
                if (value.find_first_of(",\"\r\n") == std::string::npos)
                    return value;
                std::string escaped = "\"";
                for (const char ch : value)
                {
                    if (ch == '\"')
                        escaped += "\"\"";
                    else
                        escaped += ch;
                }
                escaped += '\"';
                return escaped;
            };

            output << csvEscape(ecosystem) << ','
                   << csvEscape(package) << ','
                   << csvEscape(version) << '\n';
            ++rows;
        }

        if (rows == 0)
        {
            detail = L"The community list contained no usable package/version entries.";
            return false;
        }

        const std::string csv = output.str();
        csvBytes.assign(csv.begin(), csv.end());
        detail = L"Converted " + std::to_wstring(rows) +
            L" community list entries to normalized CSV.";
        return true;
    }

    bool NormalizeFeedPayload(
        const FeedDefinition& definition,
        const std::vector<unsigned char>& downloadedBytes,
        std::vector<unsigned char>& normalizedBytes,
        std::wstring& detail)
    {
        if (definition.payloadKind == FeedPayloadKind::Csv ||
            definition.payloadKind == FeedPayloadKind::StepSecurityApi)
        {
            normalizedBytes = downloadedBytes;
            detail = definition.payloadKind == FeedPayloadKind::StepSecurityApi
                ? L"StepSecurity API pages were combined into Package,Version CSV."
                : L"CSV response accepted for validation.";
            return true;
        }
        if (definition.payloadKind == FeedPayloadKind::CommunityText)
            return CommunityTextToCsv(downloadedBytes, normalizedBytes, detail);

        return StepSecurityExtractor::HtmlToCsv(
            downloadedBytes, normalizedBytes, detail, nullptr);
    }

    bool ValidateCsvFile(
        const std::filesystem::path& path,
        std::size_t minimumRows,
        std::wstring& detail,
        std::size_t* parsedRowsOut = nullptr)
    {
        IndicatorDatabase validation;
        validation.Clear();

        std::size_t addedPairs = 0;
        std::size_t parsedRows = 0;
        if (!validation.MergeCsv(path, detail,
                &addedPairs, &parsedRows))
            return false;

        if (parsedRowsOut)
            *parsedRowsOut = parsedRows;

        if (parsedRows < minimumRows)
        {
            detail = L"Validation rejected a suspiciously small feed (" +
                std::to_wstring(parsedRows) + L" parsed rows).";
            return false;
        }
        return true;
    }

    bool ValidateCsvBytes(
        const std::filesystem::path& cachePath,
        const std::vector<unsigned char>& bytes,
        std::size_t minimumRows,
        std::wstring& detail,
        std::size_t* parsedRowsOut = nullptr)
    {
        std::error_code ec;
        std::filesystem::create_directories(
            cachePath.parent_path(), ec);
        if (ec)
        {
            detail = L"Could not create the validation directory: " +
                Utf8ToWide(ec.message());
            return false;
        }

        const std::filesystem::path validationPath =
            std::filesystem::path(cachePath.wstring() + L".validate");
        {
            std::ofstream output(validationPath,
                std::ios::binary | std::ios::trunc);
            if (!output)
            {
                detail = L"Could not create the validation file.";
                return false;
            }
            output.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
            if (!output)
            {
                detail = L"Could not write the validation file.";
                DeleteFileW(validationPath.c_str());
                return false;
            }
        }

        const bool valid = ValidateCsvFile(
            validationPath, minimumRows, detail, parsedRowsOut);
        DeleteFileW(validationPath.c_str());
        return valid;
    }

    std::filesystem::path SelectValidLocalFeed(
        const std::filesystem::path& cached,
        const std::filesystem::path& bundled,
        std::size_t minimumRows,
        std::wstring& state)
    {
        std::wstring validation;
        std::error_code ec;

        if (std::filesystem::exists(cached, ec) &&
            ValidateCsvFile(cached, minimumRows, validation))
        {
            state = L"valid cached snapshot";
            return cached;
        }

        ec.clear();
        if (std::filesystem::exists(bundled, ec) &&
            ValidateCsvFile(bundled, minimumRows, validation))
        {
            state = L"valid bundled snapshot";
            return bundled;
        }

        state = validation.empty()
            ? L"no local snapshot found"
            : L"local snapshot validation failed: " + validation;
        return {};
    }
}

FeedSyncResult FeedUpdater::Sync(
    const std::filesystem::path& executableDirectory,
    IndicatorDatabase& database,
    bool refreshOnline)
{
    FeedSyncResult result;
    const std::filesystem::path bundledDirectory = executableDirectory / L"data";
    const std::filesystem::path cacheDirectory = LocalFeedDirectory();

    DebugLog::Write("FEED/SYNC", L"============================================================");
    DebugLog::Write("FEED/SYNC", L"Feed synchronization started.");
    DebugLog::Write("FEED/SYNC", L"Online refresh requested: " +
        std::wstring(refreshOnline ? L"yes" : L"no"));
    DebugLog::Write("FEED/SYNC", L"Executable directory: " + executableDirectory.wstring());
    DebugLog::Write("FEED/SYNC", L"Bundled feed directory: " + bundledDirectory.wstring());
    DebugLog::Write("FEED/SYNC", L"Cache feed directory: " + cacheDirectory.wstring());

    database.Clear();

    std::vector<std::wstring> degradedFeeds;
    const auto markDegraded = [&](const std::wstring& name)
    {
        if (std::find(degradedFeeds.begin(), degradedFeeds.end(), name) == degradedFeeds.end())
            degradedFeeds.push_back(name);
    };

    for (const auto& definition : kFeeds)
    {
        FeedStatus status;
        status.name = definition.name;
        status.url = definition.url;

        DebugLog::Write("FEED/SYNC", L"------------------------------------------------------------");
        DebugLog::Write("FEED/SYNC", L"Processing source: " + status.name);
        DebugLog::Write("FEED/SYNC", L"Configured URL: " + status.url);
        DebugLog::Write("FEED/SYNC", L"Minimum accepted rows: " +
            std::to_wstring(definition.minimumRows));

        const std::filesystem::path bundled = bundledDirectory / definition.fileName;
        const std::filesystem::path cached = cacheDirectory / definition.fileName;
        const std::filesystem::path metadataPath =
            std::filesystem::path(cached.wstring() + L".meta");

        DebugLog::Write("FEED/SYNC", L"Bundled snapshot path: " + bundled.wstring());
        DebugLog::Write("FEED/SYNC", L"Cached snapshot path: " + cached.wstring());
        DebugLog::Write("FEED/SYNC", L"Metadata path: " + metadataPath.wstring());

        std::wstring localState;
        std::filesystem::path selected = SelectValidLocalFeed(
            cached, bundled, definition.minimumRows, localState);
        std::wstring selectedHash = selected.empty() ? L"" : HashFile(selected);
        std::size_t selectedRows = 0;
        if (!selected.empty())
        {
            std::wstring ignoredValidation;
            const bool selectedValid = ValidateCsvFile(
                selected, definition.minimumRows,
                ignoredValidation, &selectedRows);
            DebugLog::Write("FEED/SYNC", L"Local selection: " + localState);
            DebugLog::Write("FEED/SYNC", L"Selected local snapshot: " + selected.wstring());
            DebugLog::Write("FEED/SYNC", L"Selected local snapshot validation: " +
                std::wstring(selectedValid ? L"accepted" : L"rejected") +
                L"; parsed rows=" + std::to_wstring(selectedRows) +
                L"; detail=" + ignoredValidation);
            DebugLog::Write("FEED/SYNC", L"Selected local snapshot SHA-256: " + selectedHash);
        }
        else
        {
            DebugLog::Write("FEED/SYNC", L"No valid local snapshot selected. State: " + localState);
        }

        FeedMetadata metadata = ReadMetadata(metadataPath);
        DebugLog::Write("FEED/SYNC", L"Metadata ETag: " +
            (metadata.etag.empty() ? L"<none>" : metadata.etag));
        DebugLog::Write("FEED/SYNC", L"Metadata Last-Modified: " +
            (metadata.lastModified.empty() ? L"<none>" : metadata.lastModified));
        DebugLog::Write("FEED/SYNC", L"Metadata SHA-256: " +
            (metadata.sha256.empty() ? L"<none>" : metadata.sha256));
        DebugLog::Write("FEED/SYNC", L"Metadata last checked UTC: " +
            (metadata.checkedUtc.empty() ? L"<none>" : metadata.checkedUtc));
        if (selected.empty() || selectedHash.empty() || metadata.sha256.empty() ||
            ToLower(metadata.sha256) != ToLower(selectedHash))
        {
            metadata.etag.clear();
            metadata.lastModified.clear();
            metadata.sha256 = selectedHash;
        }

        auto selectedIsCache = [&]()
        {
            std::error_code ec;
            return !selected.empty() && std::filesystem::equivalent(selected, cached, ec) && !ec;
        };
        auto fallbackKind = [&](bool rejected)
        {
            if (selectedIsCache())
                return rejected ? FeedStateKind::RejectedCached : FeedStateKind::OfflineCached;
            return rejected ? FeedStateKind::RejectedBundled : FeedStateKind::OfflineBundled;
        };

        status.kind = FeedStateKind::Current;
        if (refreshOnline)
        {
            const HttpResult http =
                definition.payloadKind == FeedPayloadKind::StepSecurityApi
                    ? FetchStepSecurityApi(definition)
                    : ConditionalGet(definition, metadata);
            if (http.statusCode == HTTP_STATUS_NOT_MODIFIED)
            {
                status.online = true;
                status.notModified = true;
                status.kind = FeedStateKind::Current;
                status.detail = L"HTTP 304: the provider confirmed that the active snapshot is current.";
                metadata.checkedUtc = UtcNow();
                if (!http.etag.empty()) metadata.etag = http.etag;
                if (!http.lastModified.empty()) metadata.lastModified = http.lastModified;
                if (metadata.sha256.empty()) metadata.sha256 = selectedHash;
                std::wstring metadataWriteError;
                const bool metadataWritten = WriteMetadata(
                    metadataPath, metadata, metadataWriteError);
                DebugLog::Write("FEED/CACHE", L"HTTP 304 metadata write: " +
                    std::wstring(metadataWritten ? L"success" : L"failure") +
                    (metadataWriteError.empty() ? L"" : L"; " + metadataWriteError));
            }
            else if (http.statusCode == HTTP_STATUS_OK && http.error.empty())
            {
                status.online = true;
                std::vector<unsigned char> normalizedBytes;
                std::wstring normalizationDetail;
                DebugLog::Write("FEED/NORMALIZE", L"Beginning payload normalization for " + status.name +
                    L". Downloaded bytes=" + std::to_wstring(http.bytes.size()));
                const bool normalized = NormalizeFeedPayload(
                    definition, http.bytes, normalizedBytes, normalizationDetail);
                DebugLog::Write("FEED/NORMALIZE", L"Normalization result for " + status.name +
                    L": " + std::wstring(normalized ? L"success" : L"failure") +
                    L"; normalized bytes=" + std::to_wstring(normalizedBytes.size()) +
                    L"; detail=" + normalizationDetail);
                if ((definition.payloadKind == FeedPayloadKind::StepSecurityHtml ||
                     definition.payloadKind == FeedPayloadKind::StepSecurityApi) &&
                    normalized && !normalizedBytes.empty())
                {
                    DebugLog::WriteBlob(
                        "STEPSECURITY/NORMALIZED",
                        L"Complete normalized StepSecurity Package,Version CSV",
                        normalizedBytes,
                        L"StepSecurity-normalized-latest.csv");
                }
                if (!normalized)
                {
                    // StepSecurity currently treats the blog as the public advisory and
                    // exposes the complete component list through its authenticated API.
                    // A reachable advisory is therefore not a failed feed update when a
                    // previously validated source-specific snapshot is already active.
                    if (definition.payloadKind == FeedPayloadKind::StepSecurityHtml &&
                        !selected.empty() && selectedRows >= definition.minimumRows)
                    {
                        status.kind = FeedStateKind::AdvisoryCurrent;
                        status.detail =
                            L"The StepSecurity advisory was checked successfully. The page did not "
                            L"expose a complete public machine-readable package list, so the "
                            L"validated StepSecurity snapshot remains active. " + normalizationDetail;
                        metadata.checkedUtc = UtcNow();
                        if (!http.etag.empty()) metadata.etag = http.etag;
                        if (!http.lastModified.empty()) metadata.lastModified = http.lastModified;
                        metadata.sha256 = selectedHash;
                        std::wstring metadataError;
                        const bool metadataWritten = WriteMetadata(
                            metadataPath, metadata, metadataError);
                        DebugLog::Write("FEED/CACHE", L"StepSecurity advisory metadata write: " +
                            std::wstring(metadataWritten ? L"success" : L"failure") +
                            (metadataError.empty() ? L"" : L"; " + metadataError));
                    }
                    else
                    {
                        result.anyValidationFailure = true;
                        status.validationFailed = true;
                        status.kind = fallbackKind(true);
                        status.detail = L"Remote response rejected: " + normalizationDetail;
                        markDegraded(status.name);
                    }
                }
                else
                {
                    std::wstring validation;
                    std::size_t remoteRows = 0;
                    DebugLog::Write("FEED/VALIDATE", L"Validating normalized payload for " + status.name +
                        L" against minimum row count " + std::to_wstring(definition.minimumRows) + L".");
                    const bool remoteValid = ValidateCsvBytes(
                        cached, normalizedBytes,
                        definition.minimumRows, validation, &remoteRows);
                    DebugLog::Write("FEED/VALIDATE", L"Validation result for " + status.name +
                        L": " + std::wstring(remoteValid ? L"accepted" : L"rejected") +
                        L"; parsed rows=" + std::to_wstring(remoteRows) +
                        L"; detail=" + validation);
                    if (!remoteValid)
                    {
                        result.anyValidationFailure = true;
                        status.validationFailed = true;
                        status.kind = fallbackKind(true);
                        status.detail = L"Remote response rejected: " + validation;
                        markDegraded(status.name);
                    }
                    else if (definition.payloadKind != FeedPayloadKind::StepSecurityApi &&
                             selectedRows >= definition.minimumRows &&
                             remoteRows * 2 < selectedRows)
                    {
                        result.anyValidationFailure = true;
                        status.validationFailed = true;
                        status.kind = fallbackKind(true);
                        status.detail = L"Remote response rejected as a probable truncation: " +
                            std::to_wstring(remoteRows) + L" rows received; " +
                            std::to_wstring(selectedRows) + L" rows are active locally.";
                        markDegraded(status.name);
                    }
                    else
                    {
                        std::wstring onlineHash;
                        const bool hashOk = HashBytes(normalizedBytes, onlineHash);
                        status.sha256 = onlineHash;
                        DebugLog::Write("FEED/VALIDATE", L"Normalized payload SHA-256 calculation for " +
                            status.name + L": " + std::wstring(hashOk ? L"success" : L"failure") +
                            L"; digest=" + (onlineHash.empty() ? L"<none>" : onlineHash));
                        DebugLog::Write("FEED/VALIDATE", L"Current active SHA-256: " +
                            (selectedHash.empty() ? L"<none>" : selectedHash));

                        FeedMetadata updatedMetadata = metadata;
                        updatedMetadata.etag = http.etag;
                        updatedMetadata.lastModified = http.lastModified;
                        updatedMetadata.sha256 = onlineHash;
                        updatedMetadata.checkedUtc = UtcNow();

                        if (!selectedHash.empty() && ToLower(onlineHash) == ToLower(selectedHash))
                        {
                            status.kind = FeedStateKind::Current;
                            status.detail = L"HTTP 200: normalized content is unchanged. " + normalizationDetail;
                            DebugLog::Write("FEED/CACHE", L"Normalized content is unchanged; active snapshot retained.");
                            std::wstring metadataError;
                            const bool metadataWritten = WriteMetadata(
                                metadataPath, updatedMetadata, metadataError);
                            DebugLog::Write("FEED/CACHE", L"Unchanged-content metadata write: " +
                                std::wstring(metadataWritten ? L"success" : L"failure") +
                                (metadataError.empty() ? L"" : L"; " + metadataError));
                        }
                        else
                        {
                            std::wstring writeError;
                            if (WriteAtomic(cached, normalizedBytes, writeError))
                            {
                                selected = cached;
                                selectedHash = onlineHash;
                                selectedRows = remoteRows;
                                status.updated = true;
                                status.kind = FeedStateKind::Updated;
                                status.detail = L"Downloaded, validated, and activated a new snapshot. " + normalizationDetail;
                                DebugLog::Write("FEED/CACHE", L"New validated snapshot activated at: " + cached.wstring());
                                std::wstring metadataError;
                                const bool metadataWritten = WriteMetadata(
                                    metadataPath, updatedMetadata, metadataError);
                                DebugLog::Write("FEED/CACHE", L"Updated-snapshot metadata write: " +
                                    std::wstring(metadataWritten ? L"success" : L"failure") +
                                    (metadataError.empty() ? L"" : L"; " + metadataError));
                            }
                            else
                            {
                                result.anyValidationFailure = true;
                                status.validationFailed = true;
                                status.kind = fallbackKind(true);
                                status.detail = L"The new snapshot validated but could not be cached: " + writeError;
                                DebugLog::Write("FEED/CACHE", L"Cache activation failed: " + writeError);
                                markDegraded(status.name);
                            }
                        }
                    }
                }
            }
            else
            {
                result.anyOnlineFailure = true;
                status.onlineFailure = true;
                status.kind = fallbackKind(false);
                status.detail = L"Online check failed: " +
                    (http.error.empty() ? L"HTTP " + std::to_wstring(http.statusCode) : http.error);
                markDegraded(status.name);
            }
        }
        else
        {
            status.kind = FeedStateKind::Current;
            status.detail = L"Startup used the active local snapshot. Online refresh has not run yet.";
        }

        if (selected.empty())
        {
            selected = SelectValidLocalFeed(cached, bundled,
                definition.minimumRows, localState);
            selectedHash = selected.empty() ? L"" : HashFile(selected);
        }

        if (!selected.empty())
        {
            std::wstring loadDetail;
            std::size_t addedPairs = 0;
            std::size_t parsedRows = 0;

            IndicatorDatabase sourceDatabase;
            sourceDatabase.Clear();
            std::wstring sourceDetail;
            std::size_t sourceAddedPairs = 0;
            std::size_t sourceRows = 0;
            DebugLog::Write("FEED/LOAD", L"Loading active source file: " + selected.wstring());
            const bool sourceParsed = sourceDatabase.MergeCsv(
                selected, sourceDetail, &sourceAddedPairs, &sourceRows);
            DebugLog::Write("FEED/LOAD", L"Source-only parse: " +
                std::wstring(sourceParsed ? L"success" : L"failure") +
                L"; rows=" + std::to_wstring(sourceRows) +
                L"; exact pairs=" + std::to_wstring(sourceDatabase.PairCount()) +
                L"; detail=" + sourceDetail);

            const bool merged = database.MergeCsv(
                selected, loadDetail, &addedPairs, &parsedRows);
            DebugLog::Write("FEED/LOAD", L"Merged database parse: " +
                std::wstring(merged ? L"success" : L"failure") +
                L"; parsed rows=" + std::to_wstring(parsedRows) +
                L"; newly contributed pairs=" + std::to_wstring(addedPairs) +
                L"; detail=" + loadDetail);

            if (merged)
            {
                status.loaded = true;
                status.source = selected.wstring();
                status.loadedRows = parsedRows;
                status.loadedPairs = sourceParsed ? sourceDatabase.PairCount() : sourceAddedPairs;
                status.addedPairs = addedPairs;
                if (status.sha256.empty()) status.sha256 = selectedHash;
                std::error_code eqError;
                status.usedBundledFallback =
                    std::filesystem::equivalent(selected, bundled, eqError) && !eqError &&
                    status.kind != FeedStateKind::Current &&
                    status.kind != FeedStateKind::Updated &&
                    status.kind != FeedStateKind::AdvisoryCurrent;
            }
            else
            {
                result.anyValidationFailure = true;
                database.AddBuiltIn(definition.sourceMask);
                status.usedBuiltInFallback = true;
                status.validationFailed = true;
                status.kind = FeedStateKind::EmbeddedFallback;
                status.detail += L" The active file could not be loaded; the embedded source-specific array is active: " + loadDetail;
                markDegraded(status.name);
            }
        }
        else
        {
            database.AddBuiltIn(definition.sourceMask);
            status.usedBuiltInFallback = true;
            status.validationFailed = true;
            status.kind = FeedStateKind::EmbeddedFallback;
            status.detail += L" No valid local snapshot was available; the embedded source-specific array is active.";
            markDegraded(status.name);
        }

        const std::wstring loaded = L"Loaded " + std::to_wstring(status.loadedRows) +
            L" rows / " + std::to_wstring(status.loadedPairs) + L" pairs";
        switch (status.kind)
        {
        case FeedStateKind::Updated:
            status.state = L"Updated - " + loaded;
            break;
        case FeedStateKind::Current:
        case FeedStateKind::AdvisoryCurrent:
            status.state = L"Already up to date - " + loaded;
            break;
        case FeedStateKind::OfflineCached:
            status.state = L"Offline - Using cached snapshot (" + loaded + L")";
            break;
        case FeedStateKind::OfflineBundled:
            status.state = L"Offline - Using bundled snapshot (" + loaded + L")";
            break;
        case FeedStateKind::RejectedCached:
            status.state = L"Rejected - Using cached snapshot (" + loaded + L")";
            break;
        case FeedStateKind::RejectedBundled:
            status.state = L"Rejected - Using bundled snapshot (" + loaded + L")";
            break;
        case FeedStateKind::EmbeddedFallback:
            status.state = L"Fallback - Embedded indicators active";
            break;
        case FeedStateKind::Unavailable:
            status.state = L"Unavailable";
            break;
        case FeedStateKind::Updating:
            status.state = L"Updating";
            break;
        }

        DebugLog::Write("FEED/SYNC", L"Final source state for " + status.name +
            L": " + status.state);
        DebugLog::Write("FEED/SYNC", L"Final source detail: " + status.detail);
        DebugLog::Write("FEED/SYNC", L"Active source path: " +
            (status.source.empty() ? L"<embedded array>" : status.source));
        DebugLog::Write("FEED/SYNC", L"Loaded rows=" + std::to_wstring(status.loadedRows) +
            L", source pairs=" + std::to_wstring(status.loadedPairs) +
            L", unique merged contribution=" + std::to_wstring(status.addedPairs));

        result.feeds.push_back(std::move(status));
    }

    std::wostringstream summary;
    summary << database.PackageCount() << L" package names / "
            << database.PairCount() << L" affected name@version pairs / "
            << result.feeds.size() << L" sources";
    result.summary = summary.str();

    if (degradedFeeds.empty())
    {
        result.healthSummary = L"All configured threat-intelligence sources are current.";
    }
    else
    {
        std::wostringstream health;
        health << L"Threat intelligence degraded: ";
        for (std::size_t index = 0; index < degradedFeeds.size(); ++index)
        {
            if (index) health << L", ";
            health << degradedFeeds[index];
        }
        health << (degradedFeeds.size() == 1
            ? L" is using a validated local or embedded fallback."
            : L" are using validated local or embedded fallbacks.");
        result.healthSummary = health.str();
    }
    DebugLog::Write("FEED/SYNC", L"Feed synchronization completed.");
    DebugLog::Write("FEED/SYNC", L"Merged summary: " + result.summary);
    DebugLog::Write("FEED/SYNC", L"Health summary: " + result.healthSummary);
    DebugLog::Write("FEED/SYNC", L"Any online failure: " +
        std::wstring(result.anyOnlineFailure ? L"yes" : L"no"));
    DebugLog::Write("FEED/SYNC", L"Any validation failure: " +
        std::wstring(result.anyValidationFailure ? L"yes" : L"no"));
    DebugLog::Flush();
    return result;
}
