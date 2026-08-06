#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace StepSecurityExtractor
{
    // Converts the HTML source of the StepSecurity ChainDrop article into the
    // same Package,Version CSV produced by the page's Download CSV button.
    // The article stores the rows in a JavaScript D array shaped as:
    // [[packageName, [version1, version2, ...]], ...]
    bool HtmlToCsv(
        const std::vector<unsigned char>& pageBytes,
        std::vector<unsigned char>& csvBytes,
        std::wstring& detail,
        std::size_t* rowCount = nullptr);

    // Parses one page returned by the public StepSecurity OSS Security Feed API.
    // Each page contains results with package_name/version fields plus pagination
    // metadata (has_more and next_token).
    bool ParseApiPage(
        const std::vector<unsigned char>& jsonBytes,
        std::vector<std::pair<std::string, std::string>>& rows,
        bool& hasMore,
        std::string& nextToken,
        std::wstring& detail);
}
