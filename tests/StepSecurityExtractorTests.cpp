#include "StepSecurityExtractor.h"

#include <iostream>
#include <string>
#include <vector>

namespace
{
    bool ExtractsExactly(const std::string& input, std::size_t expected, const char* name)
    {
        const std::vector<unsigned char> source(input.begin(), input.end());
        std::vector<unsigned char> csv;
        std::wstring detail;
        std::size_t rows = 0;
        const bool ok = StepSecurityExtractor::HtmlToCsv(source, csv, detail, &rows);
        if (!ok || rows != expected)
        {
            std::wcerr << L"[FAIL] " << name << L": rows=" << rows
                       << L" detail=" << detail << L"\n";
            return false;
        }
        std::cout << "[OK] " << name << ": " << rows << " rows\n";
        return true;
    }

    std::string JavaScriptArray()
    {
        std::string page = "<script>const campaignPackages=[";
        for (int index = 0; index < 500; ++index)
        {
            if (index) page += ',';
            page += "[\"array-package-" + std::to_string(index) +
                "\",[\"1.0." + std::to_string(index) + "\"]]";
        }
        page += "];</script>";
        return page;
    }

    std::string JsonRecords()
    {
        std::string page = "<script type=\"application/json\">[";
        for (int index = 0; index < 500; ++index)
        {
            if (index) page += ',';
            page += "{\"package\":\"json-package-" + std::to_string(index) +
                "\",\"version\":\"2.0." + std::to_string(index) + "\"}";
        }
        page += "]</script>";
        return page;
    }


    bool ParsesApiPage()
    {
        const std::string json =
            R"({"results":[{"package_name":"keyv","version":"6.0.0"},{"package_name":"@scope/package","version":"1.2.3"}],"has_more":true,"next_token":"abc+/="})";
        const std::vector<unsigned char> source(json.begin(), json.end());
        std::vector<std::pair<std::string, std::string>> rows;
        bool hasMore = false;
        std::string nextToken;
        std::wstring detail;
        const bool ok = StepSecurityExtractor::ParseApiPage(
            source, rows, hasMore, nextToken, detail);
        if (!ok || rows.size() != 2 || !hasMore || nextToken != "abc+/=")
        {
            std::wcerr << L"[FAIL] StepSecurity API page: rows=" << rows.size()
                       << L" hasMore=" << hasMore << L" detail=" << detail << L"\n";
            return false;
        }
        std::cout << "[OK] StepSecurity API page and pagination token\n";
        return true;
    }

    std::string HtmlTable()
    {
        std::string page = "<table><tbody>";
        for (int index = 0; index < 500; ++index)
        {
            page += "<tr><td><code>table-package-" + std::to_string(index) +
                "</code></td><td>3.0." + std::to_string(index) + "</td></tr>";
        }
        page += "</tbody></table>";
        return page;
    }
}

int main()
{
    const bool arrayOk = ExtractsExactly(JavaScriptArray(), 500, "JavaScript package array");
    const bool jsonOk = ExtractsExactly(JsonRecords(), 500, "embedded JSON records");
    const bool tableOk = ExtractsExactly(HtmlTable(), 500, "HTML package table");
    const bool apiOk = ParsesApiPage();
    return arrayOk && jsonOk && tableOk && apiOk ? 0 : 1;
}
