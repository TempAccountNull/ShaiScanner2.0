#include "FeedUpdater.h"
#include "Scanner.h"
#include "DebugLog.h"

#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <shellapi.h>
#include "resource.h"
#include <shlobj.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

// Dear ImGui intentionally does not expose this Win32-specific declaration in
// the backend header because doing so would require including windows.h there.
// The official Win32 examples forward-declare it in the application.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND window, UINT message, WPARAM wParam, LPARAM lParam);

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

namespace
{
    constexpr wchar_t kWindowClass[] = L"ShaiHulud2ScannerImGuiWindow";
    constexpr wchar_t kWindowTitle[] = L"Shai-Hulud 2.0 Scanner";
    constexpr const char* kVersion = "1.7.6";

    ID3D11Device* g_device = nullptr;
    ID3D11DeviceContext* g_deviceContext = nullptr;
    IDXGISwapChain* g_swapChain = nullptr;
    ID3D11RenderTargetView* g_renderTargetView = nullptr;

    ImFont* g_fontRegular = nullptr;
    ImFont* g_fontSemibold = nullptr;
    ImFont* g_fontTitle = nullptr;
    ImFont* g_fontMono = nullptr;

    struct ResponsiveLayout
    {
        ImVec2 displaySize{};
        float scale = 1.0f;
        float viewportUnitX = 1.0f;
        float viewportUnitY = 1.0f;
        float viewportMinUnit = 1.0f;
        float bodyFontPixels = 1.0f;
    } g_layout;

    ImGuiStyle g_baseStyle;

    // Layout geometry is derived directly from the current viewport, active font metrics, and measured content.

    float ViewportWidth(float fraction)
    {
        return g_layout.displaySize.x * fraction;
    }

    float ViewportHeight(float fraction)
    {
        return g_layout.displaySize.y * fraction;
    }

    float Em(float multiplier)
    {
        return ImGui::GetFontSize() * multiplier;
    }

    float TextWidth(const char* text)
    {
        return ImGui::CalcTextSize(text ? text : "").x;
    }

    float ContentChildHeight(unsigned lineCount, unsigned spacingCount = 0)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        return style.WindowPadding.y * 2.0f +
            ImGui::GetTextLineHeightWithSpacing() * static_cast<float>(lineCount) +
            style.ItemSpacing.y * static_cast<float>(spacingCount);
    }

    int FittedColumnCount(float availableWidth, float contentWidth, int maximumColumns)
    {
        const float spacing = ImGui::GetStyle().ItemSpacing.x;
        if (maximumColumns <= 1 || availableWidth <= contentWidth)
            return 1;
        const float raw = (availableWidth + spacing) / (contentWidth + spacing);
        return (std::max)(1, (std::min)(maximumColumns, static_cast<int>(std::floor(raw))));
    }

    float ColumnWidth(float availableWidth, int columnCount)
    {
        const float spacing = ImGui::GetStyle().ItemSpacing.x;
        return (std::max)(0.0f,
            (availableWidth - spacing * static_cast<float>(columnCount - 1)) /
            static_cast<float>(columnCount));
    }

    int FittedBalancedColumnCount(float availableWidth, float contentWidth,
        int itemCount, int maximumColumns)
    {
        int columns = FittedColumnCount(availableWidth, contentWidth,
            (std::min)(itemCount, maximumColumns));
        while (columns > 1 && itemCount % columns != 0)
            --columns;
        return columns;
    }

    bool CanPlaceNextInline(float itemWidth)
    {
        return ImGui::GetCursorPosX() + itemWidth <=
            ImGui::GetWindowContentRegionMax().x;
    }

    void FlowSameLine(float nextItemWidth)
    {
        if (CanPlaceNextInline(nextItemWidth + ImGui::GetStyle().ItemSpacing.x))
            ImGui::SameLine();
    }

    void UpdateResponsiveLayout()
    {
        ImGuiIO& io = ImGui::GetIO();
        g_layout.displaySize = io.DisplaySize;
        g_layout.viewportUnitX = io.DisplaySize.x * 0.01f;
        g_layout.viewportUnitY = io.DisplaySize.y * 0.01f;
        g_layout.viewportMinUnit = (std::min)(g_layout.viewportUnitX, g_layout.viewportUnitY);

        // Derive the live type scale from the current client area. Style metrics
        // are then rebuilt directly from that live em size. Do not call
        // ImGuiStyle::ScaleAllSizes() here: it truncates every metric to an
        // integer. When a resize moved the scale below 1.0, one-pixel borders
        // became zero and the entire interface abruptly lost its boxes.
        const float widthDrivenFont = io.DisplaySize.x * 0.0105f;
        const float heightDrivenFont = io.DisplaySize.y * 0.0185f;
        g_layout.bodyFontPixels = (std::min)(widthDrivenFont, heightDrivenFont);

        ImGui::GetStyle() = g_baseStyle;
        ImGuiStyle& style = ImGui::GetStyle();
        const float fontDpiScale = style.FontScaleDpi > 0.0f ? style.FontScaleDpi : 1.0f;
        const float nativeBodySize = g_fontRegular && g_fontRegular->LegacySize > 0.0f
            ? g_fontRegular->LegacySize : style.FontSizeBase;
        const float displayedNativeSize = nativeBodySize * fontDpiScale;
        g_layout.scale = displayedNativeSize > 0.0f
            ? g_layout.bodyFontPixels / displayedNativeSize : 1.0f;
        style.FontScaleMain = g_baseStyle.FontScaleMain * g_layout.scale;

        const float em = g_layout.bodyFontPixels;
        const float framebufferX = io.DisplayFramebufferScale.x > 0.0f
            ? io.DisplayFramebufferScale.x : 1.0f;
        const float framebufferY = io.DisplayFramebufferScale.y > 0.0f
            ? io.DisplayFramebufferScale.y : 1.0f;
        const float onePhysicalPixel = (std::max)(
            1.0f / framebufferX, 1.0f / framebufferY);
        const float border = (std::max)(em * 0.059f, onePhysicalPixel);

        // All geometry stays proportional to the live font and viewport. These
        // are floating-point assignments, so resizing remains continuous rather
        // than snapping or collapsing when the scale crosses an integer boundary.
        style.WindowPadding = ImVec2(em * 0.94f, em * 0.82f);
        style.FramePadding = ImVec2(em * 0.59f, em * 0.41f);
        style.CellPadding = ImVec2(em * 0.59f, em * 0.41f);
        style.ItemSpacing = ImVec2(em * 0.53f, em * 0.47f);
        style.ItemInnerSpacing = ImVec2(em * 0.41f, em * 0.35f);
        style.IndentSpacing = em * 1.24f;
        style.ColumnsMinSpacing = em * 0.35f;
        style.ScrollbarSize = em * 0.59f;
        style.GrabMinSize = em * 0.71f;
        style.WindowMinSize = ImVec2(em * 1.88f, em * 1.88f);
        style.DisplayWindowPadding = ImVec2(em * 1.12f, em * 1.12f);
        style.DisplaySafeAreaPadding = ImVec2(em * 0.18f, em * 0.18f);

        style.WindowRounding = 0.0f;
        style.ChildRounding = em * 0.29f;
        style.FrameRounding = em * 0.24f;
        style.PopupRounding = em * 0.35f;
        style.ScrollbarRounding = em * 0.53f;
        style.GrabRounding = em * 0.24f;
        style.TabRounding = em * 0.24f;

        style.WindowBorderSize = 0.0f;
        style.ChildBorderSize = border;
        style.FrameBorderSize = border;
        style.PopupBorderSize = border;
        style.TabBorderSize = border;
        style.TabBarBorderSize = border;
        style.TabBarOverlineSize = border;
        style.SeparatorSize = border;
        style.SeparatorTextBorderSize = border;
        style.TreeLinesSize = border;
        style.ImageBorderSize = border;
        style.DragDropTargetBorderSize = border;
    }

    float NativeFontSize(ImFont* font)
    {
        if (font && font->LegacySize > 0.0f)
            return font->LegacySize;
        if (g_fontRegular && g_fontRegular->LegacySize > 0.0f)
            return g_fontRegular->LegacySize;
        return ImGui::GetStyle().FontSizeBase;
    }

    void PushNativeFont(ImFont* font)
    {
        ImGui::PushFont(font, NativeFontSize(font));
    }

    void PushRelativeFont(ImFont* font, float bodyRatio)
    {
        ImGui::PushFont(font, NativeFontSize(g_fontRegular) * bodyRatio);
    }

    enum WorkspacePage
    {
        PageOverview = 0,
        PageTargets,
        PageDetection,
        PageFindings,
        PageInventory,
        PageThreatIntel,
        PagePerformance,
        PageCoverage
    };

    struct DriveInfo
    {
        std::filesystem::path root;
        std::string display;
        UINT type = DRIVE_UNKNOWN;
        bool selected = false;
    };

    struct AppState
    {
        IndicatorDatabase database;
        FeedSyncResult feedSync;
        std::vector<DriveInfo> drives;

        std::atomic_bool running{false};
        std::atomic_bool cancelRequested{false};
        std::atomic_bool feedSyncInProgress{false};
        std::thread worker;
        std::mutex dataMutex;

        std::vector<Finding> findings;
        std::vector<PackageRecord> packages;
        std::vector<PackageRecord> packagePreview;
        ScanStats stats;
        std::vector<std::filesystem::path> lastRoots;
        std::wstring currentPath;
        std::wstring status = L"Ready.";
        bool lastCancelled = false;
        bool lastFeedOnly = false;
        bool completionNotificationPending = false;
        std::uint64_t completionCriticalCount = 0;
        std::uint64_t completionHighCount = 0;
        std::uint64_t completionMediumCount = 0;
        std::uint64_t completionCoverageIssues = 0;
        std::size_t feedNames = 0;
        std::size_t feedPairs = 0;
        std::size_t activeHashIndicators = 0;

        std::array<char, 4096> customRoots{};
        std::array<char, 2048> includeTokens{};
        std::array<char, 2048> excludedNames{};
        std::array<char, 512> findingFilter{};
        std::array<char, 512> packageFilter{};

        bool scanNpmPackages = true;
        bool scanNpmLockfiles = true;
        bool scanPythonPackages = true;
        bool scanPythonLockfiles = true;
        bool scanGoDependencies = true;
        bool scanPackageCaches = true;
        bool createPackageInventory = true;
        bool scanKnownArtifacts = true;
        bool scanBehaviorVariants = true;
        bool scanEditorPersistence = true;
        bool deepHashPackageScripts = true;
        bool skipWindowsDirectory = false;
        bool followReparsePoints = false;
        bool refreshFeedsBeforeScan = true;

        int workerChoice = 0;
        int queueChoice = 1;
        int activePage = PageOverview;
        int selectedFinding = -1;
        std::wstring selectedPackageKey;
        bool showCritical = true;
        bool showHigh = true;
        bool showMedium = true;
        bool showLow = true;
        bool showInfo = true;
    } g_app;

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};
        const int length = WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        if (length <= 0)
            return {};
        std::string result(static_cast<std::size_t>(length), '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            result.data(), length, nullptr, nullptr);
        return result;
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty())
            return {};
        const int length = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (length <= 0)
            return {};
        std::wstring result(static_cast<std::size_t>(length), L'\0');
        MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), length);
        return result;
    }

    std::wstring Trim(std::wstring value)
    {
        const auto notSpace = [](wchar_t value)
        {
            return !std::iswspace(value);
        };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }

    std::vector<std::wstring> SplitWide(const std::wstring& value, wchar_t delimiter)
    {
        std::vector<std::wstring> output;
        std::wstringstream stream(value);
        std::wstring item;
        while (std::getline(stream, item, delimiter))
        {
            item = Trim(std::move(item));
            if (!item.empty())
                output.push_back(item);
        }
        return output;
    }

    std::string LowerAscii(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch)
            {
                return static_cast<char>(std::tolower(ch));
            });
        return value;
    }

    bool ContainsInsensitive(const std::string& text, const std::string& filter)
    {
        if (filter.empty())
            return true;
        return LowerAscii(text).find(LowerAscii(filter)) != std::string::npos;
    }

    std::string EllipsizeToWidth(const std::string& text, float maximumWidth)
    {
        if (text.empty() || maximumWidth <= 0.0f ||
            ImGui::CalcTextSize(text.c_str()).x <= maximumWidth)
            return text;

        static constexpr const char* suffix = "...";
        const float suffixWidth = ImGui::CalcTextSize(suffix).x;
        if (suffixWidth >= maximumWidth)
            return suffix;

        std::size_t low = 0;
        std::size_t high = text.size();
        while (low < high)
        {
            const std::size_t middle = (low + high + 1) / 2;
            std::size_t safe = middle;
            while (safe > 0 && safe < text.size() &&
                   (static_cast<unsigned char>(text[safe]) & 0xC0) == 0x80)
                --safe;
            const std::string candidate = text.substr(0, safe) + suffix;
            if (ImGui::CalcTextSize(candidate.c_str()).x <= maximumWidth)
                low = middle;
            else
                high = middle - 1;
        }

        std::size_t safe = low;
        while (safe > 0 && safe < text.size() &&
               (static_cast<unsigned char>(text[safe]) & 0xC0) == 0x80)
            --safe;
        return text.substr(0, safe) + suffix;
    }

    void SetBuffer(std::array<char, 4096>& buffer, const std::string& value)
    {
        std::fill(buffer.begin(), buffer.end(), '\0');
        const std::size_t count = (std::min)(value.size(), buffer.size() - 1);
        std::memcpy(buffer.data(), value.data(), count);
    }

    template <std::size_t N>
    void SetBuffer(std::array<char, N>& buffer, const std::string& value)
    {
        std::fill(buffer.begin(), buffer.end(), '\0');
        const std::size_t count = (std::min)(value.size(), buffer.size() - 1);
        std::memcpy(buffer.data(), value.data(), count);
    }

    std::filesystem::path ExecutableDirectory()
    {
        std::wstring buffer(32768, L'\0');
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        buffer.resize(length);
        return std::filesystem::path(buffer).parent_path();
    }

    const wchar_t* SeverityWide(Severity severity)
    {
        switch (severity)
        {
        case Severity::Critical: return L"CRITICAL";
        case Severity::High: return L"HIGH";
        case Severity::Medium: return L"MEDIUM";
        case Severity::Low: return L"LOW";
        default: return L"INFO";
        }
    }

    const char* SeverityText(Severity severity)
    {
        switch (severity)
        {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        default: return "INFO";
        }
    }

    ImVec4 SeverityColor(Severity severity)
    {
        switch (severity)
        {
        case Severity::Critical: return ImVec4(1.00f, 0.24f, 0.20f, 1.00f);
        case Severity::High: return ImVec4(1.00f, 0.55f, 0.12f, 1.00f);
        case Severity::Medium: return ImVec4(1.00f, 0.78f, 0.20f, 1.00f);
        case Severity::Low: return ImVec4(0.40f, 0.72f, 1.00f, 1.00f);
        default: return ImVec4(0.66f, 0.70f, 0.76f, 1.00f);
        }
    }

    std::string FormatBytes(ULARGE_INTEGER value)
    {
        const double bytes = static_cast<double>(value.QuadPart);
        std::ostringstream stream;
        stream << std::fixed << std::setprecision(1);
        if (bytes >= 1099511627776.0)
            stream << bytes / 1099511627776.0 << " TB";
        else if (bytes >= 1073741824.0)
            stream << bytes / 1073741824.0 << " GB";
        else
            stream << bytes / 1048576.0 << " MB";
        return stream.str();
    }

    struct HashDatabaseLoadSummary
    {
        bool loaded = false;
        std::size_t fileEntries = 0;
        std::size_t addedEntries = 0;
        std::size_t skippedEntries = 0;
        std::wstring message;
    };

    HashDatabaseLoadSummary MergeExternalHashDatabase(IndicatorDatabase& database)
    {
        HashDatabaseLoadSummary summary;
        const std::filesystem::path path =
            ExecutableDirectory() / L"malicious_hashes.json";

        std::error_code ec;
        if (!std::filesystem::exists(path, ec))
        {
            summary.message = L"malicious_hashes.json was not found; built-in hashes remain active.";
            DebugLog::Write("HASH/JSON", summary.message + L" Expected path: " + path.wstring());
            return summary;
        }

        summary.loaded = database.MergeMaliciousHashesJson(
            path, summary.message, &summary.fileEntries,
            &summary.addedEntries, &summary.skippedEntries);
        DebugLog::Write("HASH/JSON", L"Active exact hash count after merge: " +
            std::to_wstring(database.HashIndicatorCount()));
        return summary;
    }

    void RefreshDrives()
    {
        g_app.drives.clear();
        wchar_t roots[4096] = {};
        if (!GetLogicalDriveStringsW(static_cast<DWORD>(std::size(roots)), roots))
            return;

        for (const wchar_t* root = roots; *root; root += std::wcslen(root) + 1)
        {
            const UINT type = GetDriveTypeW(root);
            if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE && type != DRIVE_REMOTE)
                continue;

            wchar_t label[MAX_PATH] = {};
            wchar_t fileSystem[MAX_PATH] = {};
            GetVolumeInformationW(root, label, MAX_PATH, nullptr, nullptr, nullptr,
                fileSystem, MAX_PATH);

            ULARGE_INTEGER freeBytes{};
            ULARGE_INTEGER totalBytes{};
            ULARGE_INTEGER totalFree{};
            const bool haveSpace = GetDiskFreeSpaceExW(
                root, &freeBytes, &totalBytes, &totalFree) != FALSE;

            const wchar_t* typeName = type == DRIVE_FIXED ? L"Fixed" :
                type == DRIVE_REMOVABLE ? L"Removable" : L"Network";

            std::wostringstream display;
            display << root << L"  [" << typeName << L"]";
            if (*label)
                display << L"  " << label;
            if (*fileSystem)
                display << L"  (" << fileSystem << L")";

            std::string utf8 = WideToUtf8(display.str());
            if (haveSpace)
                utf8 += "  " + FormatBytes(totalBytes);

            DriveInfo drive;
            drive.root = root;
            drive.display = std::move(utf8);
            drive.type = type;
            drive.selected = type != DRIVE_REMOTE;
            g_app.drives.push_back(std::move(drive));
        }
    }

    void BrowseForRoot()
    {
        BROWSEINFOW info{};
        info.hwndOwner = GetActiveWindow();
        info.lpszTitle = L"Add a custom Shai-Hulud scan root";
        info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

        PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&info);
        if (!item)
            return;

        wchar_t selected[MAX_PATH] = {};
        if (SHGetPathFromIDListW(item, selected))
        {
            std::string current(g_app.customRoots.data());
            if (!current.empty() && current.back() != ';')
                current.push_back(';');
            current += WideToUtf8(selected);
            SetBuffer(g_app.customRoots, current);
        }
        CoTaskMemFree(item);
    }

    unsigned int SelectedWorkerCount()
    {
        static constexpr unsigned int values[] = {0, 1, 2, 4, 8, 12, 16, 24, 32};
        return values[(std::clamp)(g_app.workerChoice, 0,
            static_cast<int>(std::size(values) - 1))];
    }

    std::size_t SelectedQueueCapacity()
    {
        static constexpr std::size_t values[] = {2048, 8192, 32768, 65536};
        return values[(std::clamp)(g_app.queueChoice, 0,
            static_cast<int>(std::size(values) - 1))];
    }

    unsigned int DisplayWorkerCount()
    {
        const unsigned int selected = SelectedWorkerCount();
        if (selected != 0)
            return selected;
        const unsigned int hardwareThreads =
            (std::max)(2u, std::thread::hardware_concurrency());
        return (std::min)(16u,
            (std::max)(2u, hardwareThreads > 2 ? hardwareThreads - 1 : 2u));
    }

    ScanOptions CollectOptions()
    {
        ScanOptions options;
        std::unordered_set<std::wstring> seen;

        const auto addRoot = [&](const std::filesystem::path& root)
        {
            if (root.empty())
                return;
            const auto normalized = root.lexically_normal();
            std::wstring key = normalized.wstring();
            std::transform(key.begin(), key.end(), key.begin(),
                [](wchar_t ch)
                {
                    return static_cast<wchar_t>(std::towlower(ch));
                });
            if (seen.insert(key).second)
                options.roots.push_back(normalized);
        };

        for (const auto& drive : g_app.drives)
        {
            if (drive.selected)
                addRoot(drive.root);
        }

        for (const auto& root : SplitWide(Utf8ToWide(g_app.customRoots.data()), L';'))
            addRoot(root);

        options.scanNpmPackages = g_app.scanNpmPackages;
        options.scanNpmLockfiles = g_app.scanNpmLockfiles;
        options.scanPythonPackages = g_app.scanPythonPackages;
        options.scanPythonLockfiles = g_app.scanPythonLockfiles;
        options.scanGoDependencies = g_app.scanGoDependencies;
        options.scanPackageCaches = g_app.scanPackageCaches;
        options.createPackageInventory = g_app.createPackageInventory;
        options.scanKnownArtifacts = g_app.scanKnownArtifacts;
        options.scanBehaviorVariants = g_app.scanBehaviorVariants;
        options.scanEditorPersistence = g_app.scanEditorPersistence;
        options.deepHashPackageScripts = g_app.deepHashPackageScripts;
        options.skipWindowsDirectory = g_app.skipWindowsDirectory;
        options.followReparsePoints = g_app.followReparsePoints;
        options.workerThreads = SelectedWorkerCount();
        options.queueCapacity = SelectedQueueCapacity();
        options.includePathTokens = SplitWide(Utf8ToWide(g_app.includeTokens.data()), L';');
        options.excludedDirectoryNames = SplitWide(Utf8ToWide(g_app.excludedNames.data()), L';');
        return options;
    }

    std::wstring Csv(const std::wstring& value)
    {
        std::wstring output = L"\"";
        for (wchar_t ch : value)
        {
            if (ch == L'\"')
                output += L"\"\"";
            else if (ch != L'\r')
                output += ch;
        }
        output += L"\"";
        return output;
    }

    void WriteUtf8(std::ofstream& output, const std::wstring& value)
    {
        const std::string utf8 = WideToUtf8(value);
        output.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    }

    bool SaveReports(const std::filesystem::path& selected, std::wstring& status)
    {
        std::vector<Finding> findings;
        std::vector<PackageRecord> packages;
        FeedSyncResult feeds;
        ScanStats stats;
        std::vector<std::filesystem::path> roots;

        {
            std::lock_guard lock(g_app.dataMutex);
            findings = g_app.findings;
            packages = g_app.packages;
            feeds = g_app.feedSync;
            stats = g_app.stats;
            roots = g_app.lastRoots;
        }

        std::filesystem::path base = selected;
        if (base.extension() == L".csv")
            base.replace_extension();

        const auto findingsPath = std::filesystem::path(base.wstring() + L"-findings.csv");
        const auto packagesPath = std::filesystem::path(base.wstring() + L"-package-inventory.csv");
        const auto summaryPath = std::filesystem::path(base.wstring() + L"-summary.txt");

        std::ofstream findingsFile(findingsPath, std::ios::binary);
        std::ofstream packagesFile(packagesPath, std::ios::binary);
        std::ofstream summaryFile(summaryPath, std::ios::binary);
        if (!findingsFile || !packagesFile || !summaryFile)
        {
            status = L"Could not create all report files.";
            return false;
        }

        findingsFile.write("\xEF\xBB\xBF", 3);
        packagesFile.write("\xEF\xBB\xBF", 3);
        summaryFile.write("\xEF\xBB\xBF", 3);

        WriteUtf8(findingsFile,
            L"Severity,Ecosystem,Type,Indicator,Version,Path,Details\r\n");
        for (const auto& finding : findings)
        {
            WriteUtf8(findingsFile,
                Csv(SeverityWide(finding.severity)) + L"," +
                Csv(finding.ecosystem) + L"," + Csv(finding.type) + L"," +
                Csv(finding.indicator) + L"," + Csv(finding.version) + L"," +
                Csv(finding.path) + L"," + Csv(finding.details) + L"\r\n");
        }

        WriteUtf8(packagesFile,
            L"Ecosystem,Package,Version,Affected,Manifest Path\r\n");
        for (const auto& package : packages)
        {
            WriteUtf8(packagesFile,
                Csv(package.ecosystem) + L"," + Csv(package.name) + L"," +
                Csv(package.version) + L"," +
                Csv(package.affected ? L"Yes" : L"No") + L"," +
                Csv(package.path) + L"\r\n");
        }

        std::wostringstream report;
        report << L"Shai-Hulud 2.0 Scanner " << Utf8ToWide(kVersion) << L"\r\n"
               << L"=======================================\r\n\r\n"
               << L"CRITICAL means only an exact known-malware hash match.\r\n"
               << L"HIGH means strong exposure or compromise evidence, not cryptographic proof.\r\n"
               << L"MEDIUM means possible exposure such as lockfile/cache references or filenames.\r\n\r\n"
               << L"Selected roots:\r\n";
        for (const auto& root : roots)
            report << L"  " << root.wstring() << L"\r\n";

        report << L"\r\nCoverage:\r\n"
               << L"  Directories: " << stats.directoriesVisited << L"\r\n"
               << L"  Files enumerated: " << stats.filesVisited << L"\r\n"
               << L"  Candidate files queued: " << stats.filesQueued << L"\r\n"
               << L"  Worker threads: " << stats.workerThreads << L"\r\n"
               << L"  Peak queue depth: " << stats.peakQueueDepth << L"\r\n"
               << L"  npm manifests: " << stats.npmManifests << L"\r\n"
               << L"  PyPI metadata: " << stats.pythonMetadataFiles << L"\r\n"
               << L"  Package inventory: " << stats.packagesInventoried << L"\r\n"
               << L"  Hashes calculated: " << stats.hashesCalculated << L"\r\n"
               << L"  Findings: " << stats.findings << L"\r\n"
               << L"  Access denied: " << stats.accessDenied << L"\r\n"
               << L"  Errors: " << stats.errors << L"\r\n\r\n"
               << L"Threat feeds:\r\n";

        for (const auto& feed : feeds.feeds)
        {
            report << L"  " << feed.name << L"\r\n"
                   << L"    State: " << feed.state << L"\r\n"
                   << L"    Source: " << feed.source << L"\r\n"
                   << L"    SHA256: " << feed.sha256 << L"\r\n"
                   << L"    URL: " << feed.url << L"\r\n";
        }
        WriteUtf8(summaryFile, report.str());

        status = L"Saved:\r\n" + findingsPath.wstring() + L"\r\n" +
            packagesPath.wstring() + L"\r\n" + summaryPath.wstring();
        return true;
    }

    void ExportReports()
    {
        wchar_t file[MAX_PATH] = L"Shai-Hulud-2-Scan.csv";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = GetActiveWindow();
        dialog.lpstrFilter = L"CSV report base (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
        dialog.lpstrFile = file;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrDefExt = L"csv";
        dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        if (!GetSaveFileNameW(&dialog))
            return;

        std::wstring message;
        const bool ok = SaveReports(file, message);
        MessageBoxW(GetActiveWindow(), message.c_str(),
            ok ? L"Reports exported" : L"Export failed",
            MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
    }

    void JoinCompletedWorker()
    {
        if (!g_app.running.load(std::memory_order_acquire) && g_app.worker.joinable())
            g_app.worker.join();
    }

    void BeginWork(bool feedOnly)
    {
        JoinCompletedWorker();
        if (g_app.running.load(std::memory_order_acquire))
            return;

        ScanOptions options = CollectOptions();
        if (!feedOnly && options.roots.empty())
        {
            MessageBoxW(GetActiveWindow(),
                L"Select at least one detected drive or add a custom root.",
                L"No scan target", MB_OK | MB_ICONWARNING);
            return;
        }

        {
            std::lock_guard lock(g_app.dataMutex);
            g_app.lastFeedOnly = feedOnly;
            g_app.lastCancelled = false;
            g_app.completionNotificationPending = false;
            g_app.completionCriticalCount = 0;
            g_app.completionHighCount = 0;
            g_app.completionMediumCount = 0;
            g_app.completionCoverageIssues = 0;
            g_app.status = feedOnly
                ? L"Conditionally checking all configured threat feeds..."
                : L"Preparing the scan and threat-feed database...";
            g_app.currentPath.clear();
            if (!feedOnly)
            {
                g_app.findings.clear();
                g_app.packages.clear();
                g_app.packagePreview.clear();
                g_app.stats = {};
                g_app.lastRoots = options.roots;
                g_app.selectedFinding = -1;
            }
        }

        g_app.cancelRequested.store(false, std::memory_order_release);
        g_app.feedSyncInProgress.store(true, std::memory_order_release);
        g_app.running.store(true, std::memory_order_release);
        const bool refreshOnline = feedOnly || g_app.refreshFeedsBeforeScan;

        g_app.worker = std::thread([options, refreshOnline, feedOnly]
        {
            try
            {
                FeedSyncResult sync = FeedUpdater::Sync(
                    ExecutableDirectory(), g_app.database, refreshOnline);
                MergeExternalHashDatabase(g_app.database);
                g_app.feedSyncInProgress.store(false, std::memory_order_release);
                {
                    std::lock_guard lock(g_app.dataMutex);
                    g_app.feedSync = sync;
                    g_app.feedNames = g_app.database.PackageCount();
                    g_app.feedPairs = g_app.database.PairCount();
                    g_app.activeHashIndicators = g_app.database.HashIndicatorCount();
                    g_app.status = (sync.anyOnlineFailure || sync.anyValidationFailure)
                        ? sync.healthSummary : sync.summary;
                }

                if (feedOnly)
                {
                    g_app.running.store(false, std::memory_order_release);
                    return;
                }

                Scanner scanner(g_app.database);
                scanner.Run(
                    options,
                    g_app.cancelRequested,
                    [](const Finding& finding)
                    {
                        std::lock_guard lock(g_app.dataMutex);
                        g_app.findings.push_back(finding);
                    },
                    [](const PackageRecord& package)
                    {
                        std::lock_guard lock(g_app.dataMutex);
                        g_app.packages.push_back(package);
                        if (g_app.packagePreview.size() >= 5000)
                            g_app.packagePreview.erase(g_app.packagePreview.begin(),
                                g_app.packagePreview.begin() + 1000);
                        g_app.packagePreview.push_back(package);
                    },
                    [](const ScanStats& stats, const std::wstring& path)
                    {
                        std::lock_guard lock(g_app.dataMutex);
                        g_app.stats = stats;
                        g_app.currentPath = path;
                        g_app.status = L"Scanning selected roots with a bounded worker pool...";
                    },
                    [](const ScanStats& stats, bool cancelled)
                    {
                        std::lock_guard lock(g_app.dataMutex);
                        g_app.stats = stats;
                        g_app.lastCancelled = cancelled;
                        g_app.status = cancelled
                            ? L"Scan cancelled. Partial results are available."
                            : L"Scan complete. Review findings and coverage counts.";

                        if (!cancelled)
                        {
                            const auto countSeverity = [](const std::vector<Finding>& findings, Severity severity)
                            {
                                return static_cast<std::uint64_t>(std::count_if(
                                    findings.begin(), findings.end(),
                                    [severity](const Finding& finding)
                                    {
                                        return finding.severity == severity;
                                    }));
                            };
                            g_app.completionCriticalCount = countSeverity(g_app.findings, Severity::Critical);
                            g_app.completionHighCount = countSeverity(g_app.findings, Severity::High);
                            g_app.completionMediumCount = countSeverity(g_app.findings, Severity::Medium);
                            g_app.completionCoverageIssues = stats.accessDenied + stats.errors;
                                            g_app.completionNotificationPending = true;
                        }
                    });
            }
            catch (const std::exception& error)
            {
                DebugLog::Write("WORKER", std::string("Unhandled std::exception: ") + error.what());
                g_app.feedSyncInProgress.store(false, std::memory_order_release);
                std::lock_guard lock(g_app.dataMutex);
                g_app.status = L"Worker failure: " + Utf8ToWide(error.what());
                ++g_app.stats.errors;
            }
            catch (...)
            {
                DebugLog::Write("WORKER", L"Unhandled unknown exception in feed/scan worker.");
                g_app.feedSyncInProgress.store(false, std::memory_order_release);
                std::lock_guard lock(g_app.dataMutex);
                g_app.status = L"Worker failure: unknown exception.";
                ++g_app.stats.errors;
            }

            g_app.running.store(false, std::memory_order_release);
        });
    }

    void LoadApplicationFonts(ImGuiIO& io)
    {
        g_fontRegular = io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\segoeui.ttf", 17.0f);
        g_fontSemibold = io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\seguisb.ttf", 18.0f);
        g_fontTitle = io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\seguisb.ttf", 28.0f);
        g_fontMono = io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\consola.ttf", 15.0f);

        if (!g_fontRegular)
            g_fontRegular = io.Fonts->AddFontDefault();
        if (!g_fontSemibold)
            g_fontSemibold = g_fontRegular;
        if (!g_fontTitle)
            g_fontTitle = g_fontSemibold;
        if (!g_fontMono)
            g_fontMono = g_fontRegular;
        io.FontDefault = g_fontRegular;
    }

    void ApplyTheme()
    {
        ImGuiStyle& style = ImGui::GetStyle();
        const float em = NativeFontSize(g_fontRegular);
        style.WindowPadding = ImVec2(em * 0.94f, em * 0.82f);
        style.FramePadding = ImVec2(em * 0.59f, em * 0.41f);
        style.CellPadding = ImVec2(em * 0.59f, em * 0.41f);
        style.ItemSpacing = ImVec2(em * 0.53f, em * 0.47f);
        style.ItemInnerSpacing = ImVec2(em * 0.41f, em * 0.35f);
        style.ScrollbarSize = em * 0.59f;
        style.GrabMinSize = em * 0.71f;
        style.WindowRounding = 0.0f;
        style.ChildRounding = em * 0.29f;
        style.FrameRounding = em * 0.24f;
        style.PopupRounding = em * 0.35f;
        style.GrabRounding = em * 0.24f;
        style.TabRounding = em * 0.24f;
        style.WindowBorderSize = 0.0f;
        style.ChildBorderSize = em * 0.059f;
        style.FrameBorderSize = em * 0.059f;
        style.PopupBorderSize = em * 0.059f;
        style.TabBorderSize = em * 0.059f;

        auto& colors = style.Colors;
        colors[ImGuiCol_Text] = ImVec4(0.91f, 0.91f, 0.90f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.49f, 0.49f, 0.47f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.008f, 0.009f, 0.010f, 1.00f);
        colors[ImGuiCol_ChildBg] = ImVec4(0.014f, 0.015f, 0.016f, 0.99f);
        colors[ImGuiCol_PopupBg] = ImVec4(0.018f, 0.018f, 0.019f, 0.99f);
        colors[ImGuiCol_Border] = ImVec4(0.25f, 0.16f, 0.09f, 0.95f);
        colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.045f, 0.042f, 0.039f, 1.00f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.095f, 0.062f, 0.038f, 1.00f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.135f, 0.078f, 0.036f, 1.00f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.008f, 0.009f, 0.010f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.008f, 0.009f, 0.010f, 1.00f);
        colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 0.39f, 0.07f, 1.00f);
        colors[ImGuiCol_SliderGrab] = ImVec4(0.92f, 0.31f, 0.05f, 0.90f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(1.00f, 0.47f, 0.10f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.060f, 0.054f, 0.049f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.145f, 0.078f, 0.034f, 1.00f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.205f, 0.096f, 0.030f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.100f, 0.060f, 0.030f, 1.00f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.165f, 0.083f, 0.028f, 1.00f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.220f, 0.103f, 0.024f, 1.00f);
        colors[ImGuiCol_Separator] = ImVec4(0.24f, 0.15f, 0.08f, 0.90f);
        colors[ImGuiCol_SeparatorHovered] = ImVec4(1.00f, 0.39f, 0.07f, 0.80f);
        colors[ImGuiCol_SeparatorActive] = ImVec4(1.00f, 0.39f, 0.07f, 1.00f);
        colors[ImGuiCol_Tab] = ImVec4(0.045f, 0.040f, 0.036f, 1.00f);
        colors[ImGuiCol_TabHovered] = ImVec4(0.150f, 0.075f, 0.030f, 1.00f);
        colors[ImGuiCol_TabSelected] = ImVec4(0.180f, 0.085f, 0.025f, 1.00f);
        colors[ImGuiCol_TableHeaderBg] = ImVec4(0.075f, 0.052f, 0.035f, 1.00f);
        colors[ImGuiCol_TableBorderStrong] = ImVec4(0.25f, 0.16f, 0.09f, 0.90f);
        colors[ImGuiCol_TableBorderLight] = ImVec4(0.12f, 0.085f, 0.055f, 0.90f);
        colors[ImGuiCol_TableRowBg] = ImVec4(0.016f, 0.016f, 0.017f, 1.00f);
        colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.026f, 0.024f, 0.022f, 1.00f);
        colors[ImGuiCol_ScrollbarBg] = ImVec4(0.010f, 0.010f, 0.011f, 0.90f);
        colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.22f, 0.14f, 0.075f, 0.90f);
        colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.52f, 0.24f, 0.06f, 1.00f);
        colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.88f, 0.34f, 0.05f, 1.00f);
        colors[ImGuiCol_ResizeGrip] = ImVec4(0.95f, 0.34f, 0.05f, 0.20f);
        colors[ImGuiCol_ResizeGripHovered] = ImVec4(1.00f, 0.40f, 0.06f, 0.60f);
        colors[ImGuiCol_ResizeGripActive] = ImVec4(1.00f, 0.40f, 0.06f, 1.00f);
        colors[ImGuiCol_NavHighlight] = ImVec4(1.00f, 0.39f, 0.07f, 1.00f);
        colors[ImGuiCol_PlotHistogram] = ImVec4(1.00f, 0.39f, 0.07f, 1.00f);
        colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.58f, 0.18f, 1.00f);
        colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.76f);
    }

    void DrawBackgroundGrid(const ImVec2& minimum, const ImVec2& maximum)
    {
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImU32 minor = IM_COL32(126, 57, 17, 11);
        const ImU32 major = IM_COL32(181, 75, 13, 18);
        const float spacing = g_layout.viewportMinUnit * 4.7f;
        int index = 0;
        for (float x = minimum.x; x < maximum.x; x += spacing, ++index)
            draw->AddLine(ImVec2(x, minimum.y), ImVec2(x, maximum.y),
                index % 4 == 0 ? major : minor, ImGui::GetStyle().FrameBorderSize);
        index = 0;
        for (float y = minimum.y; y < maximum.y; y += spacing, ++index)
            draw->AddLine(ImVec2(minimum.x, y), ImVec2(maximum.x, y),
                index % 4 == 0 ? major : minor, ImGui::GetStyle().FrameBorderSize);
    }

    void DrawShieldMark(const ImVec2& position, float size, const ImVec4& color)
    {
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImU32 outline = ImGui::ColorConvertFloat4ToU32(color);
        const ImU32 fill = ImGui::ColorConvertFloat4ToU32(
            ImVec4(color.x * 0.25f, color.y * 0.25f, color.z * 0.25f, 0.85f));
        const ImVec2 points[] =
        {
            ImVec2(position.x + size * 0.50f, position.y),
            ImVec2(position.x + size * 0.90f, position.y + size * 0.16f),
            ImVec2(position.x + size * 0.84f, position.y + size * 0.62f),
            ImVec2(position.x + size * 0.50f, position.y + size),
            ImVec2(position.x + size * 0.16f, position.y + size * 0.62f),
            ImVec2(position.x + size * 0.10f, position.y + size * 0.16f)
        };
        const float strokeWidth = (std::max)(ImGui::GetStyle().FrameBorderSize * 2.0f,
            g_layout.scale);
        draw->AddConvexPolyFilled(points, static_cast<int>(std::size(points)), fill);
        draw->AddPolyline(points, static_cast<int>(std::size(points)), outline,
            strokeWidth, ImDrawFlags_Closed);
        draw->AddLine(
            ImVec2(position.x + size * 0.31f, position.y + size * 0.50f),
            ImVec2(position.x + size * 0.45f, position.y + size * 0.65f), outline, strokeWidth);
        draw->AddLine(
            ImVec2(position.x + size * 0.45f, position.y + size * 0.65f),
            ImVec2(position.x + size * 0.72f, position.y + size * 0.34f), outline, strokeWidth);
    }

    enum class IntelligenceHealth
    {
        Current,
        Degraded,
        Unavailable
    };

    bool IsCurrentFeedState(FeedStateKind state)
    {
        return state == FeedStateKind::Current ||
            state == FeedStateKind::Updated ||
            state == FeedStateKind::AdvisoryCurrent;
    }

    IntelligenceHealth GetIntelligenceHealth(const FeedSyncResult& sync)
    {
        bool degraded = false;
        for (const auto& feed : sync.feeds)
        {
            if (feed.kind == FeedStateKind::Unavailable)
                return IntelligenceHealth::Unavailable;
            if (!IsCurrentFeedState(feed.kind))
                degraded = true;
        }
        return degraded ? IntelligenceHealth::Degraded : IntelligenceHealth::Current;
    }

    ImVec4 IntelligenceHealthColor(IntelligenceHealth health)
    {
        switch (health)
        {
        case IntelligenceHealth::Current: return ImVec4(0.24f, 0.82f, 0.49f, 1.00f);
        case IntelligenceHealth::Degraded: return ImVec4(0.96f, 0.79f, 0.18f, 1.00f);
        default: return ImVec4(0.95f, 0.24f, 0.20f, 1.00f);
        }
    }

    ImVec4 CautionColor()
    {
        return ImVec4(0.96f, 0.79f, 0.18f, 1.00f);
    }

    const char* FeedStateText(FeedStateKind state)
    {
        switch (state)
        {
        case FeedStateKind::Updated: return "Updated";
        case FeedStateKind::Current:
        case FeedStateKind::AdvisoryCurrent: return "Already up to date";
        case FeedStateKind::Updating: return "Updating";
        case FeedStateKind::OfflineCached: return "Offline - cached snapshot";
        case FeedStateKind::OfflineBundled: return "Offline - bundled snapshot";
        case FeedStateKind::RejectedCached: return "Feed rejected - cached snapshot";
        case FeedStateKind::RejectedBundled: return "Feed rejected - bundled snapshot";
        case FeedStateKind::EmbeddedFallback: return "Embedded fallback";
        default: return "Unavailable";
        }
    }

    ImVec4 FeedStateColor(FeedStateKind state)
    {
        switch (state)
        {
        case FeedStateKind::Updated:
        case FeedStateKind::Current:
        case FeedStateKind::AdvisoryCurrent:
            return ImVec4(0.24f, 0.82f, 0.49f, 1.00f);
        case FeedStateKind::Updating:
            return ImVec4(1.00f, 0.47f, 0.10f, 1.00f);
        case FeedStateKind::OfflineCached:
        case FeedStateKind::OfflineBundled:
        case FeedStateKind::RejectedCached:
        case FeedStateKind::RejectedBundled:
        case FeedStateKind::EmbeddedFallback:
            return CautionColor();
        default:
            return ImVec4(0.95f, 0.24f, 0.20f, 1.00f);
        }
    }

    std::string AbbreviateHash(const std::wstring& hash)
    {
        const std::string value = WideToUtf8(hash);
        if (value.size() <= 28)
            return value;
        return value.substr(0, 12) + "..." + value.substr(value.size() - 10);
    }

    float StatusPillWidth(const char* label)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        return ImGui::CalcTextSize(label).x + style.FramePadding.x * 3.0f;
    }

    float StatusPillHeight()
    {
        return ImGui::GetTextLineHeight() + ImGui::GetStyle().FramePadding.y * 1.6f;
    }

    void StatusPill(const char* label, const ImVec4& color)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const ImVec2 textSize = ImGui::CalcTextSize(label);
        const ImVec2 position = ImGui::GetCursorScreenPos();
        const ImVec2 size(StatusPillWidth(label), StatusPillHeight());
        const float radius = size.y * 0.5f;
        const float dotRadius = size.y * 0.12f;
        const float dotX = position.x + style.FramePadding.x;
        const float textX = dotX + dotRadius * 2.0f + style.ItemInnerSpacing.x;
        const float textY = position.y + (size.y - textSize.y) * 0.5f;
        ImDrawList* draw = ImGui::GetWindowDrawList();
        draw->AddRectFilled(position, ImVec2(position.x + size.x, position.y + size.y),
            ImGui::ColorConvertFloat4ToU32(ImVec4(color.x * 0.18f, color.y * 0.18f,
                color.z * 0.18f, 0.95f)), radius);
        draw->AddRect(position, ImVec2(position.x + size.x, position.y + size.y),
            ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.55f)),
            radius, 0, (std::max)(ImGui::GetStyle().FrameBorderSize, g_layout.viewportMinUnit * 0.04f));
        draw->AddCircleFilled(ImVec2(dotX + dotRadius, position.y + size.y * 0.5f), dotRadius,
            ImGui::ColorConvertFloat4ToU32(color));
        draw->AddText(ImVec2(textX, textY), ImGui::ColorConvertFloat4ToU32(color), label);
        ImGui::Dummy(size);
    }

    void PageHeader(const char* title, const char* description, const char* eyebrow)
    {
        PushNativeFont(g_fontSemibold);
        ImGui::TextColored(ImVec4(1.00f, 0.39f, 0.07f, 1.00f), "%s", eyebrow);
        ImGui::PopFont();
        PushNativeFont(g_fontTitle);
        ImGui::TextUnformatted(title);
        ImGui::PopFont();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextDisabled("%s", description);
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    void SectionTitle(const char* title, const char* subtitle = nullptr)
    {
        PushNativeFont(g_fontSemibold);
        ImGui::TextColored(ImVec4(0.94f, 0.78f, 0.66f, 1.00f), "%s", title);
        ImGui::PopFont();
        if (subtitle)
        {
            const float subtitleWidth = ImGui::CalcTextSize(subtitle).x;
            if (CanPlaceNextInline(subtitleWidth + ImGui::GetStyle().ItemSpacing.x))
                ImGui::SameLine();
            ImGui::TextDisabled("%s", subtitle);
        }
        ImGui::Separator();
    }

    float MetricCardMinimumWidth(const char* label, const char* caption)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const float valueLine = ImGui::CalcTextSize("000000000").x +
            style.ItemInnerSpacing.x + ImGui::CalcTextSize(caption).x;
        return (std::max)(ImGui::CalcTextSize(label).x, valueLine) +
            style.WindowPadding.x * 2.0f;
    }

    float MetricCardHeight()
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        return style.WindowPadding.y * 2.0f +
            ImGui::GetTextLineHeightWithSpacing() * 2.0f + style.ItemSpacing.y;
    }

    void MetricCard(const char* id, const char* label, std::uint64_t value,
        const char* caption, const ImVec4& color, float width)
    {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.025f, 0.023f, 0.021f, 0.99f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(color.x, color.y, color.z, 0.34f));
        ImGui::BeginChild(id, ImVec2(width, MetricCardHeight()), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        const ImVec2 topLeft = ImGui::GetWindowPos();
        const float stripe = ImGui::GetWindowHeight() * 0.035f;
        ImGui::GetWindowDrawList()->AddRectFilled(
            topLeft, ImVec2(topLeft.x + ImGui::GetWindowWidth(), topLeft.y + stripe),
            ImGui::ColorConvertFloat4ToU32(color));
        ImGui::TextDisabled("%s", label);
        PushNativeFont(g_fontSemibold);
        ImGui::TextColored(color, "%llu", static_cast<unsigned long long>(value));
        ImGui::PopFont();
        ImGui::SameLine();
        ImGui::TextDisabled("%s", caption);
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
    }

    bool SeverityVisible(Severity severity)
    {
        switch (severity)
        {
        case Severity::Critical: return g_app.showCritical;
        case Severity::High: return g_app.showHigh;
        case Severity::Medium: return g_app.showMedium;
        case Severity::Low: return g_app.showLow;
        default: return g_app.showInfo;
        }
    }

    std::string FindingSearchText(const Finding& finding)
    {
        return WideToUtf8(finding.ecosystem + L" " + finding.type + L" " +
            finding.indicator + L" " + finding.version + L" " + finding.path +
            L" " + finding.details);
    }

    void TextCellWithTooltip(const std::string& text)
    {
        ImGui::TextUnformatted(text.c_str());
        if (ImGui::IsItemHovered())
        {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ViewportWidth(0.45f));
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }

    std::vector<std::string> SplitNoticeParagraphs(const char* body)
    {
        std::vector<std::string> paragraphs;
        const std::string text = body ? body : "";
        std::size_t start = 0;
        while (start <= text.size())
        {
            const std::size_t separator = text.find("\n\n", start);
            if (separator == std::string::npos)
            {
                paragraphs.emplace_back(text.substr(start));
                break;
            }
            paragraphs.emplace_back(text.substr(start, separator - start));
            start = separator + 2;
        }
        if (paragraphs.empty())
            paragraphs.emplace_back();
        return paragraphs;
    }

    ImVec2 NoticeBoxPadding()
    {
        // The scan-verdict body temporarily sets WindowPadding to zero.  Never
        // derive this inset from WindowPadding or the measured notice height and
        // the rendered notice height will disagree, leaving a large empty strip
        // above the metrics separator.  FramePadding is unchanged in both paths.
        const ImGuiStyle& style = ImGui::GetStyle();
        return ImVec2(style.FramePadding.x * 2.0f,
            style.FramePadding.y * 1.75f);
    }

    float CalculateNoticeBoxHeight(const char* heading, const char* body, float availableWidth)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const ImVec2 noticePadding = NoticeBoxPadding();
        const float horizontalPadding = noticePadding.x;
        const float verticalPadding = noticePadding.y;
        const float border = style.ChildBorderSize;
        const float contentWidth = (std::max)(availableWidth -
            horizontalPadding * 2.0f - border * 2.0f, ImGui::GetFontSize());

        PushNativeFont(g_fontSemibold);
        const float headingHeight = ImGui::CalcTextSize(
            heading ? heading : "", nullptr, false, contentWidth).y;
        ImGui::PopFont();

        const std::vector<std::string> paragraphs = SplitNoticeParagraphs(body);
        float bodyHeight = 0.0f;
        for (const std::string& paragraph : paragraphs)
        {
            bodyHeight += ImGui::CalcTextSize(paragraph.c_str(), nullptr,
                false, contentWidth).y;
        }

        // TextWrapped already advances by ItemSpacing.y between consecutive
        // items.  The heading plus N paragraphs therefore contains exactly N
        // inter-item gaps.  Do not add Dummy spacing in the renderer as that
        // advances by its own height plus another ItemSpacing.y and causes the
        // final paragraph to be clipped by the child border.
        const float interItemGaps = style.ItemSpacing.y *
            static_cast<float>(paragraphs.size());
        const float measured = border * 2.0f + verticalPadding * 2.0f +
            headingHeight + bodyHeight + interItemGaps;

        // Keep fractional DPI measurements from rounding the child one pixel
        // shorter than its final text layout.
        return std::ceil(measured) + (std::max)(border, 1.0f);
    }

    void NoticeBox(const char* id, const char* heading, const char* body,
        const ImVec4& accent)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const ImVec2 noticePadding = NoticeBoxPadding();
        const std::vector<std::string> paragraphs = SplitNoticeParagraphs(body);
        const float availableWidth = ImGui::GetContentRegionAvail().x;
        const float measuredHeight = CalculateNoticeBoxHeight(
            heading, body, availableWidth);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, noticePadding);
        ImGui::PushStyleColor(ImGuiCol_ChildBg,
            ImVec4(accent.x * 0.045f, accent.y * 0.042f, accent.z * 0.018f, 0.98f));
        ImGui::PushStyleColor(ImGuiCol_Border,
            ImVec4(accent.x, accent.y, accent.z, 0.72f));

        // Use the same explicit inset, width, and paragraph measurements for
        // layout and drawing.  This keeps the text clear of the border and keeps
        // the box bottom close to the metrics separator without a blank strip.
        ImGui::BeginChild(id, ImVec2(0.0f, measuredHeight),
            ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        PushNativeFont(g_fontSemibold);
        ImGui::PushStyleColor(ImGuiCol_Text, accent);
        ImGui::TextWrapped("%s", heading ? heading : "");
        ImGui::PopStyleColor();
        ImGui::PopFont();

        // Consecutive ImGui text items already receive ItemSpacing.y.  Extra
        // Dummy items doubled that gap and made the measured child too short,
        // which clipped the last caution paragraph at some window sizes.
        for (const std::string& paragraph : paragraphs)
            ImGui::TextWrapped("%s", paragraph.c_str());

        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();
    }

    void AuditRow(const char* label, std::uint64_t value)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const float rowHeight = ImGui::GetTextLineHeightWithSpacing() + style.CellPadding.y * 2.0f;
        ImGui::TableNextRow(ImGuiTableRowFlags_None, rowHeight);
        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(label);
        ImGui::TableSetColumnIndex(1);
        const std::string number = std::to_string(value);
        PushNativeFont(g_fontMono);
        const float numberWidth = ImGui::CalcTextSize(number.c_str()).x;
        const float rightEdge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
        ImGui::SetCursorPosX((std::max)(ImGui::GetCursorPosX(), rightEdge - numberWidth));
        ImGui::TextColored(ImVec4(0.94f, 0.55f, 0.20f, 1.00f), "%s", number.c_str());
        ImGui::PopFont();
    }

    void RenderFindings(std::vector<Finding> findings)
    {
        const float filterWidth = ImGui::GetContentRegionAvail().x * 0.38f;
        ImGui::SetNextItemWidth(filterWidth);
        ImGui::InputTextWithHint("##finding_filter", "Filter indicator, path, package, type...",
            g_app.findingFilter.data(), g_app.findingFilter.size());
        const std::pair<const char*, bool*> severityFilters[] = {
            {"Critical", &g_app.showCritical}, {"High", &g_app.showHigh},
            {"Medium", &g_app.showMedium}, {"Low", &g_app.showLow}, {"Info", &g_app.showInfo}
        };
        for (const auto& [label, value] : severityFilters)
        {
            FlowSameLine(ImGui::CalcTextSize(label).x + ImGui::GetFrameHeight() +
                ImGui::GetStyle().ItemInnerSpacing.x);
            ImGui::Checkbox(label, value);
        }

        const std::string filter = g_app.findingFilter.data();
        findings.erase(std::remove_if(findings.begin(), findings.end(),
            [&](const Finding& finding)
            {
                return !SeverityVisible(finding.severity) ||
                    !ContainsInsensitive(FindingSearchText(finding), filter);
            }), findings.end());

        float detailHeight = 0.0f;
        if (g_app.selectedFinding >= 0 &&
            g_app.selectedFinding < static_cast<int>(findings.size()))
        {
            const Finding& selected = findings[static_cast<std::size_t>(g_app.selectedFinding)];
            const float wrappedWidth = ImGui::GetContentRegionAvail().x -
                ImGui::GetStyle().WindowPadding.x * 2.0f;
            detailHeight = ImGui::GetStyle().WindowPadding.y * 2.0f +
                ImGui::GetTextLineHeightWithSpacing() * 2.0f +
                ImGui::CalcTextSize(WideToUtf8(selected.details).c_str(), nullptr, false, wrappedWidth).y +
                ImGui::CalcTextSize(WideToUtf8(selected.path).c_str(), nullptr, false, wrappedWidth).y;
        }

        const ImGuiTableFlags flags =
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
            ImGuiTableFlags_Hideable | ImGuiTableFlags_ScrollX |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable |
            ImGuiTableFlags_SortMulti;

        const float tableHeight = ImGui::GetContentRegionAvail().y -
            (detailHeight > 0.0f ? detailHeight + ImGui::GetStyle().ItemSpacing.y : 0.0f);
        if (ImGui::BeginTable("findings_table", 6, flags, ImVec2(0.0f, tableHeight)))
        {
            ImGui::TableSetupScrollFreeze(1, 1);
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.10f, 0);
            ImGui::TableSetupColumn("Ecosystem", ImGuiTableColumnFlags_WidthStretch, 0.10f, 1);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.17f, 2);
            ImGui::TableSetupColumn("Indicator", ImGuiTableColumnFlags_WidthStretch, 0.22f, 3);
            ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthStretch, 0.11f, 4);
            ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 0.30f, 5);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs();
                sortSpecs && sortSpecs->SpecsCount > 0)
            {
                std::stable_sort(findings.begin(), findings.end(),
                    [sortSpecs](const Finding& left, const Finding& right)
                    {
                        for (int index = 0; index < sortSpecs->SpecsCount; ++index)
                        {
                            const ImGuiTableColumnSortSpecs& spec = sortSpecs->Specs[index];
                            int comparison = 0;
                            switch (spec.ColumnUserID)
                            {
                            case 0: comparison = static_cast<int>(left.severity) - static_cast<int>(right.severity); break;
                            case 1: comparison = left.ecosystem.compare(right.ecosystem); break;
                            case 2: comparison = left.type.compare(right.type); break;
                            case 3: comparison = left.indicator.compare(right.indicator); break;
                            case 4: comparison = left.version.compare(right.version); break;
                            case 5: comparison = left.path.compare(right.path); break;
                            default: break;
                            }
                            if (comparison != 0)
                                return spec.SortDirection == ImGuiSortDirection_Ascending
                                    ? comparison < 0 : comparison > 0;
                        }
                        return false;
                    });
            }

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(findings.size()));
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    const Finding& finding = findings[static_cast<std::size_t>(row)];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(row);
                    const bool selected = g_app.selectedFinding == row;
                    if (ImGui::Selectable("##row", selected,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap))
                        g_app.selectedFinding = row;
                    ImGui::SameLine();
                    ImGui::TextColored(SeverityColor(finding.severity), "%s", SeverityText(finding.severity));
                    if (ImGui::BeginPopupContextItem("finding_context"))
                    {
                        if (ImGui::MenuItem("Copy path"))
                            ImGui::SetClipboardText(WideToUtf8(finding.path).c_str());
                        if (ImGui::MenuItem("Open containing folder"))
                        {
                            const std::wstring arguments = L"/select,\"" + finding.path + L"\"";
                            ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
                        }
                        ImGui::EndPopup();
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(WideToUtf8(finding.ecosystem).c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(WideToUtf8(finding.type).c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(WideToUtf8(finding.indicator).c_str());
                    ImGui::TableSetColumnIndex(4);
                    ImGui::TextUnformatted(WideToUtf8(finding.version).c_str());
                    ImGui::TableSetColumnIndex(5);
                    ImGui::TextUnformatted(WideToUtf8(finding.path).c_str());
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        if (detailHeight > 0.0f && g_app.selectedFinding >= 0 &&
            g_app.selectedFinding < static_cast<int>(findings.size()))
        {
            const Finding& selected = findings[static_cast<std::size_t>(g_app.selectedFinding)];
            ImGui::BeginChild("finding_details", ImVec2(0.0f, detailHeight), ImGuiChildFlags_Borders,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::TextColored(SeverityColor(selected.severity), "%s", SeverityText(selected.severity));
            ImGui::SameLine();
            ImGui::Text("%s", WideToUtf8(selected.type).c_str());
            ImGui::TextWrapped("%s", WideToUtf8(selected.details).c_str());
            ImGui::TextDisabled("%s", WideToUtf8(selected.path).c_str());
            ImGui::EndChild();
        }
    }

    void RenderInventory(const std::vector<PackageRecord>& packages, bool running)
    {
        const float filterWidth = ImGui::GetContentRegionAvail().x * 0.42f;
        ImGui::SetNextItemWidth(filterWidth);
        ImGui::InputTextWithHint("##package_filter", "Filter package, version, ecosystem, or path...",
            g_app.packageFilter.data(), g_app.packageFilter.size());
        const char* helper = running
            ? "Live view is limited to 5,000 records. Export contains the complete inventory."
            : "Select a row for the full path. Click a column heading to sort.";
        FlowSameLine(ImGui::CalcTextSize(helper).x);
        ImGui::TextDisabled("%s", helper);

        std::vector<PackageRecord> filtered;
        filtered.reserve(packages.size());
        const std::string filter = g_app.packageFilter.data();
        for (const auto& package : packages)
        {
            const std::string search = WideToUtf8(package.ecosystem + L" " + package.name +
                L" " + package.version + L" " + package.path);
            if (ContainsInsensitive(search, filter))
                filtered.push_back(package);
        }

        const auto packageKey = [](const PackageRecord& package)
        {
            return package.ecosystem + L"\n" + package.name + L"\n" +
                package.version + L"\n" + package.path;
        };

        PackageRecord selectedRecordStorage;
        const PackageRecord* selectedRecord = nullptr;
        if (!g_app.selectedPackageKey.empty())
        {
            const auto found = std::find_if(filtered.begin(), filtered.end(),
                [&](const PackageRecord& package) { return packageKey(package) == g_app.selectedPackageKey; });
            if (found != filtered.end())
            {
                selectedRecordStorage = *found;
                selectedRecord = &selectedRecordStorage;
            }
            else
            {
                g_app.selectedPackageKey.clear();
            }
        }

        float detailHeight = 0.0f;
        bool detailSideBySide = false;
        if (selectedRecord)
        {
            const float available = ImGui::GetContentRegionAvail().x;
            const float actionMinimum = (std::max)({TextWidth("COPY PACKAGE@VERSION"),
                TextWidth("OPEN LOCATION"), TextWidth("COPY FULL PATH")}) +
                ImGui::GetStyle().FramePadding.x * 2.0f;
            const float detailsMinimum = TextWidth("Manifest / metadata path") +
                ImGui::GetStyle().WindowPadding.x * 2.0f;
            detailSideBySide = available >= actionMinimum + detailsMinimum +
                ImGui::GetStyle().ItemSpacing.x;
            const float pathWidth = detailSideBySide ? available * 0.72f : available;
            const float pathHeight = ImGui::CalcTextSize(WideToUtf8(selectedRecord->path).c_str(),
                nullptr, false, pathWidth).y;
            const float detailTextHeight = ImGui::GetTextLineHeightWithSpacing() * 3.0f + pathHeight +
                ImGui::GetStyle().WindowPadding.y * 2.0f;
            const float actionHeight = ImGui::GetFrameHeight() * 3.0f +
                ImGui::GetStyle().ItemSpacing.y * 2.0f + ImGui::GetStyle().WindowPadding.y * 2.0f;
            detailHeight = detailSideBySide ? (std::max)(detailTextHeight, actionHeight) :
                detailTextHeight + actionHeight;
        }

        const ImGuiTableFlags flags =
            ImGuiTableFlags_BordersInner | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
            ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable |
            ImGuiTableFlags_SortMulti | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_ScrollX | ImGuiTableFlags_SizingStretchProp;
        const float tableHeight = ImGui::GetContentRegionAvail().y -
            (detailHeight > 0.0f ? detailHeight + ImGui::GetStyle().ItemSpacing.y : 0.0f);
        if (ImGui::BeginTable("inventory_table", 5, flags, ImVec2(0.0f, tableHeight)))
        {
            ImGui::TableSetupScrollFreeze(1, 1);
            ImGui::TableSetupColumn("Ecosystem", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_DefaultSort, 0.12f, 0);
            ImGui::TableSetupColumn("Package", ImGuiTableColumnFlags_WidthStretch, 0.24f, 1);
            ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthStretch, 0.14f, 2);
            ImGui::TableSetupColumn("Affected", ImGuiTableColumnFlags_WidthStretch, 0.10f, 3);
            ImGui::TableSetupColumn("Manifest / metadata path", ImGuiTableColumnFlags_WidthStretch, 0.40f, 4);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsCount > 0)
            {
                const auto lower = [](std::wstring value)
                {
                    std::transform(value.begin(), value.end(), value.begin(),
                        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
                    return value;
                };
                std::stable_sort(filtered.begin(), filtered.end(),
                    [&](const PackageRecord& left, const PackageRecord& right)
                    {
                        for (int index = 0; index < specs->SpecsCount; ++index)
                        {
                            const ImGuiTableColumnSortSpecs& spec = specs->Specs[index];
                            int comparison = 0;
                            switch (spec.ColumnUserID)
                            {
                            case 0: comparison = lower(left.ecosystem).compare(lower(right.ecosystem)); break;
                            case 1: comparison = lower(left.name).compare(lower(right.name)); break;
                            case 2: comparison = lower(left.version).compare(lower(right.version)); break;
                            case 3: comparison = left.affected == right.affected ? 0 : (left.affected ? 1 : -1); break;
                            case 4: comparison = lower(left.path).compare(lower(right.path)); break;
                            default: break;
                            }
                            if (comparison != 0)
                                return spec.SortDirection == ImGuiSortDirection_Ascending ? comparison < 0 : comparison > 0;
                        }
                        return false;
                    });
                specs->SpecsDirty = false;
            }

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(filtered.size()));
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    const auto& package = filtered[static_cast<std::size_t>(row)];
                    const std::wstring key = packageKey(package);
                    ImGui::PushID(row);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    const bool selected = g_app.selectedPackageKey == key;
                    if (ImGui::Selectable("##package_row", selected,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                            ImGuiSelectableFlags_AllowDoubleClick))
                    {
                        g_app.selectedPackageKey = key;
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        {
                            const std::wstring arguments = L"/select,\"" + package.path + L"\"";
                            ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
                        }
                    }
                    if (ImGui::BeginPopupContextItem("package_context"))
                    {
                        if (ImGui::MenuItem("Copy full path"))
                            ImGui::SetClipboardText(WideToUtf8(package.path).c_str());
                        if (ImGui::MenuItem("Copy package@version"))
                            ImGui::SetClipboardText(WideToUtf8(package.name + L"@" + package.version).c_str());
                        if (ImGui::MenuItem("Open containing folder"))
                        {
                            const std::wstring arguments = L"/select,\"" + package.path + L"\"";
                            ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
                        }
                        ImGui::EndPopup();
                    }
                    ImGui::SameLine();
                    TextCellWithTooltip(WideToUtf8(package.ecosystem));
                    ImGui::TableSetColumnIndex(1);
                    TextCellWithTooltip(WideToUtf8(package.name));
                    ImGui::TableSetColumnIndex(2);
                    TextCellWithTooltip(WideToUtf8(package.version));
                    ImGui::TableSetColumnIndex(3);
                    if (package.affected)
                        ImGui::TextColored(SeverityColor(Severity::High), "YES");
                    else
                        ImGui::TextDisabled("No");
                    ImGui::TableSetColumnIndex(4);
                    TextCellWithTooltip(WideToUtf8(package.path));
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        if (selectedRecord && detailHeight > 0.0f)
        {
            ImGui::BeginChild("package_details", ImVec2(0.0f, detailHeight), ImGuiChildFlags_Borders,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            const int columns = detailSideBySide ? 2 : 1;
            if (ImGui::BeginTable("package_detail_layout", columns,
                    ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoPadOuterX))
            {
                ImGui::TableSetupColumn("details", ImGuiTableColumnFlags_WidthStretch,
                    detailSideBySide ? 0.72f : 1.0f);
                if (detailSideBySide)
                    ImGui::TableSetupColumn("actions", ImGuiTableColumnFlags_WidthStretch, 0.28f);
                ImGui::TableNextColumn();
                PushNativeFont(g_fontSemibold);
                ImGui::TextColored(selectedRecord->affected ? SeverityColor(Severity::High) : ImVec4(0.91f, 0.91f, 0.90f, 1.0f),
                    "%s@%s", WideToUtf8(selectedRecord->name).c_str(), WideToUtf8(selectedRecord->version).c_str());
                ImGui::PopFont();
                ImGui::TextDisabled("%s  /  %s", WideToUtf8(selectedRecord->ecosystem).c_str(),
                    selectedRecord->affected ? "affected release" : "not in current affected list");
                ImGui::Spacing();
                ImGui::TextDisabled("Manifest / metadata path");
                PushNativeFont(g_fontMono);
                ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
                ImGui::TextUnformatted(WideToUtf8(selectedRecord->path).c_str());
                ImGui::PopTextWrapPos();
                ImGui::PopFont();

                ImGui::TableNextColumn();
                if (ImGui::Button("COPY FULL PATH", ImVec2(-1.0f, 0.0f)))
                    ImGui::SetClipboardText(WideToUtf8(selectedRecord->path).c_str());
                if (ImGui::Button("OPEN LOCATION", ImVec2(-1.0f, 0.0f)))
                {
                    const std::wstring arguments = L"/select,\"" + selectedRecord->path + L"\"";
                    ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
                }
                if (ImGui::Button("COPY PACKAGE@VERSION", ImVec2(-1.0f, 0.0f)))
                    ImGui::SetClipboardText(WideToUtf8(selectedRecord->name + L"@" + selectedRecord->version).c_str());
                ImGui::EndTable();
            }
            ImGui::EndChild();
        }
    }

    void RenderFeeds(const FeedSyncResult& sync, std::size_t names, std::size_t pairs)
    {
        std::size_t currentCount = 0;
        std::size_t fallbackCount = 0;
        for (const auto& feed : sync.feeds)
        {
            if (IsCurrentFeedState(feed.kind))
                ++currentCount;
            else
                ++fallbackCount;
        }

        ImGui::Text("Merged intelligence: %llu package names / %llu exact versions / %llu sources",
            static_cast<unsigned long long>(names),
            static_cast<unsigned long long>(pairs),
            static_cast<unsigned long long>(sync.feeds.size()));
        ImGui::TextColored(fallbackCount ? CautionColor() : ImVec4(0.24f, 0.82f, 0.49f, 1.0f),
            "%llu current  |  %llu using fallback",
            static_cast<unsigned long long>(currentCount),
            static_cast<unsigned long long>(fallbackCount));
        ImGui::SameLine();
        ImGui::TextDisabled("Select a row for the active file and complete update record.");
        ImGui::Spacing();

        static int selectedFeed = -1;
        const bool updating = g_app.feedSyncInProgress.load(std::memory_order_acquire);
        const ImGuiTableFlags flags = ImGuiTableFlags_BordersInner |
            ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp;

        if (ImGui::BeginTable("feed_table", 3, flags))
        {
            ImGui::TableSetupColumn("Feed", ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthStretch, 0.38f);
            ImGui::TableSetupColumn("SHA-256", ImGuiTableColumnFlags_WidthStretch, 0.32f);
            ImGui::TableHeadersRow();

            for (std::size_t index = 0; index < sync.feeds.size(); ++index)
            {
                const FeedStatus& feed = sync.feeds[index];
                const FeedStateKind displayedKind = updating ? FeedStateKind::Updating : feed.kind;
                std::string state;
                if (updating)
                {
                    state = "Updating";
                }
                else if (IsCurrentFeedState(feed.kind))
                {
                    state = std::string(FeedStateText(feed.kind)) + " - " +
                        std::to_string(feed.loadedRows) + " rows / " +
                        std::to_string(feed.loadedPairs) + " pairs";
                }
                else
                {
                    state = FeedStateText(feed.kind);
                }

                ImGui::PushID(static_cast<int>(index));
                ImGui::TableNextRow(ImGuiTableRowFlags_None, ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().CellPadding.y * 2.0f);
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(WideToUtf8(feed.name).c_str(), false,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowOverlap,
                        ImVec2(0.0f, ImGui::GetFrameHeight())))
                {
                    selectedFeed = static_cast<int>(index);
                    ImGui::OpenPopup("Threat feed details");
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(FeedStateColor(displayedKind), "%s", state.c_str());
                if (ImGui::IsItemHovered())
                {
                    ImGui::BeginTooltip();
                    ImGui::PushTextWrapPos(ViewportWidth(0.45f));
                    ImGui::TextUnformatted(WideToUtf8(feed.detail).c_str());
                    ImGui::PopTextWrapPos();
                    ImGui::EndTooltip();
                }
                ImGui::TableSetColumnIndex(2);
                PushNativeFont(g_fontMono);
                const std::string abbreviated = AbbreviateHash(feed.sha256);
                ImGui::TextUnformatted(abbreviated.c_str());
                ImGui::PopFont();
                if (ImGui::IsItemHovered())
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted(WideToUtf8(feed.sha256).c_str());
                    ImGui::EndTooltip();
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                    ImGui::SetClipboardText(WideToUtf8(feed.sha256).c_str());
                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        ImGui::SetNextWindowSize(ImVec2(g_layout.displaySize.x * 0.86f,
            g_layout.displaySize.y * 0.86f), ImGuiCond_Appearing);
        if (ImGui::BeginPopupModal("Threat feed details", nullptr,
                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse))
        {
            if (selectedFeed >= 0 && selectedFeed < static_cast<int>(sync.feeds.size()))
            {
                const FeedStatus& feed = sync.feeds[static_cast<std::size_t>(selectedFeed)];
                PushNativeFont(g_fontTitle);
                ImGui::TextColored(ImVec4(1.00f, 0.39f, 0.07f, 1.00f), "%s",
                    WideToUtf8(feed.name).c_str());
                ImGui::PopFont();
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::BeginChild("feed_detail_body", ImVec2(0.0f,
                        ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeight() - ImGui::GetStyle().ItemSpacing.y),
                    ImGuiChildFlags_None, ImGuiWindowFlags_None);

                const std::filesystem::path source(feed.source);
                const auto detailRow = [](const char* label, const std::string& value, bool mono = false)
                {
                    ImGui::TextDisabled("%s", label);
                    if (mono) PushNativeFont(g_fontMono);
                    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
                    ImGui::TextUnformatted(value.c_str());
                    ImGui::PopTextWrapPos();
                    if (mono) ImGui::PopFont();
                    ImGui::Spacing();
                };

                detailRow("Status", feed.state.empty() ? FeedStateText(feed.kind) : WideToUtf8(feed.state));
                detailRow("Active file", source.empty() ? "Embedded source-specific indicators" : WideToUtf8(source.filename().wstring()), true);
                detailRow("Full path", feed.source.empty() ? "No file is active." : WideToUtf8(feed.source), true);
                detailRow("Provider URL", WideToUtf8(feed.url), true);
                detailRow("SHA-256", WideToUtf8(feed.sha256), true);

                ImGui::TextDisabled("Loaded rows / source pairs / unique merged contribution");
                ImGui::Text("%llu / %llu / +%llu",
                    static_cast<unsigned long long>(feed.loadedRows),
                    static_cast<unsigned long long>(feed.loadedPairs),
                    static_cast<unsigned long long>(feed.addedPairs));
                ImGui::Spacing();
                NoticeBox("feed_update_record", "Update record",
                    WideToUtf8(feed.detail).c_str(), FeedStateColor(feed.kind));
                ImGui::EndChild();
                ImGui::Separator();

                const float feedActionMinimum = (std::max)({TextWidth("COPY PATH"),
                    TextWidth("COPY SHA-256"), TextWidth("CLOSE")}) +
                    ImGui::GetStyle().FramePadding.x * 2.0f;
                const int feedActionColumns = FittedColumnCount(
                    ImGui::GetContentRegionAvail().x, feedActionMinimum, 3);
                const float feedActionWidth = ColumnWidth(ImGui::GetContentRegionAvail().x,
                    feedActionColumns);
                if (ImGui::Button("COPY PATH", ImVec2(feedActionWidth, 0.0f)) && !feed.source.empty())
                    ImGui::SetClipboardText(WideToUtf8(feed.source).c_str());
                if (feedActionColumns > 1) ImGui::SameLine();
                if (ImGui::Button("COPY SHA-256", ImVec2(feedActionWidth, 0.0f)))
                    ImGui::SetClipboardText(WideToUtf8(feed.sha256).c_str());
                if (feedActionColumns > 2) ImGui::SameLine();
                if (ImGui::Button("CLOSE", ImVec2(feedActionWidth, 0.0f)))
                    ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    std::uint64_t CountFindings(const std::vector<Finding>& findings, Severity severity)
    {
        return static_cast<std::uint64_t>(std::count_if(
            findings.begin(), findings.end(),
            [severity](const Finding& finding)
            {
                return finding.severity == severity;
            }));
    }

    std::size_t SelectedRootCount()
    {
        std::size_t count = static_cast<std::size_t>(std::count_if(
            g_app.drives.begin(), g_app.drives.end(),
            [](const DriveInfo& drive)
            {
                return drive.selected;
            }));
        count += SplitWide(Utf8ToWide(g_app.customRoots.data()), L';').size();
        return count;
    }

    float NavigationWidth()
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const char* labels[] = {
            "Overview", "Scan targets", "Detection policy", "Findings",
            "Package inventory", "Threat intelligence", "Scan performance",
            "Coverage & audit"
        };
        float longest = 0.0f;
        for (const char* label : labels)
            longest = (std::max)(longest, ImGui::CalcTextSize(label).x);

        // NavigationItem places the code after one FramePadding.x, then the
        // label after two ItemInnerSpacing.x gaps.  Reserve the matching right
        // frame padding as well as the child padding/border so the longest label
        // is never clipped ("Coverage & audit" was losing its final character).
        const float rowContentWidth = style.FramePadding.x +
            ImGui::CalcTextSize("00").x + style.ItemInnerSpacing.x * 2.0f +
            longest + style.FramePadding.x;
        const float desired = std::ceil(rowContentWidth +
            style.WindowPadding.x * 2.0f + style.ChildBorderSize * 2.0f);
        return (std::min)(desired, g_layout.displaySize.x * 0.30f);
    }

    bool NavigationItem(const char* id, const char* label, const char* code, int page)
    {
        ImGui::PushID(id);
        const bool selected = g_app.activePage == page;
        const ImGuiStyle& style = ImGui::GetStyle();
        const ImVec2 position = ImGui::GetCursorScreenPos();
        const ImVec2 size(ImGui::GetContentRegionAvail().x,
            ImGui::GetTextLineHeight() + style.FramePadding.y * 2.0f);
        ImGui::InvisibleButton("##nav", size);
        const bool clicked = ImGui::IsItemClicked();
        const bool hovered = ImGui::IsItemHovered();
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImVec2 maximum(position.x + size.x, position.y + size.y);
        const float rounding = size.y * 0.10f;
        const float outlineWidth = (std::max)(ImGui::GetStyle().FrameBorderSize,
            g_layout.viewportMinUnit * 0.04f);
        // Keep the live, style-derived safety inset on the vertical axis only.
        // The selected row is drawn with filled
        // rectangles rather than an outside stroke, so its horizontal edges can
        // safely use the full content width and align exactly with the section
        // separators above and below it.
        const float edgeInset = (std::max)(outlineWidth,
            (std::min)(style.ItemSpacing.x, style.ItemSpacing.y) * 0.20f);
        const ImVec2 visualMinimum(position.x, position.y + edgeInset);
        const ImVec2 visualMaximum(maximum.x, maximum.y - edgeInset);
        const auto drawInsideBorder = [&](ImU32 fillColor, ImU32 borderColor)
        {
            if (visualMaximum.x <= visualMinimum.x ||
                visualMaximum.y <= visualMinimum.y)
                return;
            draw->AddRectFilled(visualMinimum, visualMaximum, borderColor, rounding);
            const float borderInset = (std::min)(outlineWidth,
                (std::min)(visualMaximum.x - visualMinimum.x,
                    visualMaximum.y - visualMinimum.y) * 0.25f);
            const ImVec2 innerMinimum(visualMinimum.x + borderInset,
                visualMinimum.y + borderInset);
            const ImVec2 innerMaximum(visualMaximum.x - borderInset,
                visualMaximum.y - borderInset);
            if (innerMaximum.x > innerMinimum.x && innerMaximum.y > innerMinimum.y)
            {
                draw->AddRectFilled(innerMinimum, innerMaximum, fillColor,
                    (std::max)(0.0f, rounding - borderInset));
            }
        };

        if (selected)
        {
            drawInsideBorder(IM_COL32(42, 20, 8, 242), IM_COL32(255, 102, 18, 230));
        }
        else if (hovered)
        {
            drawInsideBorder(IM_COL32(28, 19, 13, 220), IM_COL32(122, 65, 24, 180));
        }

        const float codeX = position.x + style.FramePadding.x;
        const float textY = position.y + (size.y - ImGui::GetTextLineHeight()) * 0.5f;
        const float labelX = codeX + ImGui::CalcTextSize("00").x + style.ItemInnerSpacing.x * 2.0f;
        draw->AddText(ImVec2(codeX, textY),
            selected ? IM_COL32(255, 123, 38, 255) : IM_COL32(124, 104, 88, 255), code);
        draw->AddText(ImVec2(labelX, textY),
            selected ? IM_COL32(248, 242, 236, 255) : IM_COL32(180, 175, 169, 255), label);

        if (clicked)
            g_app.activePage = page;
        ImGui::PopID();
        return clicked;
    }

    void RenderNavigation(bool running, std::size_t feedNames, std::size_t feedPairs,
        const ScanStats& stats)
    {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.011f, 0.012f, 0.013f, 0.99f));
        ImGui::BeginChild("security_navigation", ImVec2(NavigationWidth(), 0.0f), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        ImGui::TextDisabled("SECURITY OPERATIONS");
        ImGui::Spacing();
        NavigationItem("nav_overview", "Overview", "01", PageOverview);
        NavigationItem("nav_targets", "Scan targets", "02", PageTargets);
        NavigationItem("nav_detection", "Detection policy", "03", PageDetection);
        NavigationItem("nav_findings", "Findings", "04", PageFindings);
        NavigationItem("nav_inventory", "Package inventory", "05", PageInventory);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextDisabled("INTELLIGENCE & HEALTH");
        ImGui::Spacing();
        NavigationItem("nav_feeds", "Threat intelligence", "06", PageThreatIntel);
        NavigationItem("nav_performance", "Scan performance", "07", PagePerformance);
        NavigationItem("nav_coverage", "Coverage & audit", "08", PageCoverage);

        const ImGuiStyle& style = ImGui::GetStyle();
        const float buttonHeight = ImGui::GetFrameHeight();
        const float actionHeight = ImGui::GetTextLineHeightWithSpacing() * 5.0f +
            buttonHeight * 2.0f + style.ItemSpacing.y * 6.0f + style.ItemSpacing.y;
        const float remaining = ImGui::GetContentRegionAvail().y;
        if (remaining > actionHeight)
            ImGui::Dummy(ImVec2(0.0f, remaining - actionHeight));

        ImGui::Separator();
        ImGui::TextDisabled("%llu target roots  |  %llu workers",
            static_cast<unsigned long long>(SelectedRootCount()),
            static_cast<unsigned long long>(stats.workerThreads));

        const float width = ImGui::GetContentRegionAvail().x;
        if (!running)
        {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.91f, 0.27f, 0.025f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.00f, 0.39f, 0.055f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.72f, 0.18f, 0.015f, 1.00f));
            if (ImGui::Button("START SYSTEM SCAN", ImVec2(width, 0.0f)))
                BeginWork(false);
            ImGui::PopStyleColor(3);
        }
        else
        {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.48f, 0.08f, 0.08f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.68f, 0.10f, 0.09f, 1.00f));
            if (ImGui::Button("CANCEL ACTIVE SCAN", ImVec2(width, 0.0f)))
                g_app.cancelRequested.store(true, std::memory_order_release);
            ImGui::PopStyleColor(2);
        }

        ImGui::BeginDisabled(running);
        const float secondaryMinimum = (std::max)(TextWidth("SYNC FEEDS"), TextWidth("EXPORT")) +
            style.FramePadding.x * 2.0f;
        const int secondaryColumns = FittedColumnCount(ImGui::GetContentRegionAvail().x,
            secondaryMinimum, 2);
        const float secondaryWidth = ColumnWidth(ImGui::GetContentRegionAvail().x, secondaryColumns);
        if (ImGui::Button("SYNC FEEDS", ImVec2(secondaryWidth, 0.0f)))
            BeginWork(true);
        if (secondaryColumns > 1) ImGui::SameLine();
        if (ImGui::Button("EXPORT", ImVec2(secondaryWidth, 0.0f)))
            ExportReports();
        ImGui::EndDisabled();
        ImGui::TextDisabled("THREAT INTELLIGENCE");
        ImGui::Text("%llu package names", static_cast<unsigned long long>(feedNames));
        ImGui::Text("%llu exact versions", static_cast<unsigned long long>(feedPairs));
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    void RenderCompactNavigation(bool running, std::size_t feedNames,
        std::size_t feedPairs, const ScanStats& stats)
    {
        struct CompactPage
        {
            const char* code;
            const char* label;
            int page;
        };
        const CompactPage pages[] = {
            {"01", "Overview", PageOverview},
            {"02", "Scan targets", PageTargets},
            {"03", "Detection policy", PageDetection},
            {"04", "Findings", PageFindings},
            {"05", "Package inventory", PageInventory},
            {"06", "Threat intelligence", PageThreatIntel},
            {"07", "Scan performance", PagePerformance},
            {"08", "Coverage & audit", PageCoverage}
        };

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.011f, 0.012f, 0.013f, 0.99f));
        ImGui::BeginChild("security_navigation_compact", ImVec2(0.0f, 0.0f),
            ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        bool first = true;
        for (const CompactPage& page : pages)
        {
            const std::string caption = std::string(page.code) + "  " + page.label;
            const float width = TextWidth(caption.c_str()) +
                ImGui::GetStyle().FramePadding.x * 2.0f;
            if (!first && CanPlaceNextInline(width + ImGui::GetStyle().ItemSpacing.x))
                ImGui::SameLine();

            const bool selected = g_app.activePage == page.page;
            if (selected)
            {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.075f, 0.018f, 1.00f));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.00f, 0.39f, 0.07f, 1.00f));
            }
            if (ImGui::Button(caption.c_str(), ImVec2(width, 0.0f)))
                g_app.activePage = page.page;
            if (selected)
                ImGui::PopStyleColor(2);
            first = false;
        }

        ImGui::Separator();
        const char* primaryLabel = running ? "CANCEL ACTIVE SCAN" : "START SYSTEM SCAN";
        const char* actionLabels[] = {primaryLabel, "SYNC FEEDS", "EXPORT"};
        float actionMinimum = 0.0f;
        for (const char* label : actionLabels)
            actionMinimum = (std::max)(actionMinimum,
                TextWidth(label) + ImGui::GetStyle().FramePadding.x * 2.0f);
        const float actionAreaWidth = ImGui::GetContentRegionAvail().x;
        const int actionColumns = FittedColumnCount(actionAreaWidth, actionMinimum, 3);
        const float actionWidth = ColumnWidth(actionAreaWidth, actionColumns);

        if (!running)
        {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.91f, 0.27f, 0.025f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.00f, 0.39f, 0.055f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.72f, 0.18f, 0.015f, 1.00f));
            if (ImGui::Button(primaryLabel, ImVec2(actionWidth, 0.0f)))
                BeginWork(false);
            ImGui::PopStyleColor(3);
        }
        else
        {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.48f, 0.08f, 0.08f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.66f, 0.10f, 0.10f, 1.00f));
            if (ImGui::Button(primaryLabel, ImVec2(actionWidth, 0.0f)))
                g_app.cancelRequested.store(true, std::memory_order_release);
            ImGui::PopStyleColor(2);
        }

        if (actionColumns > 1) ImGui::SameLine();
        ImGui::BeginDisabled(running);
        if (ImGui::Button("SYNC FEEDS", ImVec2(actionWidth, 0.0f)))
            BeginWork(true);
        ImGui::EndDisabled();
        if (actionColumns > 2) ImGui::SameLine();
        if (ImGui::Button("EXPORT", ImVec2(actionWidth, 0.0f)))
            ExportReports();

        ImGui::TextDisabled("%llu roots  |  %llu workers  |  %llu names  |  %llu versions",
            static_cast<unsigned long long>(SelectedRootCount()),
            static_cast<unsigned long long>(stats.workerThreads),
            static_cast<unsigned long long>(feedNames),
            static_cast<unsigned long long>(feedPairs));
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    float MinimumWorkspaceWidth()
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const float pageHeading = (std::max)({
            TextWidth("Security posture"),
            TextWidth("Threat intelligence"),
            TextWidth("Package inventory"),
            TextWidth("Coverage and audit")
        });
        const float tableHeading = TextWidth("Manifest / metadata path");
        return (std::max)(pageHeading * 2.0f, tableHeading) +
            style.WindowPadding.x * 2.0f;
    }

    void RenderRecentFindings(const std::vector<Finding>& findings)
    {
        if (findings.empty())
        {
            const ImVec2 available = ImGui::GetContentRegionAvail();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + available.y * 0.30f);
            PushNativeFont(g_fontSemibold);
            ImGui::TextColored(ImVec4(0.24f, 0.82f, 0.49f, 1.00f), "NO ACTIVE FINDINGS");
            ImGui::PopFont();
            ImGui::TextDisabled("No known indicators have been recorded in this scan session.");
            return;
        }

        if (ImGui::BeginTable("overview_findings", 4,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_ScrollY,
                ImVec2(0.0f, 0.0f)))
        {
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableSetupColumn("Indicator", ImGuiTableColumnFlags_WidthStretch, 0.26f);
            ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 0.40f);
            ImGui::TableHeadersRow();
            const std::size_t first = findings.size() > 100 ? findings.size() - 100 : 0;
            for (std::size_t index = first; index < findings.size(); ++index)
            {
                const Finding& finding = findings[index];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(SeverityColor(finding.severity), "%s", SeverityText(finding.severity));
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(WideToUtf8(finding.type).c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(WideToUtf8(finding.indicator).c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(WideToUtf8(finding.path).c_str());
            }
            ImGui::EndTable();
        }
    }

    void RenderOverviewPage(const ScanStats& stats, const std::vector<Finding>& findings,
        const std::wstring& status, const std::wstring& currentPath, bool running,
        bool cancelled, std::size_t feedNames, std::size_t feedPairs,
        const FeedSyncResult& feedSync)
    {
        PageHeader("Security posture", "System-wide package compromise assessment and scan telemetry.",
            "OPERATIONS / OVERVIEW");

        const std::uint64_t critical = CountFindings(findings, Severity::Critical);
        const std::uint64_t high = CountFindings(findings, Severity::High);
        const std::uint64_t medium = CountFindings(findings, Severity::Medium);
        const std::uint64_t coverageIssues = stats.accessDenied + stats.errors;
        const IntelligenceHealth feedHealth = GetIntelligenceHealth(feedSync);
        const bool degradedFeeds = feedHealth != IntelligenceHealth::Current;
        const ImVec4 posture = critical > 0
            ? SeverityColor(Severity::Critical)
            : running ? ImVec4(0.24f, 0.82f, 0.49f, 1.00f)
            : cancelled ? CautionColor()
            : degradedFeeds ? IntelligenceHealthColor(feedHealth)
            : ImVec4(0.24f, 0.82f, 0.49f, 1.00f);

        const std::string fullStatus = WideToUtf8(
            degradedFeeds && !running && critical == 0 ? feedSync.healthSummary : status);
        const std::string fullPath = running && !currentPath.empty() ? WideToUtf8(currentPath) : std::string{};
        const unsigned bannerLines = fullPath.empty() ? 2u : 3u;
        const float bannerHeight = ContentChildHeight(bannerLines, bannerLines - 1u);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.023f, 0.018f, 0.014f, 0.98f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(posture.x, posture.y, posture.z, 0.38f));
        ImGui::BeginChild("posture_banner", ImVec2(0.0f, bannerHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        const ImVec2 bannerPos = ImGui::GetWindowPos();
        const float accentWidth = ImGui::GetWindowHeight() * 0.035f;
        ImGui::GetWindowDrawList()->AddRectFilled(
            bannerPos, ImVec2(bannerPos.x + accentWidth, bannerPos.y + ImGui::GetWindowHeight()),
            ImGui::ColorConvertFloat4ToU32(posture), accentWidth);

        PushRelativeFont(g_fontSemibold, 0.76f);
        ImGui::TextColored(posture, "%s",
            critical > 0 ? "CONFIRMED MALWARE HASH MATCH" :
            running ? "ACTIVE SCAN IN PROGRESS" :
            cancelled ? "SCAN CANCELLED" :
            degradedFeeds ? "THREAT INTELLIGENCE DEGRADED" : "SCANNER READY");
        ImGui::PopFont();

        PushRelativeFont(g_fontSemibold, 0.82f);
        const std::string clippedStatus = EllipsizeToWidth(fullStatus, ImGui::GetContentRegionAvail().x);
        ImGui::TextUnformatted(clippedStatus.c_str());
        if (ImGui::IsItemHovered() && clippedStatus != fullStatus)
        {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ViewportWidth(0.55f));
            ImGui::TextUnformatted(fullStatus.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
        ImGui::PopFont();

        if (!fullPath.empty())
        {
            PushRelativeFont(g_fontMono, 0.71f);
            const std::string clippedPath = EllipsizeToWidth(fullPath, ImGui::GetContentRegionAvail().x);
            ImGui::TextDisabled("%s", clippedPath.c_str());
            if (ImGui::IsItemHovered() && clippedPath != fullPath)
            {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ViewportWidth(0.55f));
                ImGui::TextUnformatted(fullPath.c_str());
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::PopFont();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);

        ImGui::Spacing();
        struct CardData
        {
            const char* id;
            const char* label;
            std::uint64_t value;
            const char* caption;
            ImVec4 color;
        };
        const CardData cards[] = {
            {"overview_critical", "CRITICAL", critical, "exact hashes", SeverityColor(Severity::Critical)},
            {"overview_high", "HIGH", high, "strong evidence", SeverityColor(Severity::High)},
            {"overview_medium", "MEDIUM", medium, "exposure leads", SeverityColor(Severity::Medium)},
            {"overview_packages", "PACKAGES", stats.packagesInventoried, "inventoried", ImVec4(1.00f, 0.39f, 0.07f, 1.00f)},
            {"overview_files", "FILES", stats.filesVisited, "enumerated", ImVec4(0.82f, 0.60f, 0.38f, 1.00f)},
            {"overview_coverage", "COVERAGE", coverageIssues, "denied/errors",
                coverageIssues ? CautionColor() : ImVec4(0.24f, 0.82f, 0.49f, 1.00f)}
        };
        float cardMinimum = 0.0f;
        for (const CardData& card : cards)
            cardMinimum = (std::max)(cardMinimum, MetricCardMinimumWidth(card.label, card.caption));
        const float cardAreaWidth = ImGui::GetContentRegionAvail().x;
        const int cardColumns = FittedBalancedColumnCount(cardAreaWidth, cardMinimum, 6, 6);
        const float cardWidth = ColumnWidth(cardAreaWidth, cardColumns);
        for (int index = 0; index < static_cast<int>(std::size(cards)); ++index)
        {
            const CardData& card = cards[index];
            MetricCard(card.id, card.label, card.value, card.caption, card.color, cardWidth);
            if ((index + 1) % cardColumns != 0 && index + 1 < static_cast<int>(std::size(cards)))
                ImGui::SameLine();
        }

        ImGui::Spacing();
        const float lowerWidth = ImGui::GetContentRegionAvail().x;
        const float telemetryContentWidth = (std::max)({
            TextWidth("Threat intelligence"), TextWidth("Files queued  000000000"),
            TextWidth("OPEN FINDINGS"), TextWidth("Fallback source active")
        }) + ImGui::GetStyle().WindowPadding.x * 2.0f;
        const bool sideBySide = lowerWidth >= telemetryContentWidth * 2.25f;
        const float lowerHeight = (std::max)(ImGui::GetContentRegionAvail().y, ImGui::GetFrameHeight() * 8.0f);
        const float telemetryWidth = sideBySide
            ? (std::max)(telemetryContentWidth, lowerWidth * 0.20f)
            : lowerWidth;
        const float streamWidth = sideBySide
            ? lowerWidth - telemetryWidth - ImGui::GetStyle().ItemSpacing.x
            : lowerWidth;
        const float streamHeight = sideBySide ? lowerHeight : lowerHeight * 0.58f;
        const float telemetryHeight = sideBySide ? lowerHeight :
            lowerHeight - streamHeight - ImGui::GetStyle().ItemSpacing.y;

        ImGui::BeginChild("overview_stream", ImVec2(streamWidth, streamHeight), ImGuiChildFlags_Borders);
        SectionTitle("Detection stream", "most recent session evidence");
        RenderRecentFindings(findings);
        ImGui::EndChild();
        if (sideBySide)
            ImGui::SameLine();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.021f, 0.018f, 0.015f, 0.98f));
        ImGui::BeginChild("overview_telemetry", ImVec2(telemetryWidth, telemetryHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Scan telemetry");
        ImGui::TextDisabled("PARALLEL ENGINE");
        ImGui::Text("Workers       %llu / %llu",
            static_cast<unsigned long long>(stats.activeWorkers),
            static_cast<unsigned long long>(stats.workerThreads));
        ImGui::Text("Files queued  %llu", static_cast<unsigned long long>(stats.filesQueued));
        ImGui::Text("Peak queue    %llu", static_cast<unsigned long long>(stats.peakQueueDepth));
        ImGui::Text("Roots         %llu / %llu",
            static_cast<unsigned long long>(stats.rootsCompleted),
            static_cast<unsigned long long>(stats.rootsTotal));
        const float progress = stats.rootsTotal == 0 ? 0.0f :
            static_cast<float>(stats.rootsCompleted) / static_cast<float>(stats.rootsTotal);
        ImGui::ProgressBar((std::clamp)(progress, 0.0f, 1.0f),
            ImVec2(-1.0f, ImGui::GetFrameHeight() * 0.45f), "");
        ImGui::Spacing();
        SectionTitle("Threat intelligence");
        ImGui::Text("%llu package names", static_cast<unsigned long long>(feedNames));
        ImGui::Text("%llu exact versions", static_cast<unsigned long long>(feedPairs));
        ImGui::TextColored(IntelligenceHealthColor(feedHealth), "%s",
            feedHealth == IntelligenceHealth::Current ? "All sources current" :
            feedHealth == IntelligenceHealth::Degraded ? "Fallback source active" : "Source unavailable");
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextDisabled("Socket, SafeDep, Wiz, Datadog, StepSecurity, JFrog, and community intelligence are merged independently.");
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        if (ImGui::Button("OPEN FINDINGS", ImVec2(-1.0f, 0.0f)))
            g_app.activePage = PageFindings;
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    void RenderTargetsPage(bool running)
    {
        PageHeader("Scan targets", "Select every local, removable, mapped, or custom root to inspect.",
            "CONFIGURATION / TARGETS");
        ImGui::BeginDisabled(running);
        if (ImGui::Button("SELECT LOCAL"))
            for (auto& drive : g_app.drives) drive.selected = drive.type != DRIVE_REMOTE;
        FlowSameLine(TextWidth("SELECT ALL") + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::Button("SELECT ALL"))
            for (auto& drive : g_app.drives) drive.selected = true;
        FlowSameLine(TextWidth("CLEAR") + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::Button("CLEAR"))
            for (auto& drive : g_app.drives) drive.selected = false;
        FlowSameLine(TextWidth("REFRESH HARDWARE") + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::Button("REFRESH HARDWARE"))
            RefreshDrives();
        FlowSameLine(TextWidth("000 roots selected"));
        ImGui::TextDisabled("%llu roots selected", static_cast<unsigned long long>(SelectedRootCount()));

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.020f, 0.017f, 0.014f, 0.98f));
        const float targetPanelHeight = ImGui::GetContentRegionAvail().y * 0.52f;
        ImGui::BeginChild("target_drive_panel", ImVec2(0.0f, targetPanelHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Detected storage", "fixed, removable and mapped drives");
        if (ImGui::BeginTable("drive_targets", 3,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_ScrollY,
                ImVec2(0.0f, 0.0f)))
        {
            ImGui::TableSetupColumn("Scan", ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableSetupColumn("Root", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("Volume / type / capacity", ImGuiTableColumnFlags_WidthStretch, 0.74f);
            ImGui::TableHeadersRow();
            for (std::size_t index = 0; index < g_app.drives.size(); ++index)
            {
                DriveInfo& drive = g_app.drives[index];
                ImGui::PushID(static_cast<int>(index));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Checkbox("##drive", &drive.selected);
                ImGui::TableSetColumnIndex(1);
                PushNativeFont(g_fontMono);
                ImGui::TextUnformatted(WideToUtf8(drive.root.wstring()).c_str());
                ImGui::PopFont();
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(drive.display.c_str());
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        const float targetLowerWidth = ImGui::GetContentRegionAvail().x;
        const float targetMinColumn = TextWidth("Optional include tokens; blank scans all paths") +
            ImGui::GetStyle().WindowPadding.x * 2.0f;
        const bool targetColumns = targetLowerWidth >= targetMinColumn * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        const float targetColumnWidth = targetColumns ? ColumnWidth(targetLowerWidth, 2) : targetLowerWidth;
        const float targetLowerHeight = ImGui::GetContentRegionAvail().y;
        const float targetPanelLowerHeight = targetColumns ? targetLowerHeight :
            (targetLowerHeight - ImGui::GetStyle().ItemSpacing.y) * 0.5f;
        ImGui::BeginChild("custom_root_panel", ImVec2(targetColumnWidth, targetPanelLowerHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Custom roots");
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.72f);
        ImGui::InputTextWithHint("##custom_roots", "D:\\Repos;E:\\Builds;\\\\server\\share",
            g_app.customRoots.data(), g_app.customRoots.size());
        ImGui::SameLine();
        if (ImGui::Button("BROWSE", ImVec2(ImGui::GetContentRegionAvail().x, 0.0f)))
            BrowseForRoot();
        ImGui::TextDisabled("Semicolon-separated. Custom paths are scanned in addition to checked drives.");
        ImGui::EndChild();
        if (targetColumns)
            ImGui::SameLine();
        ImGui::BeginChild("path_policy_panel", ImVec2(targetColumnWidth, targetPanelLowerHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Path policy");
        ImGui::InputTextWithHint("##include_tokens", "Optional include tokens; blank scans all paths",
            g_app.includeTokens.data(), g_app.includeTokens.size());
        ImGui::InputTextWithHint("##exclude_names", "Excluded directory names; semicolon-separated",
            g_app.excludedNames.data(), g_app.excludedNames.size());
        ImGui::Checkbox("Skip top-level Windows directory", &g_app.skipWindowsDirectory);
        ImGui::Checkbox("Follow junctions / reparse points", &g_app.followReparsePoints);
        if (g_app.followReparsePoints)
        {
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
            ImGui::TextColored(CautionColor(),
                "Caution: following reparse points can duplicate work or create traversal loops.");
            ImGui::PopTextWrapPos();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::EndDisabled();
    }

    void ToggleRow(const char* id, const char* title, const char* description, bool* value)
    {
        const ImVec2 togglePadding(ImGui::GetStyle().WindowPadding.x * 0.75f,
            ImGui::GetStyle().WindowPadding.y * 0.60f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, togglePadding);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.022f, 0.021f, 0.020f, 0.98f));
        const float optionTextWidth = (std::max)(ImGui::GetContentRegionAvail().x -
            ImGui::GetFrameHeight() - ImGui::GetStyle().ItemSpacing.x,
            ImGui::GetContentRegionAvail().x * 0.35f);
        const float optionHeight = ImGui::GetStyle().WindowPadding.y * 2.0f +
            ImGui::GetTextLineHeightWithSpacing() +
            ImGui::CalcTextSize(description, nullptr, false, optionTextWidth).y;
        ImGui::BeginChild(id, ImVec2(0.0f, optionHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        if (ImGui::BeginTable("toggle_layout", 2,
                ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoPadOuterX))
        {
            ImGui::TableSetupColumn("toggle", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFrameHeight());
            ImGui::TableSetupColumn("copy", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableNextColumn();
            ImGui::SetCursorPosY((ImGui::GetWindowHeight() - ImGui::GetFrameHeight()) * 0.5f);
            ImGui::Checkbox("##enabled", value);
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            PushRelativeFont(g_fontSemibold, 0.94f);
            ImGui::TextUnformatted(title);
            ImGui::PopFont();
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
            ImGui::TextDisabled("%s", description);
            ImGui::PopTextWrapPos();
            ImGui::EndTable();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();
    }

    void RenderDetectionPage(bool running, std::size_t activeHashIndicators)
    {
        PageHeader("Detection policy",
            "Choose which package ecosystems, persistence locations, and payload evidence are examined.",
            "CONFIGURATION / DETECTION");
        const float availableWidth = ImGui::GetContentRegionAvail().x;
        const float minimumColumn = (std::max)(TextWidth("Known artifacts and exact hashes"),
            TextWidth("Package-manager caches")) + ImGui::GetFrameHeight() +
            ImGui::GetStyle().WindowPadding.x * 3.0f;
        const bool sideBySide = availableWidth >= minimumColumn * 2.0f +
            ImGui::GetStyle().ItemSpacing.x;
        const int columns = sideBySide ? 2 : 1;

        ImGui::BeginDisabled(running);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
            ImVec2(ImGui::GetStyle().ItemSpacing.x, ImGui::GetStyle().ItemSpacing.y * 0.65f));
        if (ImGui::BeginTable("detection_columns", columns,
                ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoPadOuterX))
        {
            ImGui::TableNextColumn();
            ImGui::BeginChild("package_coverage", ImVec2(0.0f, sideBySide ? 0.0f :
                    ImGui::GetContentRegionAvail().y * 0.52f), ImGuiChildFlags_Borders,
                ImGuiWindowFlags_None);
            SectionTitle("Package intelligence");
            ToggleRow("npm_manifest", "npm installed manifests",
                "Compares package.json names and exact installed versions.", &g_app.scanNpmPackages);
            ToggleRow("npm_locks", "JavaScript lockfiles",
                "Checks npm, Yarn, pnpm, and Bun lockfiles.", &g_app.scanNpmLockfiles);
            ToggleRow("python_metadata", "Installed Python metadata",
                "Checks installed dist-info and egg-info releases.", &g_app.scanPythonPackages);
            ToggleRow("python_locks", "Python dependency files",
                "Checks requirements, Poetry, Pipenv, and uv locks.", &g_app.scanPythonLockfiles);
            ToggleRow("go_modules", "Go module references",
                "Checks go.mod and go.sum dependency records.", &g_app.scanGoDependencies);
            ToggleRow("package_caches", "Package-manager caches",
                "Checks npm, Yarn, pnpm, pip, and uv cache metadata.", &g_app.scanPackageCaches);
            ToggleRow("inventory", "Full package inventory",
                "Records every installed package for review and export.", &g_app.createPackageInventory);
            ImGui::EndChild();

            ImGui::TableNextColumn();
            ImGui::BeginChild("malware_policy", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders,
                ImGuiWindowFlags_None);
            SectionTitle("Malware and persistence");
            const std::string hashDescription =
                "Checks known artifact names and " + std::to_string(activeHashIndicators) +
                " exact malicious hashes. Edit malicious_hashes.json to add new IOCs without rebuilding.";
            ToggleRow("known_artifacts", "Known artifacts and exact hashes",
                hashDescription.c_str(), &g_app.scanKnownArtifacts);
            ToggleRow("behavior_variants", "Renamed behavior variants",
                "Looks for loader, C2, credential-theft, and propagation code.", &g_app.scanBehaviorVariants);
            ToggleRow("persistence", "Developer-tool persistence",
                "Checks VS Code, Claude Code, and GitHub workflow hooks.", &g_app.scanEditorPersistence);
            ToggleRow("deep_hash", "Deep package-script hashing",
                "Hashes every package script; slower on large systems.", &g_app.deepHashPackageScripts);
            ImGui::Spacing();
            NoticeBox("severity_contract", "How findings are graded",
                "Critical means a scanned file exactly matches a known malicious hash.\n\n"
                "High means an affected installed release, strong persistence, or malicious payload behavior was found and needs immediate investigation.\n\n"
                "Medium means possible exposure in a lockfile, cache, or suspicious artifact. High and Medium are evidence for triage; they are not cryptographic proof that the payload ran.",
                CautionColor());
            ImGui::EndChild();
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
        ImGui::EndDisabled();
    }

    void RenderFindingsPage(std::vector<Finding> findings)
    {
        PageHeader("Findings", "Triage exact hashes, installed exposure and behavioral evidence.",
            "ANALYSIS / FINDINGS");
        RenderFindings(std::move(findings));
    }

    void RenderInventoryPage(const std::vector<PackageRecord>& packages, bool running)
    {
        PageHeader("Package inventory", "Search the complete package manifest and metadata collection.",
            "ANALYSIS / INVENTORY");
        RenderInventory(packages, running);
    }

    void RenderThreatIntelPage(const FeedSyncResult& sync, std::size_t names, std::size_t pairs)
    {
        PageHeader("Threat intelligence", "Independent campaign feeds are validated, cached and merged.",
            "INTELLIGENCE / FEEDS");
        RenderFeeds(sync, names, pairs);
    }

    void RenderPerformancePage(const ScanStats& stats, bool running)
    {
        PageHeader("Scan performance",
            "Tune bounded parallelism without flooding a disk or allowing the work queue to grow without limit.",
            "ENGINE / PERFORMANCE");
        const float availableWidth = ImGui::GetContentRegionAvail().x;
        const float minimumColumn = (std::max)(TextWidth("Conditionally refresh feeds before every scan"),
            TextWidth("Configured workers")) + ImGui::GetStyle().WindowPadding.x * 2.0f;
        const bool sideBySide = availableWidth >= minimumColumn * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        const float panelWidth = sideBySide ? ColumnWidth(availableWidth, 2) : availableWidth;
        const float availableHeight = ImGui::GetContentRegionAvail().y;
        const float panelHeight = sideBySide ? availableHeight :
            (availableHeight - ImGui::GetStyle().ItemSpacing.y) * 0.5f;

        ImGui::BeginDisabled(running);
        ImGui::BeginChild("engine_configuration", ImVec2(panelWidth, panelHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Bounded worker engine");
        static const char* workerLabels[] = {"Auto", "1", "2", "4", "8", "12", "16", "24", "32"};
        if (ImGui::BeginTable("engine_controls", 2, ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("Control", ImGuiTableColumnFlags_WidthStretch, 0.62f);
            ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch, 0.38f);
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::Combo("##worker_threads", &g_app.workerChoice, workerLabels,
                static_cast<int>(std::size(workerLabels)));
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Worker threads");
            ImGui::TableNextColumn();
            static const char* queueLabels[] = {"2,048", "8,192", "32,768", "65,536"};
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::Combo("##bounded_queue", &g_app.queueChoice, queueLabels,
                static_cast<int>(std::size(queueLabels)));
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Bounded queue");
            ImGui::EndTable();
        }
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextDisabled("Auto uses hardware concurrency minus one and stays within the scanner's safety limits.");
        ImGui::TextDisabled("Backpressure pauses enumeration when workers cannot drain the queue quickly enough.");
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        SectionTitle("Feed synchronization");
        ImGui::Checkbox("Conditionally refresh feeds before every scan", &g_app.refreshFeedsBeforeScan);
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextDisabled("HTTP validators avoid unnecessary downloads. Every valid source is merged, and no provider can remove another provider's unique indicators.");
        ImGui::PopTextWrapPos();
        ImGui::EndChild();
        ImGui::EndDisabled();

        if (sideBySide)
            ImGui::SameLine();
        ImGui::BeginChild("engine_telemetry", ImVec2(panelWidth, panelHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle(running ? "Current scan telemetry" : "Last scan telemetry");
        if (ImGui::BeginTable("engine_stats", 2,
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerH))
        {
            ImGui::TableSetupColumn("Metric", ImGuiTableColumnFlags_WidthStretch, 0.76f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.24f);
            AuditRow("Configured workers", stats.workerThreads);
            AuditRow("Active workers", stats.activeWorkers);
            AuditRow("Files queued", stats.filesQueued);
            AuditRow("Peak queue depth", stats.peakQueueDepth);
            AuditRow("Files enumerated", stats.filesVisited);
            AuditRow("Hashes calculated", stats.hashesCalculated);
            ImGui::EndTable();
        }
        ImGui::Spacing();
        ImGui::TextDisabled("Roots completed");
        ImGui::SameLine();
        PushNativeFont(g_fontMono);
        ImGui::TextColored(ImVec4(0.94f, 0.55f, 0.20f, 1.00f), "%llu / %llu",
            static_cast<unsigned long long>(stats.rootsCompleted),
            static_cast<unsigned long long>(stats.rootsTotal));
        ImGui::PopFont();
        const float progress = stats.rootsTotal == 0 ? 0.0f :
            static_cast<float>(stats.rootsCompleted) / static_cast<float>(stats.rootsTotal);
        char overlay[32]{};
        std::snprintf(overlay, sizeof(overlay), "%.0f%%", (std::clamp)(progress, 0.0f, 1.0f) * 100.0f);
        ImGui::ProgressBar((std::clamp)(progress, 0.0f, 1.0f),
            ImVec2(-1.0f, ImGui::GetFrameHeight() * 0.55f), overlay);
        ImGui::EndChild();
    }

    void RenderCoveragePage(const ScanStats& stats)
    {
        PageHeader("Coverage and audit",
            "Confirm what the scanner examined and identify any locations it could not read.",
            "AUDIT / COVERAGE");

        struct CoverageCard
        {
            const char* id;
            const char* label;
            std::uint64_t value;
            const char* caption;
            ImVec4 color;
        };
        const CoverageCard cards[] = {
            {"coverage_dirs", "DIRECTORIES", stats.directoriesVisited, "visited", ImVec4(1.00f, 0.39f, 0.07f, 1.00f)},
            {"coverage_hashes", "HASHES", stats.hashesCalculated, "calculated", ImVec4(0.94f, 0.55f, 0.20f, 1.00f)},
            {"coverage_denied", "ACCESS DENIED", stats.accessDenied, "locations",
                stats.accessDenied ? SeverityColor(Severity::Medium) : ImVec4(0.35f, 0.80f, 0.47f, 1.00f)},
            {"coverage_errors", "ERRORS", stats.errors, "operations",
                stats.errors ? SeverityColor(Severity::Critical) : ImVec4(0.35f, 0.80f, 0.47f, 1.00f)}
        };
        float minimumCardWidth = 0.0f;
        for (const CoverageCard& card : cards)
            minimumCardWidth = (std::max)(minimumCardWidth, MetricCardMinimumWidth(card.label, card.caption));
        const float cardAreaWidth = ImGui::GetContentRegionAvail().x;
        const int cardColumns = FittedBalancedColumnCount(cardAreaWidth, minimumCardWidth, 4, 4);
        const float cardWidth = ColumnWidth(cardAreaWidth, cardColumns);
        for (int index = 0; index < static_cast<int>(std::size(cards)); ++index)
        {
            const CoverageCard& card = cards[index];
            MetricCard(card.id, card.label, card.value, card.caption, card.color, cardWidth);
            if ((index + 1) % cardColumns != 0 && index + 1 < static_cast<int>(std::size(cards)))
                ImGui::SameLine();
        }

        ImGui::Spacing();
        PushNativeFont(g_fontSemibold);
        const float auditTitleHeight = ImGui::GetTextLineHeightWithSpacing();
        ImGui::PopFont();
        const float auditRowHeight = ImGui::GetTextLineHeightWithSpacing() +
            ImGui::GetStyle().CellPadding.y * 2.0f;
        const float auditChromeHeight = ImGui::GetStyle().WindowPadding.y * 2.0f +
            auditTitleHeight + ImGui::GetStyle().ItemSpacing.y;
        const float auditHeight = auditChromeHeight + auditRowHeight * 8.0f;

        const float auditAreaWidth = ImGui::GetContentRegionAvail().x;
        const float auditMinimum = (std::max)(TextWidth("Candidate files queued"),
            TextWidth("Deep-hashed scripts")) + TextWidth("000000000") +
            ImGui::GetStyle().WindowPadding.x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        const bool auditSideBySide = auditAreaWidth >= auditMinimum * 2.0f +
            ImGui::GetStyle().ItemSpacing.x;
        const float auditWidth = auditSideBySide ? ColumnWidth(auditAreaWidth, 2) : auditAreaWidth;

        ImGui::BeginChild("parallel_audit", ImVec2(auditWidth, auditHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Enumeration audit");
        if (ImGui::BeginTable("enumeration_audit_table", 2,
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerH))
        {
            ImGui::TableSetupColumn("Metric", ImGuiTableColumnFlags_WidthStretch, 0.78f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            AuditRow("Selected roots", stats.rootsTotal);
            AuditRow("Roots completed", stats.rootsCompleted);
            AuditRow("Directories visited", stats.directoriesVisited);
            AuditRow("Files enumerated", stats.filesVisited);
            AuditRow("Candidate files queued", stats.filesQueued);
            AuditRow("Reparse points skipped", stats.skippedReparsePoints);
            AuditRow("Access denied", stats.accessDenied);
            AuditRow("Errors", stats.errors);
            ImGui::EndTable();
        }
        ImGui::EndChild();

        if (auditSideBySide)
            ImGui::SameLine();
        ImGui::BeginChild("detection_audit", ImVec2(auditWidth, auditHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        SectionTitle("Detection audit");
        if (ImGui::BeginTable("detection_audit_table", 2,
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerH))
        {
            ImGui::TableSetupColumn("Metric", ImGuiTableColumnFlags_WidthStretch, 0.78f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            AuditRow("npm manifests", stats.npmManifests);
            AuditRow("PyPI metadata", stats.pythonMetadataFiles);
            AuditRow("JavaScript lockfiles", stats.npmLockfiles);
            AuditRow("Python lockfiles", stats.pythonLockfiles);
            AuditRow("Go dependency files", stats.goDependencyFiles);
            AuditRow("Behavior files", stats.behaviorFiles);
            AuditRow("Deep-hashed scripts", stats.deepHashedScripts);
            AuditRow("Inventory records", stats.packagesInventoried);
            ImGui::EndTable();
        }
        ImGui::EndChild();

        ImGui::Spacing();
        NoticeBox("coverage_caution", "Caution: a clean scan is not a guarantee",
            "No known indicators means this scan did not find evidence in its current rules and intelligence.\n\n"
            "It does not prove the host was never exposed. An install-time payload may have run and removed itself before the scan.\n\n"
            "Review every High or Medium finding, access-denied location, and scan error before treating the system as clean.",
            CautionColor());
    }

    void RenderScanCompletionNotification(
        const ImGuiViewport* viewport,
        bool openNow,
        std::uint64_t criticalCount,
        std::uint64_t highCount,
        std::uint64_t mediumCount,
        std::uint64_t coverageIssues)
    {
        constexpr const char* popupName = "Scan completion verdict";
        if (openNow)
            ImGui::OpenPopup(popupName);

        const bool affected = criticalCount > 0;
        const ImVec4 accent = affected
            ? ImVec4(0.96f, 0.18f, 0.16f, 1.00f)
            : ImVec4(0.12f, 0.92f, 0.34f, 1.00f);
        const char* verdictTitle = affected
            ? "CONFIRMED MALWARE FILE DETECTED"
            : "NO CRITICALS ARE PRESENT - YOU ARE NOT CURRENTLY AFFECTED!";
        const char* cleanSummary =
            "No exact known-malware file hash was found.\n\n"
            "Keep package updates paused until maintainers and threat-intelligence sources confirm clean releases.";
        const char* cleanCautionHeading = "Caution: this is not proof of cleanliness";
        const char* cleanCautionBody =
            "No scanned file matched the scanner's current exact malware hashes.\n\n"
            "An affected package may still be present, an install-time payload may have removed itself, or part of the system may not have been readable.\n\n"
            "Review every High and Medium finding, access-denied path, and scan error before relying on this result.";
        const char* affectedSummary =
            "An exact known-malware hash matched a scanned file. Treat this machine, "
            "and any developer workstation or CI runner that installed the affected release, "
            "as compromised.";
        const struct CompromiseResponseStep
        {
            const char* number;
            const char* heading;
            const char* body;
        } compromiseSteps[] =
        {
            {"01", "Isolate the affected environment",
                "Disconnect the machine or runner, stop active builds, and do not run package installs, updates, or sensitive sign-ins from it."},
            {"02", "Preserve evidence before cleanup",
                "Export this report and record every Critical path, affected release, High finding, denied location, and scan error before removing anything."},
            {"03", "Remove token-monitor persistence first",
                "Remove gh-token-monitor services or launch agents before revoking GitHub tokens. Review .claude and .vscode hooks, GitHub workflows, Bun staging directories, temporary lock files, and CI caches."},
            {"04", "Restore known-good releases",
                "Remove affected packages and persistence, clear compromised caches, and pin or roll back to a verified clean version. Keep package updates paused until maintainers confirm clean releases."},
            {"05", "Rotate secrets from a separate clean machine",
                "Rotate npm and GitHub tokens, cloud credentials, SSH keys, CI secrets, AI-tool credentials, API keys, and browser sessions. Rebuild or reimage the host when persistence cannot be ruled out."}
        };

        const ImGuiStyle& style = ImGui::GetStyle();
        const ImVec2 verdictPadding(style.WindowPadding.x * 1.45f,
            style.WindowPadding.y * 1.45f);
        const float horizontalMargin = (std::max)(style.WindowPadding.x * 2.0f,
            viewport->WorkSize.x * 0.025f);
        const float verticalMargin = (std::max)(style.WindowPadding.y * 2.0f,
            viewport->WorkSize.y * 0.025f);
        const float maximumWidth = (std::max)(
            viewport->WorkSize.x - horizontalMargin * 2.0f,
            style.WindowPadding.x * 8.0f);

        // Clean and compromised results have very different content density.
        // Size the popup from the live viewport and measured content rather
        // than retaining the size from the frame in which it first appeared.
        PushNativeFont(g_fontTitle);
        const float titleNaturalWidth = ImGui::CalcTextSize(verdictTitle).x;
        ImGui::PopFont();
        const float resultWidthRatio = affected ? 0.86f : 0.78f;
        const float measuredMinimumWidth = titleNaturalWidth + verdictPadding.x * 2.0f;
        const float width = (std::min)(maximumWidth,
            (std::max)(viewport->WorkSize.x * resultWidthRatio, measuredMinimumWidth));
        const float innerWidth = (std::max)(width - verdictPadding.x * 2.0f,
            style.FramePadding.x * 6.0f);

        const auto wrappedHeight = [](const char* text, float wrapWidth)
        {
            return ImGui::CalcTextSize(text, nullptr, false,
                (std::max)(wrapWidth, ImGui::GetFontSize())).y;
        };
        const auto wrappedHeightWithFont = [&](ImFont* font, const char* text,
            float wrapWidth)
        {
            PushNativeFont(font);
            const float measured = wrappedHeight(text, wrapWidth);
            ImGui::PopFont();
            return measured;
        };

        const float headerHeight = ImGui::GetTextLineHeightWithSpacing() +
            NativeFontSize(g_fontTitle) * g_layout.scale +
            style.ItemSpacing.y * 3.0f + style.SeparatorSize;
        float bodyNaturalHeight = 0.0f;
        if (affected)
        {
            const float stepColumnWidth = ImGui::CalcTextSize("00").x +
                style.CellPadding.x * 2.0f;
            const float actionWidth = (std::max)(innerWidth - stepColumnWidth -
                style.CellPadding.x * 4.0f, ImGui::GetFontSize() * 8.0f);
            bodyNaturalHeight = wrappedHeightWithFont(g_fontSemibold, affectedSummary, innerWidth) +
                style.ItemSpacing.y;
            for (const auto& step : compromiseSteps)
            {
                const float headingHeight = wrappedHeightWithFont(
                    g_fontSemibold, step.heading, actionWidth);
                const float bodyHeightForStep = wrappedHeight(step.body, actionWidth);
                const float actionCellHeight = headingHeight + style.ItemSpacing.y +
                    bodyHeightForStep + style.CellPadding.y * 2.0f;
                const float numberCellHeight = ImGui::GetTextLineHeight() +
                    style.CellPadding.y * 2.0f;
                bodyNaturalHeight += (std::max)(actionCellHeight, numberCellHeight);
            }
            // Inner table borders consume space but do not create a full item-spacing
            // gap after each row. Keep only a one-border safety allowance.
            bodyNaturalHeight += style.SeparatorSize *
                static_cast<float>((std::size)(compromiseSteps) - 1);
        }
        else
        {
            // The verdict body uses zero window padding. Measure every clean
            // result element against that exact content width.
            const float bodyContentWidth = (std::max)(innerWidth, ImGui::GetFontSize());
            bodyNaturalHeight = wrappedHeightWithFont(g_fontSemibold,
                cleanSummary, bodyContentWidth) + style.ItemSpacing.y +
                CalculateNoticeBoxHeight(cleanCautionHeading,
                    cleanCautionBody, bodyContentWidth);
        }

        const float metricMinimum = (std::max)({
            TextWidth("CRITICAL 000"), TextWidth("HIGH 000"),
            TextWidth("MEDIUM 000"), TextWidth("COVERAGE ISSUES 000")}) +
            style.CellPadding.x * 2.0f;
        const int metricColumns = FittedColumnCount(innerWidth, metricMinimum, 4);
        const int metricRows = (4 + metricColumns - 1) / metricColumns;
        const float metricHeight = static_cast<float>(metricRows) *
            (ImGui::GetTextLineHeightWithSpacing() + style.CellPadding.y * 2.0f);
        const float disclaimerHeight = wrappedHeight(
            "Critical is reserved for an exact known-malware file-hash match. The scanner does not remove files or rotate credentials.",
            innerWidth);
        const float buttonMinimum = (std::max)(TextWidth("ACKNOWLEDGE"),
            TextWidth("REVIEW FINDINGS")) + style.FramePadding.x * 2.0f;
        const int buttonColumns = FittedColumnCount(innerWidth, buttonMinimum, 2);
        const int buttonRows = (2 + buttonColumns - 1) / buttonColumns;
        const float footerNaturalHeight = style.SeparatorSize + style.ItemSpacing.y * 3.0f +
            metricHeight + disclaimerHeight +
            static_cast<float>(buttonRows) * ImGui::GetFrameHeight() +
            static_cast<float>((std::max)(0, buttonRows - 1)) * style.ItemSpacing.y;
        const float maximumHeight = (std::max)(
            viewport->WorkSize.y - verticalMargin * 2.0f,
            headerHeight + footerNaturalHeight + ImGui::GetTextLineHeightWithSpacing());
        const float availableBodyHeight = (std::max)(ImGui::GetTextLineHeightWithSpacing(),
            maximumHeight - verdictPadding.y * 2.0f - headerHeight - footerNaturalHeight);
        const float measurementTolerance = (std::max)(style.ChildBorderSize * 2.0f,
            ImGui::GetFontSize() * 0.05f);
        const bool bodyNeedsScroll = bodyNaturalHeight >
            availableBodyHeight + measurementTolerance;
        const float bodyHeight = bodyNeedsScroll ? availableBodyHeight : bodyNaturalHeight;
        const float height = (std::min)(maximumHeight,
            verdictPadding.y * 2.0f + headerHeight + bodyHeight + footerNaturalHeight);

        ImGui::SetNextWindowPos(
            ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f,
                   viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.65f);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, ImGui::GetStyle().FrameBorderSize * 2.5f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, ImGui::GetStyle().FrameRounding * 2.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, verdictPadding);
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.005f, 0.005f, 0.006f, 0.65f));
        ImGui::PushStyleColor(ImGuiCol_Border, accent);
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.00f, 0.00f, 0.00f, 0.78f));

        const ImGuiWindowFlags flags =
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse;

        if (ImGui::BeginPopupModal(popupName, nullptr, flags))
        {
            const ImVec2 windowPos = ImGui::GetWindowPos();
            ImGui::GetWindowDrawList()->AddRectFilled(windowPos,
                ImVec2(windowPos.x + ImGui::GetWindowWidth(),
                    windowPos.y + ImGui::GetStyle().FrameBorderSize * 3.0f),
                ImGui::ColorConvertFloat4ToU32(accent), ImGui::GetStyle().WindowRounding,
                ImDrawFlags_RoundCornersTop);

            ImGui::TextColored(accent, "SCAN VERDICT / %s",
                affected ? "CONFIRMED HASH MATCH" : "NO CRITICAL HASH MATCH");

            PushNativeFont(g_fontTitle);
            ImGui::PushStyleColor(ImGuiCol_Text, accent);
            ImGui::TextWrapped("%s", verdictTitle);
            ImGui::PopStyleColor();
            ImGui::PopFont();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            const ImGuiWindowFlags verdictBodyFlags = bodyNeedsScroll
                ? ImGuiWindowFlags_None
                : ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
            ImGui::BeginChild("verdict_body", ImVec2(0.0f, bodyHeight),
                ImGuiChildFlags_None, verdictBodyFlags);

            if (affected)
            {
                PushNativeFont(g_fontSemibold);
                ImGui::TextWrapped("%s", affectedSummary);
                ImGui::PopFont();
                ImGui::Spacing();

                if (ImGui::BeginTable("compromise_response_steps", 2,
                        ImGuiTableFlags_SizingStretchProp |
                        ImGuiTableFlags_BordersInnerH |
                        ImGuiTableFlags_NoPadOuterX))
                {
                    ImGui::TableSetupColumn("Step", ImGuiTableColumnFlags_WidthFixed,
                        ImGui::CalcTextSize("00").x + ImGui::GetStyle().CellPadding.x * 2.0f);
                    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch);
                    const auto responseStep = [](const char* number,
                        const char* heading, const char* body)
                    {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        PushNativeFont(g_fontMono);
                        ImGui::TextColored(ImVec4(1.00f, 0.34f, 0.12f, 1.00f), "%s", number);
                        ImGui::PopFont();
                        ImGui::TableSetColumnIndex(1);
                        PushNativeFont(g_fontSemibold);
                        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                            ImGui::GetContentRegionAvail().x);
                        ImGui::TextWrapped("%s", heading);
                        ImGui::PopTextWrapPos();
                        ImGui::PopFont();
                        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                            ImGui::GetContentRegionAvail().x);
                        ImGui::TextDisabled("%s", body);
                        ImGui::PopTextWrapPos();
                    };
                    for (const auto& step : compromiseSteps)
                        responseStep(step.number, step.heading, step.body);
                    ImGui::EndTable();
                }
            }
            else
            {
                PushNativeFont(g_fontSemibold);
                ImGui::PushStyleColor(ImGuiCol_Text, accent);
                ImGui::TextWrapped("%s", cleanSummary);
                ImGui::PopStyleColor();
                ImGui::PopFont();
                // TextWrapped already leaves the normal ItemSpacing gap. Adding
                // ImGui::Spacing() here pushed the caution child down far enough
                // for its bottom border to be clipped by verdict_body.
                NoticeBox("clean_verdict_caution", cleanCautionHeading,
                    cleanCautionBody, CautionColor());
            }
            ImGui::EndChild();
            ImGui::PopStyleVar();

            ImGui::Separator();
            if (ImGui::BeginTable("verdict_metrics", metricColumns,
                    ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_BordersInnerV))
            {
                const struct VerdictMetric { const char* label; std::uint64_t value; ImVec4 color; } metrics[] =
                {
                    {"CRITICAL", criticalCount, SeverityColor(Severity::Critical)},
                    {"HIGH", highCount, SeverityColor(Severity::High)},
                    {"MEDIUM", mediumCount, SeverityColor(Severity::Medium)},
                    {"COVERAGE ISSUES", coverageIssues,
                        coverageIssues ? SeverityColor(Severity::Medium) : ImVec4(0.24f, 0.82f, 0.49f, 1.00f)}
                };
                for (const auto& metric : metrics)
                {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", metric.label);
                    ImGui::SameLine();
                    PushNativeFont(g_fontSemibold);
                    ImGui::TextColored(metric.color, "%llu",
                        static_cast<unsigned long long>(metric.value));
                    ImGui::PopFont();
                }
                ImGui::EndTable();
            }
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                ImGui::GetContentRegionAvail().x);
            ImGui::TextDisabled(
                "Critical is reserved for an exact known-malware file-hash match. "
                "The scanner does not remove files or rotate credentials.");
            ImGui::PopTextWrapPos();
            ImGui::Spacing();

            const float totalWidth = ImGui::GetContentRegionAvail().x;
            const float verdictButtonMinimum = (std::max)(TextWidth("ACKNOWLEDGE"),
                TextWidth("REVIEW FINDINGS")) + ImGui::GetStyle().FramePadding.x * 2.0f;
            const int verdictButtonColumns = FittedColumnCount(totalWidth,
                verdictButtonMinimum, 2);
            const float buttonWidth = ColumnWidth(totalWidth, verdictButtonColumns);
            ImGui::PushStyleColor(ImGuiCol_Button,
                ImVec4(accent.x * 0.28f, accent.y * 0.28f, accent.z * 0.28f, 0.96f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                ImVec4(accent.x * 0.45f, accent.y * 0.45f, accent.z * 0.45f, 1.00f));
            if (ImGui::Button("ACKNOWLEDGE", ImVec2(buttonWidth, 0.0f)))
                ImGui::CloseCurrentPopup();
            if (verdictButtonColumns > 1) ImGui::SameLine();
            if (ImGui::Button("REVIEW FINDINGS", ImVec2(buttonWidth, 0.0f)))
            {
                g_app.activePage = PageFindings;
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopStyleColor(2);
            ImGui::EndPopup();
        }

        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar(3);
    }

    void RenderTopHeader(bool running, const ScanStats& stats,
        std::size_t feedNames, std::size_t feedPairs, const FeedSyncResult& feedSync)
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const IntelligenceHealth health = GetIntelligenceHealth(feedSync);
        const char* engineLabel = running ? "SCAN ACTIVE" : "ENGINE IDLE";
        const ImVec4 engineColor = running
            ? ImVec4(0.24f, 0.82f, 0.49f, 1.00f)
            : ImVec4(0.88f, 0.88f, 0.86f, 1.00f);
        char feedLabel[96]{};
        std::snprintf(feedLabel, sizeof(feedLabel), "%llu TI VERSIONS",
            static_cast<unsigned long long>(feedPairs));
        const char* healthLabel = health == IntelligenceHealth::Current
            ? nullptr : health == IntelligenceHealth::Degraded
                ? "FEEDS DEGRADED" : "FEEDS UNAVAILABLE";

        float pillsWidth = StatusPillWidth(engineLabel) + style.ItemSpacing.x + StatusPillWidth(feedLabel);
        if (healthLabel)
            pillsWidth += style.ItemSpacing.x + StatusPillWidth(healthLabel);
        PushNativeFont(g_fontTitle);
        const float titleWidth = ImGui::CalcTextSize("SHAI-HULUD 2.0 SCANNER").x;
        ImGui::PopFont();
        const float brandTextWidth = (std::max)(titleWidth,
            TextWidth("Read-only supply-chain compromise assessment"));
        const float brandBlockWidth = brandTextWidth + ImGui::GetTextLineHeight() * 4.0f + style.ItemSpacing.x;
        const float availableWidth = ImGui::GetContentRegionAvail().x;
        const bool horizontal = availableWidth >= brandBlockWidth + pillsWidth + style.ItemSpacing.x * 2.0f;
        const float brandHeight = (std::max)(ImGui::GetTextLineHeight() * 3.0f,
            ImGui::GetTextLineHeightWithSpacing() * 2.0f);
        const int pillCount = healthLabel ? 3 : 2;
        const float widestPill = (std::max)({StatusPillWidth(engineLabel),
            StatusPillWidth(feedLabel), healthLabel ? StatusPillWidth(healthLabel) : 0.0f});
        const int stackedPillColumns = FittedColumnCount(availableWidth, widestPill, pillCount);
        const int stackedPillRows = (pillCount + stackedPillColumns - 1) / stackedPillColumns;
        const float statusHeight = StatusPillHeight() * static_cast<float>(horizontal ? 1 : stackedPillRows) +
            style.ItemSpacing.y * static_cast<float>(horizontal ? 0 : stackedPillRows - 1) +
            ImGui::GetTextLineHeightWithSpacing();
        const float headerHeight = style.WindowPadding.y * 2.0f +
            (horizontal ? (std::max)(brandHeight, statusHeight) :
                brandHeight + statusHeight + style.ItemSpacing.y);

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.010f, 0.011f, 0.012f, 0.99f));
        ImGui::BeginChild("command_header", ImVec2(0.0f, headerHeight), ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        auto renderBrand = [&]()
        {
            const float shieldSize = brandHeight * 0.72f;
            const ImVec2 shieldPosition = ImGui::GetCursorScreenPos();
            DrawShieldMark(shieldPosition, shieldSize, ImVec4(1.00f, 0.39f, 0.07f, 1.00f));
            ImGui::Dummy(ImVec2(shieldSize, shieldSize));
            ImGui::SameLine();
            ImGui::BeginGroup();
            PushNativeFont(g_fontTitle);
            ImGui::TextUnformatted("SHAI-HULUD 2.0 SCANNER");
            ImGui::PopFont();
            ImGui::TextDisabled("Read-only supply-chain compromise assessment  /  build %s", kVersion);
            ImGui::EndGroup();
        };

        auto renderStatus = [&]()
        {
            const float statusAvailable = ImGui::GetContentRegionAvail().x;
            const int columns = horizontal ? pillCount :
                FittedColumnCount(statusAvailable, widestPill, pillCount);
            if (horizontal)
            {
                const float startX = ImGui::GetCursorPosX() +
                    (std::max)(0.0f, statusAvailable - pillsWidth);
                ImGui::SetCursorPosX(startX);
            }

            StatusPill(engineLabel, engineColor);
            if (columns > 1) ImGui::SameLine();
            StatusPill(feedLabel, ImVec4(0.90f, 0.51f, 0.18f, 1.00f));
            if (healthLabel)
            {
                if (columns > 2) ImGui::SameLine();
                StatusPill(healthLabel, IntelligenceHealthColor(health));
            }

            const std::uint64_t shownWorkers = running ? stats.workerThreads : DisplayWorkerCount();
            const std::uint64_t shownRoots = running ? stats.rootsTotal :
                static_cast<std::uint64_t>(SelectedRootCount());
            char headerMeta[160]{};
            std::snprintf(headerMeta, sizeof(headerMeta),
                "%llu names  |  %llu workers  |  %llu roots selected",
                static_cast<unsigned long long>(feedNames),
                static_cast<unsigned long long>(shownWorkers),
                static_cast<unsigned long long>(shownRoots));
            const std::string clippedMeta = EllipsizeToWidth(headerMeta, statusAvailable);
            const float metaWidth = ImGui::CalcTextSize(clippedMeta.c_str()).x;
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() +
                (std::max)(0.0f, ImGui::GetContentRegionAvail().x - metaWidth));
            ImGui::TextDisabled("%s", clippedMeta.c_str());
            if (ImGui::IsItemHovered() && clippedMeta != headerMeta)
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted(headerMeta);
                ImGui::EndTooltip();
            }
        };

        if (horizontal && ImGui::BeginTable("header_layout", 2,
                ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoPadOuterX))
        {
            ImGui::TableSetupColumn("brand", ImGuiTableColumnFlags_WidthStretch,
                brandBlockWidth / availableWidth);
            ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch,
                pillsWidth / availableWidth);
            ImGui::TableNextColumn();
            renderBrand();
            ImGui::TableNextColumn();
            renderStatus();
            ImGui::EndTable();
        }
        else
        {
            renderBrand();
            renderStatus();
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    float FooterHeight()
    {
        return ImGui::GetTextLineHeight() + ImGui::GetStyle().WindowPadding.y;
    }

    void RenderFooter(const std::wstring& currentPath, const std::wstring& status)
    {
        const float footerHeight = FooterHeight();
        const float horizontalPadding = ImGui::GetStyle().WindowPadding.x;
        const float fontSize = ImGui::GetFontSize();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.009f, 0.010f, 0.011f, 1.00f));
        ImGui::BeginChild("status_footer", ImVec2(0.0f, footerHeight),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        const std::wstring& message = currentPath.empty() ? status : currentPath;
        const std::string fullMessage = WideToUtf8(message);

        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImVec2 position = ImGui::GetWindowPos();
        const ImVec2 size = ImGui::GetWindowSize();
        const float messageX = position.x + horizontalPadding;
        const float messageWidth = size.x - horizontalPadding * 2.0f;
        const float textY = position.y + (size.y - fontSize) * 0.5f;
        const std::string clippedMessage = EllipsizeToWidth(fullMessage, messageWidth);

        draw->PushClipRect(position, ImVec2(position.x + size.x, position.y + size.y), true);
        draw->AddText(g_fontMono, fontSize, ImVec2(messageX, textY),
            ImGui::GetColorU32(ImGuiCol_Text), clippedMessage.c_str());
        draw->PopClipRect();

        ImGui::SetCursorScreenPos(ImVec2(messageX, position.y));
        ImGui::InvisibleButton("##footer_message", ImVec2(messageWidth, size.y));
        if (ImGui::IsItemHovered() && clippedMessage != fullMessage)
        {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ViewportWidth(0.55f));
            ImGui::TextUnformatted(fullMessage.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    void RenderMainWindow()
    {
        JoinCompletedWorker();

        ScanStats stats;
        std::vector<Finding> findings;
        std::vector<PackageRecord> packages;
        FeedSyncResult feedSync;
        std::wstring status;
        std::wstring currentPath;
        std::size_t feedNames = 0;
        std::size_t feedPairs = 0;
        std::size_t activeHashIndicators = 0;
        bool cancelled = false;
        bool openCompletionNotification = false;
        std::uint64_t completionCriticalCount = 0;
        std::uint64_t completionHighCount = 0;
        std::uint64_t completionMediumCount = 0;
        std::uint64_t completionCoverageIssues = 0;
        const bool running = g_app.running.load(std::memory_order_acquire);

        {
            std::lock_guard lock(g_app.dataMutex);
            stats = g_app.stats;
            findings = g_app.findings;
            packages = running ? g_app.packagePreview : g_app.packages;
            feedSync = g_app.feedSync;
            status = g_app.status;
            currentPath = g_app.currentPath;
            feedNames = g_app.feedNames;
            feedPairs = g_app.feedPairs;
            activeHashIndicators = g_app.activeHashIndicators;
            cancelled = g_app.lastCancelled;
            // Keep the verdict snapshot stable for every frame while the modal is open.
            completionCriticalCount = g_app.completionCriticalCount;
            completionHighCount = g_app.completionHighCount;
            completionMediumCount = g_app.completionMediumCount;
            completionCoverageIssues = g_app.completionCoverageIssues;
            if (!running && g_app.completionNotificationPending)
            {
                openCompletionNotification = true;
                g_app.completionNotificationPending = false;
            }
        }

        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImGui::GetStyle().ItemSpacing);
        ImGui::Begin("ShaiHuludRoot", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        ImGui::PopStyleVar();

        DrawBackgroundGrid(ImGui::GetWindowPos(),
            ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth(),
                ImGui::GetWindowPos().y + ImGui::GetWindowHeight()));
        RenderTopHeader(running, stats, feedNames, feedPairs, feedSync);

        // Keep the footer visibly above the client edge. The reserved region includes
        // the footer itself, the item gap, and a small bottom inset for DPI rounding.
        const float footerReservedHeight = FooterHeight() + ImGui::GetStyle().ItemSpacing.y;
        const float bodyHeight = (std::max)(1.0f,
            ImGui::GetContentRegionAvail().y - footerReservedHeight);
        ImGui::BeginChild("application_body",
            ImVec2(0.0f, bodyHeight),
            ImGuiChildFlags_None,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        const float availableBodyWidth = ImGui::GetContentRegionAvail().x;
        const float navigationWidth = NavigationWidth();
        const bool useSideNavigation = availableBodyWidth >=
            navigationWidth + MinimumWorkspaceWidth() + ImGui::GetStyle().ItemSpacing.x;
        if (useSideNavigation)
        {
            RenderNavigation(running, feedNames, feedPairs, stats);
            ImGui::SameLine();
        }
        else
        {
            RenderCompactNavigation(running, feedNames, feedPairs, stats);
        }

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.012f, 0.012f, 0.013f, 0.98f));
        const ImGuiWindowFlags workspaceFlags = ImGuiWindowFlags_None;
        ImGui::BeginChild("workspace_content", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders,
            workspaceFlags);
        switch (g_app.activePage)
        {
        case PageTargets:
            RenderTargetsPage(running);
            break;
        case PageDetection:
            RenderDetectionPage(running, activeHashIndicators);
            break;
        case PageFindings:
            RenderFindingsPage(std::move(findings));
            break;
        case PageInventory:
            RenderInventoryPage(packages, running);
            break;
        case PageThreatIntel:
            RenderThreatIntelPage(feedSync, feedNames, feedPairs);
            break;
        case PagePerformance:
            RenderPerformancePage(stats, running);
            break;
        case PageCoverage:
            RenderCoveragePage(stats);
            break;
        default:
            RenderOverviewPage(stats, findings, status, currentPath, running,
                cancelled, feedNames, feedPairs, feedSync);
            break;
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::EndChild();

        RenderFooter(currentPath, status);
        ImGui::End();

        RenderScanCompletionNotification(
            viewport,
            openCompletionNotification,
            completionCriticalCount,
            completionHighCount,
            completionMediumCount,
            completionCoverageIssues);
    }

    bool DebugModeRequested()
    {
        int argumentCount = 0;
        wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
        if (!arguments)
            return false;

        bool enabled = false;
        for (int index = 1; index < argumentCount; ++index)
        {
            if (_wcsicmp(arguments[index], L"--debug") == 0)
            {
                enabled = true;
                break;
            }
        }
        LocalFree(arguments);
        return enabled;
    }

    void CreateRenderTarget()
    {
        ID3D11Texture2D* backBuffer = nullptr;
        if (SUCCEEDED(g_swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
        {
            g_device->CreateRenderTargetView(backBuffer, nullptr, &g_renderTargetView);
            backBuffer->Release();
        }
    }

    void CleanupRenderTarget()
    {
        if (g_renderTargetView)
        {
            g_renderTargetView->Release();
            g_renderTargetView = nullptr;
        }
    }

    bool CreateDeviceD3D(HWND window)
    {
        DXGI_SWAP_CHAIN_DESC description{};
        description.BufferCount = 2;
        description.BufferDesc.Width = 0;
        description.BufferDesc.Height = 0;
        description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        description.BufferDesc.RefreshRate.Numerator = 60;
        description.BufferDesc.RefreshRate.Denominator = 1;
        description.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        description.OutputWindow = window;
        description.SampleDesc.Count = 1;
        description.SampleDesc.Quality = 0;
        description.Windowed = TRUE;
        description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        const D3D_FEATURE_LEVEL levels[] =
            {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
        D3D_FEATURE_LEVEL createdLevel{};
        HRESULT result = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            levels, static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
            &description, &g_swapChain, &g_device, &createdLevel, &g_deviceContext);
        if (result == DXGI_ERROR_UNSUPPORTED)
        {
            result = D3D11CreateDeviceAndSwapChain(
                nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
                levels, static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
                &description, &g_swapChain, &g_device, &createdLevel, &g_deviceContext);
        }
        if (FAILED(result))
            return false;

        CreateRenderTarget();
        return true;
    }

    void CleanupDeviceD3D()
    {
        CleanupRenderTarget();
        if (g_swapChain) { g_swapChain->Release(); g_swapChain = nullptr; }
        if (g_deviceContext) { g_deviceContext->Release(); g_deviceContext = nullptr; }
        if (g_device) { g_device->Release(); g_device = nullptr; }
    }

    LRESULT WINAPI WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam))
            return true;

        switch (message)
        {
        case WM_SIZE:
            if (g_device != nullptr && wParam != SIZE_MINIMIZED)
            {
                CleanupRenderTarget();
                g_swapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam),
                    DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
        }
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int)
{
    const std::filesystem::path executableDirectory = ExecutableDirectory();
    const bool debugMode = DebugModeRequested();
    if (debugMode)
    {
        DebugLog::Initialize(executableDirectory, true);
        DebugLog::Write("SYSTEM", L"Application startup. Executable directory: " + executableDirectory.wstring());
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_CLASSDC;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SHAIHULUD_APP));
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.lpszClassName = kWindowClass;
    windowClass.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_SHAIHULUD_APP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
    if (!windowClass.hIcon) windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    if (!windowClass.hIconSm) windowClass.hIconSm = windowClass.hIcon;
    RegisterClassExW(&windowClass);

    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    GetMonitorInfoW(MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY), &monitorInfo);
    const LONG workWidth = monitorInfo.rcWork.right - monitorInfo.rcWork.left;
    const LONG workHeight = monitorInfo.rcWork.bottom - monitorInfo.rcWork.top;
    const int initialWidth = static_cast<int>(static_cast<float>(workWidth) * 0.86f);
    const int initialHeight = static_cast<int>(static_cast<float>(workHeight) * 0.86f);
    const int initialX = monitorInfo.rcWork.left + (workWidth - initialWidth) / 2;
    const int initialY = monitorInfo.rcWork.top + (workHeight - initialHeight) / 2;

    HWND window = CreateWindowW(
        windowClass.lpszClassName, kWindowTitle,
        WS_OVERLAPPEDWINDOW, initialX, initialY, initialWidth, initialHeight,
        nullptr, nullptr, windowClass.hInstance, nullptr);

    SendMessageW(window, WM_SETICON, ICON_BIG,
        reinterpret_cast<LPARAM>(windowClass.hIcon));
    SendMessageW(window, WM_SETICON, ICON_SMALL,
        reinterpret_cast<LPARAM>(windowClass.hIconSm));

    BOOL darkTitle = TRUE;
    DwmSetWindowAttribute(window, 20, &darkTitle, sizeof(darkTitle));

    if (!CreateDeviceD3D(window))
    {
        CleanupDeviceD3D();
        UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
        MessageBoxW(nullptr, L"Could not initialize DirectX 11.",
            L"Shai-Hulud 2.0 Scanner", MB_OK | MB_ICONERROR);
        DebugLog::Write("SYSTEM", L"DirectX 11 initialization failed. Application is exiting.");
        CoUninitialize();
        DebugLog::Shutdown();
        return 1;
    }

    ShowWindow(window, SW_SHOWDEFAULT);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    LoadApplicationFonts(io);
    ApplyTheme();

    // The live responsive pass derives all geometry from DisplaySize. DPI is
    // applied to fonts only; style geometry is rebuilt every frame in the same
    // coordinate space and therefore must not be integer-scaled here.
    const float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(window);
    if (dpiScale > 0.0f)
        ImGui::GetStyle().FontScaleDpi = dpiScale;
    g_baseStyle = ImGui::GetStyle();

    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(g_device, g_deviceContext);

    SetBuffer(g_app.excludedNames, "$Recycle.Bin;System Volume Information");
    RefreshDrives();
    {
        FeedSyncResult initial = FeedUpdater::Sync(
            ExecutableDirectory(), g_app.database, false);
        MergeExternalHashDatabase(g_app.database);
        std::lock_guard lock(g_app.dataMutex);
        g_app.feedSync = std::move(initial);
        g_app.feedNames = g_app.database.PackageCount();
        g_app.feedPairs = g_app.database.PairCount();
        g_app.activeHashIndicators = g_app.database.HashIndicatorCount();
        g_app.status = L"Ready. Select scan targets and detection policy, then start the assessment.";
    }

    bool done = false;
    while (!done)
    {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        UpdateResponsiveLayout();
        ImGui::NewFrame();
        RenderMainWindow();
        ImGui::Render();

        const float clearColor[4] = {0.006f, 0.005f, 0.004f, 1.00f};
        g_deviceContext->OMSetRenderTargets(1, &g_renderTargetView, nullptr);
        g_deviceContext->ClearRenderTargetView(g_renderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapChain->Present(1, 0);
    }

    g_app.cancelRequested.store(true, std::memory_order_release);
    if (g_app.worker.joinable())
        g_app.worker.join();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(window);
    UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
    CoUninitialize();
    DebugLog::Write("SYSTEM", L"Application shutdown completed.");
    DebugLog::Shutdown();
    return 0;
}
