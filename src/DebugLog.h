#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace DebugLog
{
    // Starts a fresh diagnostic session. Production startup does not call this
    // unless the user explicitly launches the scanner with --debug. When
    // enabled, the logger writes debug.log and mirrors trace lines to a Win32
    // console window. Safe to call once at process startup.
    bool Initialize(
        const std::filesystem::path& executableDirectory,
        bool showConsole = true);

    void Shutdown();
    void Flush();

    void Write(const char* component, const std::wstring& message);
    void Write(const char* component, const std::string& message);

    // Writes the complete payload to debug.log and also saves an exact copy
    // beside the log. The console receives only a one-line summary so it
    // remains usable while the file preserves all response content.
    void WriteBlob(
        const char* component,
        const std::wstring& label,
        const std::vector<unsigned char>& bytes,
        const std::wstring& artifactFileName = L"");

    std::filesystem::path LogPath();
    std::filesystem::path LogDirectory();
    std::wstring FormatWin32Error(unsigned long errorCode);
}
