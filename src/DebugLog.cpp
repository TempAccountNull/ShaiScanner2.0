#include "DebugLog.h"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace
{
    std::mutex g_logMutex;
    std::ofstream g_log;
    std::filesystem::path g_logPath;
    std::filesystem::path g_logDirectory;
    bool g_consoleReady = false;
    bool g_initialized = false;

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};

        const int count = WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        if (count <= 0)
            return {};

        std::string output(static_cast<std::size_t>(count), '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            output.data(), count, nullptr, nullptr);
        return output;
    }

    std::string Timestamp()
    {
        SYSTEMTIME time{};
        GetLocalTime(&time);

        char buffer[64]{};
        std::snprintf(
            buffer, sizeof(buffer),
            "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
        return buffer;
    }

    std::string Prefix(const char* component)
    {
        std::ostringstream output;
        output << '[' << Timestamp() << "]"
               << " [T" << GetCurrentThreadId() << ']'
               << " [" << (component ? component : "GENERAL") << "] ";
        return output.str();
    }

    bool OpenLogAt(const std::filesystem::path& directory)
    {
        std::error_code error;
        std::filesystem::create_directories(directory, error);
        if (error)
            return false;

        const auto path = directory / L"debug.log";
        const auto previous = directory / L"debug.previous.log";
        if (std::filesystem::exists(path, error) && !error)
        {
            std::filesystem::remove(previous, error);
            error.clear();
            std::filesystem::rename(path, previous, error);
            error.clear();
        }

        g_log.clear();
        g_log.open(path, std::ios::binary | std::ios::trunc);
        if (!g_log)
            return false;

        g_logPath = path;
        g_logDirectory = directory;
        return true;
    }

    void MirrorToConsole(const std::string& line)
    {
        if (!g_consoleReady)
            return;

        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fwrite("\n", 1, 1, stdout);
        std::fflush(stdout);
    }
}

bool DebugLog::Initialize(
    const std::filesystem::path& executableDirectory,
    bool showConsole)
{
    std::lock_guard lock(g_logMutex);
    if (g_initialized)
        return static_cast<bool>(g_log);

    if (showConsole)
    {
        bool allocatedNewConsole = false;
        bool consoleAvailable = GetConsoleWindow() != nullptr;
        if (!consoleAvailable)
            consoleAvailable = AttachConsole(ATTACH_PARENT_PROCESS) != FALSE;
        if (!consoleAvailable)
        {
            allocatedNewConsole = AllocConsole() != FALSE;
            consoleAvailable = allocatedNewConsole;
        }

        if (consoleAvailable)
        {
            FILE* stream = nullptr;
            freopen_s(&stream, "CONOUT$", "w", stdout);
            freopen_s(&stream, "CONOUT$", "w", stderr);
            freopen_s(&stream, "CONIN$", "r", stdin);
            SetConsoleOutputCP(CP_UTF8);
            SetConsoleCP(CP_UTF8);
            SetConsoleTitleW(L"Shai-Hulud 2.0 Scanner - Diagnostic Console");
            g_consoleReady = true;

            // Prevent the close button on a console created by this process from
            // terminating the GUI. Do not alter a parent developer console.
            if (allocatedNewConsole)
            {
                if (HWND console = GetConsoleWindow())
                {
                    if (HMENU menu = GetSystemMenu(console, FALSE))
                    {
                        DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
                        DrawMenuBar(console);
                    }
                }
            }
        }
    }

    bool opened = OpenLogAt(executableDirectory);
    if (!opened)
    {
        wchar_t temporary[MAX_PATH]{};
        const DWORD length = GetTempPathW(MAX_PATH, temporary);
        if (length > 0 && length < MAX_PATH)
        {
            opened = OpenLogAt(
                std::filesystem::path(temporary) / L"ShaiHulud2Scanner");
        }
    }

    g_initialized = true;

    if (opened)
    {
        const std::string header =
            "============================================================\n"
            "Shai-Hulud 2.0 Scanner diagnostic session\n"
            "Version: 1.7.6\n"
            "The complete StepSecurity request, response, parser trace,\n"
            "validation decisions, and fallback selection are recorded here.\n"
            "============================================================\n";
        g_log.write(header.data(), static_cast<std::streamsize>(header.size()));
        g_log.flush();
    }

    const std::string consoleMessage = opened
        ? "Diagnostic logging enabled: " + WideToUtf8(g_logPath.wstring())
        : "WARNING: debug.log could not be created.";
    MirrorToConsole(consoleMessage);
    return opened;
}

void DebugLog::Shutdown()
{
    std::lock_guard lock(g_logMutex);
    if (!g_initialized)
        return;
    if (g_log)
    {
        const std::string line = Prefix("SYSTEM") + "Diagnostic session ended.\n";
        g_log.write(line.data(), static_cast<std::streamsize>(line.size()));
        g_log.flush();
        g_log.close();
    }
    g_initialized = false;
}

void DebugLog::Flush()
{
    std::lock_guard lock(g_logMutex);
    if (!g_initialized)
        return;
    if (g_log)
        g_log.flush();
}

void DebugLog::Write(const char* component, const std::wstring& message)
{
    Write(component, WideToUtf8(message));
}

void DebugLog::Write(const char* component, const std::string& message)
{
    std::lock_guard lock(g_logMutex);
    if (!g_initialized)
        return;
    const std::string line = Prefix(component) + message;

    if (g_log)
    {
        g_log.write(line.data(), static_cast<std::streamsize>(line.size()));
        g_log.write("\n", 1);
        g_log.flush();
    }
    MirrorToConsole(line);
}

void DebugLog::WriteBlob(
    const char* component,
    const std::wstring& label,
    const std::vector<unsigned char>& bytes,
    const std::wstring& artifactFileName)
{
    std::lock_guard lock(g_logMutex);
    if (!g_initialized)
        return;

    const std::string labelUtf8 = WideToUtf8(label);
    const std::string begin = Prefix(component) +
        "BEGIN FULL CONTENT: " + labelUtf8 +
        " (" + std::to_string(bytes.size()) + " bytes)\n";
    const std::string end = "\n" + Prefix(component) +
        "END FULL CONTENT: " + labelUtf8 + "\n";

    if (g_log)
    {
        g_log.write(begin.data(), static_cast<std::streamsize>(begin.size()));
        if (!bytes.empty())
        {
            g_log.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        }
        g_log.write(end.data(), static_cast<std::streamsize>(end.size()));
        g_log.flush();
    }

    MirrorToConsole(Prefix(component) + "Captured full content: " +
        labelUtf8 + " (" + std::to_string(bytes.size()) + " bytes)");

    if (!artifactFileName.empty() && !g_logDirectory.empty())
    {
        const auto artifactPath = g_logDirectory / artifactFileName;
        std::ofstream artifact(artifactPath, std::ios::binary | std::ios::trunc);
        if (artifact)
        {
            if (!bytes.empty())
            {
                artifact.write(
                    reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
            }
            artifact.flush();

            const std::string saved = Prefix(component) +
                "Saved exact response copy: " +
                WideToUtf8(artifactPath.wstring());
            if (g_log)
            {
                g_log.write(saved.data(), static_cast<std::streamsize>(saved.size()));
                g_log.write("\n", 1);
                g_log.flush();
            }
            MirrorToConsole(saved);
        }
    }
}

std::filesystem::path DebugLog::LogPath()
{
    std::lock_guard lock(g_logMutex);
    return g_logPath;
}

std::filesystem::path DebugLog::LogDirectory()
{
    std::lock_guard lock(g_logMutex);
    return g_logDirectory;
}

std::wstring DebugLog::FormatWin32Error(unsigned long errorCode)
{
    if (errorCode == ERROR_SUCCESS)
        return L"The operation completed successfully.";

    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&buffer),
        0,
        nullptr);

    std::wstring message;
    if (length > 0 && buffer)
        message.assign(buffer, length);
    else
        message = L"No system error text was available.";

    if (buffer)
        LocalFree(buffer);

    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' ||
            message.back() == L' ' || message.back() == L'\t'))
    {
        message.pop_back();
    }
    return message;
}
