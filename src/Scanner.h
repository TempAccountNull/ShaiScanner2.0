#pragma once

#include "Indicators.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

enum class Severity
{
    Info = 0,
    Low,
    Medium,
    High,
    Critical
};

struct Finding
{
    Severity severity = Severity::Info;
    std::wstring type;
    std::wstring ecosystem;
    std::wstring indicator;
    std::wstring version;
    std::wstring path;
    std::wstring details;
};

struct PackageRecord
{
    std::wstring ecosystem;
    std::wstring name;
    std::wstring version;
    std::wstring path;
    bool affected = false;
};

struct ScanStats
{
    std::uint64_t directoriesVisited = 0;
    std::uint64_t filesVisited = 0;
    std::uint64_t npmManifests = 0;
    std::uint64_t pythonMetadataFiles = 0;
    std::uint64_t packagesInventoried = 0;
    std::uint64_t npmLockfiles = 0;
    std::uint64_t pythonLockfiles = 0;
    std::uint64_t goDependencyFiles = 0;
    std::uint64_t behaviorFiles = 0;
    std::uint64_t hashesCalculated = 0;
    std::uint64_t deepHashedScripts = 0;
    std::uint64_t skippedReparsePoints = 0;
    std::uint64_t accessDenied = 0;
    std::uint64_t errors = 0;
    std::uint64_t findings = 0;
    std::uint64_t filesQueued = 0;
    std::uint64_t rootsCompleted = 0;
    std::uint64_t rootsTotal = 0;
    std::uint64_t workerThreads = 0;
    std::uint64_t activeWorkers = 0;
    std::uint64_t peakQueueDepth = 0;
};

struct ScanOptions
{
    std::vector<std::filesystem::path> roots;

    bool scanNpmPackages = true;
    bool scanNpmLockfiles = true;
    bool scanPythonPackages = true;
    bool scanPythonLockfiles = true;
    bool scanGoDependencies = true;
    bool scanPackageCaches = true;
    bool scanKnownArtifacts = true;
    bool scanBehaviorVariants = true;
    bool scanEditorPersistence = true;
    bool deepHashPackageScripts = false;
    bool createPackageInventory = true;
    bool skipWindowsDirectory = false;
    bool followReparsePoints = false;

    // 0 selects an automatic bounded worker count.
    std::uint32_t workerThreads = 0;
    std::size_t queueCapacity = 8192;

    std::vector<std::wstring> includePathTokens;
    std::vector<std::wstring> excludedDirectoryNames;

    std::uintmax_t maxTextFileBytes = 8ull * 1024ull * 1024ull;
    std::uintmax_t maxLockfileBytes = 128ull * 1024ull * 1024ull;
};

struct TextSearchEntry
{
    std::string ecosystem;
    std::string name;
    std::vector<std::string> versions;
};

struct DynamicHashIndicator
{
    std::wstring algorithm;
    std::wstring digest;
    std::wstring description;
    std::vector<std::wstring> filenames;
};

struct DynamicTextIndicator
{
    std::wstring category;
    std::wstring value;
    std::wstring description;
    bool highConfidence = false;
};

class IndicatorDatabase
{
public:
    IndicatorDatabase();

    void Clear();
    void ResetToBuiltIn(std::uint32_t sourceMask = BuiltInAllFeeds);
    void AddBuiltIn(std::uint32_t sourceMask);

    bool MergeCsv(
        const std::filesystem::path& csvPath,
        std::wstring& error,
        std::size_t* addedPairs = nullptr,
        std::size_t* parsedRows = nullptr);

    bool MergeMaliciousHashesJson(
        const std::filesystem::path& jsonPath,
        std::wstring& message,
        std::size_t* loadedEntries = nullptr,
        std::size_t* addedEntries = nullptr,
        std::size_t* skippedEntries = nullptr);

    bool IsAffected(
        const std::wstring& ecosystem,
        const std::wstring& name,
        const std::wstring& version) const;

    std::size_t PairCount() const noexcept;
    std::size_t PackageCount() const noexcept;

    const std::vector<TextSearchEntry>& TextEntries() const noexcept;
    const std::vector<DynamicHashIndicator>& HashIndicators() const noexcept;
    const std::vector<DynamicTextIndicator>& TextIndicators() const noexcept;
    bool ShouldHashFileName(const std::wstring& lowerFileName) const noexcept;
    std::size_t HashIndicatorCount() const noexcept;

private:
    void AddPackage(
        const std::wstring& ecosystem,
        const std::wstring& name,
        const std::wstring& version);
    void AddHash(
        const std::wstring& algorithm,
        const std::wstring& digest,
        const std::wstring& description,
        const std::vector<std::wstring>& filenames = {});
    void AddTextIndicator(
        const std::wstring& category,
        const std::wstring& value,
        const std::wstring& description,
        bool highConfidence);
    void RebuildTextEntries();

    // ecosystem -> package -> versions
    std::unordered_map<
        std::wstring,
        std::unordered_map<std::wstring, std::unordered_set<std::wstring>>> affected_;
    std::vector<TextSearchEntry> textEntries_;
    std::vector<DynamicHashIndicator> hashIndicators_;
    std::vector<DynamicTextIndicator> textIndicators_;
    std::unordered_set<std::wstring> hashKeys_;
    std::unordered_set<std::wstring> hashTargetNames_;
    std::unordered_set<std::wstring> textKeys_;
    std::size_t pairCount_ = 0;
};

class Scanner
{
public:
    using FindingCallback = std::function<void(const Finding&)>;
    using PackageCallback = std::function<void(const PackageRecord&)>;
    using ProgressCallback = std::function<void(const ScanStats&, const std::wstring&)>;
    using CompletedCallback = std::function<void(const ScanStats&, bool cancelled)>;

    explicit Scanner(const IndicatorDatabase& database);

    void Run(
        const ScanOptions& options,
        std::atomic_bool& cancelRequested,
        FindingCallback onFinding,
        PackageCallback onPackage,
        ProgressCallback onProgress,
        CompletedCallback onCompleted);

private:
    const IndicatorDatabase& database_;
};
