#pragma once

#include "Scanner.h"

#include <filesystem>
#include <string>
#include <vector>

enum class FeedStateKind
{
    Current,
    Updated,
    AdvisoryCurrent,
    Updating,
    OfflineCached,
    OfflineBundled,
    RejectedCached,
    RejectedBundled,
    EmbeddedFallback,
    Unavailable
};

struct FeedStatus
{
    std::wstring name;
    std::wstring url;
    std::wstring source;
    std::wstring sha256;
    std::wstring state;
    std::wstring detail;
    FeedStateKind kind = FeedStateKind::Current;
    bool online = false;
    bool onlineFailure = false;
    bool notModified = false;
    bool updated = false;
    bool loaded = false;
    bool usedBuiltInFallback = false;
    bool usedBundledFallback = false;
    std::size_t loadedRows = 0;
    std::size_t loadedPairs = 0;
    std::size_t addedPairs = 0;
    bool validationFailed = false;
};

struct FeedSyncResult
{
    std::vector<FeedStatus> feeds;
    std::wstring summary;
    std::wstring healthSummary;
    bool anyOnlineFailure = false;
    bool anyValidationFailure = false;
};

class FeedUpdater
{
public:
    // refreshOnline performs a conditional GET. A valid ETag or Last-Modified
    // response prevents the response body from being downloaded when unchanged.
    static FeedSyncResult Sync(
        const std::filesystem::path& executableDirectory,
        IndicatorDatabase& database,
        bool refreshOnline);
};
