#pragma once
#include <cstddef>
#include <cstdint>

enum BuiltInFeedSource : std::uint32_t
{
    BuiltInSocket = 0x1,
    BuiltInSafeDep = 0x2,
    BuiltInWiz = 0x4,
    BuiltInDatadog = 0x8,
    BuiltInStepSecurity = 0x10,
    BuiltInJFrog = 0x20,
    BuiltInCommunityAggregate = 0x40,
    BuiltInAllFeeds = BuiltInSocket | BuiltInSafeDep | BuiltInWiz |
        BuiltInDatadog | BuiltInStepSecurity | BuiltInJFrog |
        BuiltInCommunityAggregate
};

struct PackageIndicator
{
    const wchar_t* ecosystem;
    const wchar_t* name;
    const wchar_t* version;
    std::uint32_t sourceMask;
};

struct HashIndicator
{
    const wchar_t* algorithm;
    const wchar_t* digest;
    const wchar_t* description;
};

struct TextIndicator
{
    const wchar_t* category;
    const wchar_t* value;
    const wchar_t* description;
    bool highConfidence;
};

extern const PackageIndicator kAffectedPackages[];
extern const std::size_t kAffectedPackageCount;

extern const HashIndicator kKnownHashes[];
extern const std::size_t kKnownHashCount;

extern const TextIndicator kKnownTextIndicators[];
extern const std::size_t kKnownTextIndicatorCount;
