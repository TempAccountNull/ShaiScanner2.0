#pragma once

#include <filesystem>
#include <string>
#include <vector>

struct MaliciousHashRecord
{
    std::string algorithm;
    std::string digest;
    std::string description;
    std::string campaign;
    std::string source;
    std::vector<std::string> filenames;
};

struct MaliciousHashLoadResult
{
    std::vector<MaliciousHashRecord> records;
    std::vector<std::string> warnings;
    std::size_t declaredEntries = 0;
    std::size_t skippedEntries = 0;
};

bool LoadMaliciousHashesJson(
    const std::filesystem::path& path,
    MaliciousHashLoadResult& result,
    std::string& error);
