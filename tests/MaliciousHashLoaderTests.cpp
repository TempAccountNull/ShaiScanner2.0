#include "MaliciousHashLoader.h"

#include <filesystem>
#include <fstream>
#include <iostream>

int main(int argc, char** argv)
{
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "shaihulud-malicious-hash-test.json";
    {
        std::ofstream output(path, std::ios::binary);
        output << R"({
  "schema_version": 1,
  "hashes": [
    {
      "algorithm": "SHA-256",
      "digest": "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668",
      "description": "test loader",
      "campaign": "test campaign",
      "filenames": ["setup.mjs"]
    },
    {
      "algorithm": "sha1",
      "hash": "d1829b4708126dcc7bea7437c04d1f10eacd4a16",
      "description": "test sha1"
    },
    {
      "algorithm": "md5",
      "digest": "00000000000000000000000000000000"
    }
  ]
})";
    }

    MaliciousHashLoadResult result;
    std::string error;
    const bool loaded = LoadMaliciousHashesJson(path, result, error);
    std::error_code ec;
    std::filesystem::remove(path, ec);

    if (!loaded)
    {
        std::cerr << error << '\n';
        return 1;
    }
    if (result.records.size() != 2 || result.skippedEntries != 1)
        return 2;
    if (result.records[0].algorithm != "SHA256" ||
        result.records[0].campaign != "test campaign" ||
        result.records[0].filenames.size() != 1 ||
        result.records[0].filenames[0] != "setup.mjs")
        return 3;
    if (result.records[1].algorithm != "SHA1")
        return 4;

    if (argc > 1)
    {
        MaliciousHashLoadResult shipped;
        std::string shippedError;
        if (!LoadMaliciousHashesJson(argv[1], shipped, shippedError))
        {
            std::cerr << shippedError << '\n';
            return 5;
        }
        if (shipped.records.size() < 65 || shipped.skippedEntries != 0)
            return 6;
        const auto& finalEntry = shipped.records.back();
        if (finalEntry.algorithm != "SHA1" ||
            finalEntry.digest != "92a88981f1594c193bb66040e9c1782a6ce22cf6" ||
            finalEntry.filenames.size() != 1 ||
            finalEntry.filenames[0] != "testfile.js")
            return 7;
    }

    std::cout << "MaliciousHashLoaderTests passed\n";
    return 0;
}
