#include "MaliciousHashLoader.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <variant>

namespace
{
    struct JsonValue
    {
        using Object = std::map<std::string, JsonValue>;
        using Array = std::vector<JsonValue>;
        using Storage = std::variant<std::nullptr_t, bool, double, std::string, Object, Array>;
        Storage value = nullptr;

        const Object* AsObject() const { return std::get_if<Object>(&value); }
        const Array* AsArray() const { return std::get_if<Array>(&value); }
        const std::string* AsString() const { return std::get_if<std::string>(&value); }
        const bool* AsBool() const { return std::get_if<bool>(&value); }
    };

    void AppendUtf8(std::string& output, unsigned int codePoint)
    {
        if (codePoint <= 0x7F)
        {
            output.push_back(static_cast<char>(codePoint));
        }
        else if (codePoint <= 0x7FF)
        {
            output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0xFFFF)
        {
            output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else
        {
            output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    class Parser
    {
    public:
        explicit Parser(std::string_view input) : input_(input) {}

        bool Parse(JsonValue& output, std::string& error)
        {
            SkipWhitespace();
            if (!ParseValue(output, error))
                return false;
            SkipWhitespace();
            if (position_ != input_.size())
            {
                error = Error("unexpected trailing data");
                return false;
            }
            return true;
        }

    private:
        std::string Error(const std::string& message) const
        {
            return message + " at byte " + std::to_string(position_);
        }

        void SkipWhitespace()
        {
            while (position_ < input_.size() &&
                std::isspace(static_cast<unsigned char>(input_[position_])))
                ++position_;
        }

        bool Consume(char expected)
        {
            SkipWhitespace();
            if (position_ >= input_.size() || input_[position_] != expected)
                return false;
            ++position_;
            return true;
        }

        bool ParseValue(JsonValue& output, std::string& error)
        {
            SkipWhitespace();
            if (position_ >= input_.size())
            {
                error = Error("unexpected end of input");
                return false;
            }

            const char ch = input_[position_];
            if (ch == '{') return ParseObject(output, error);
            if (ch == '[') return ParseArray(output, error);
            if (ch == '"')
            {
                std::string value;
                if (!ParseString(value, error)) return false;
                output.value = std::move(value);
                return true;
            }
            if (ch == 't' && MatchLiteral("true"))
            {
                output.value = true;
                return true;
            }
            if (ch == 'f' && MatchLiteral("false"))
            {
                output.value = false;
                return true;
            }
            if (ch == 'n' && MatchLiteral("null"))
            {
                output.value = nullptr;
                return true;
            }
            if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)))
                return ParseNumber(output, error);

            error = Error("unexpected token");
            return false;
        }

        bool MatchLiteral(std::string_view literal)
        {
            if (input_.substr(position_, literal.size()) != literal)
                return false;
            position_ += literal.size();
            return true;
        }

        bool ParseObject(JsonValue& output, std::string& error)
        {
            if (!Consume('{'))
            {
                error = Error("expected object");
                return false;
            }
            JsonValue::Object object;
            SkipWhitespace();
            if (Consume('}'))
            {
                output.value = std::move(object);
                return true;
            }

            for (;;)
            {
                std::string key;
                if (!ParseString(key, error)) return false;
                if (!Consume(':'))
                {
                    error = Error("expected ':' after object key");
                    return false;
                }
                JsonValue value;
                if (!ParseValue(value, error)) return false;
                object[std::move(key)] = std::move(value);

                if (Consume('}')) break;
                if (!Consume(','))
                {
                    error = Error("expected ',' or '}' in object");
                    return false;
                }
            }
            output.value = std::move(object);
            return true;
        }

        bool ParseArray(JsonValue& output, std::string& error)
        {
            if (!Consume('['))
            {
                error = Error("expected array");
                return false;
            }
            JsonValue::Array array;
            SkipWhitespace();
            if (Consume(']'))
            {
                output.value = std::move(array);
                return true;
            }

            for (;;)
            {
                JsonValue value;
                if (!ParseValue(value, error)) return false;
                array.push_back(std::move(value));
                if (Consume(']')) break;
                if (!Consume(','))
                {
                    error = Error("expected ',' or ']' in array");
                    return false;
                }
            }
            output.value = std::move(array);
            return true;
        }

        bool ParseString(std::string& output, std::string& error)
        {
            SkipWhitespace();
            if (position_ >= input_.size() || input_[position_] != '"')
            {
                error = Error("expected string");
                return false;
            }
            ++position_;
            output.clear();

            while (position_ < input_.size())
            {
                const unsigned char ch = static_cast<unsigned char>(input_[position_++]);
                if (ch == '"') return true;
                if (ch < 0x20)
                {
                    error = Error("control character in string");
                    return false;
                }
                if (ch != '\\')
                {
                    output.push_back(static_cast<char>(ch));
                    continue;
                }

                if (position_ >= input_.size())
                {
                    error = Error("unterminated escape sequence");
                    return false;
                }
                const char escaped = input_[position_++];
                switch (escaped)
                {
                case '"': output.push_back('"'); break;
                case '\\': output.push_back('\\'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u':
                {
                    if (position_ + 4 > input_.size())
                    {
                        error = Error("truncated Unicode escape");
                        return false;
                    }
                    unsigned int codePoint = 0;
                    for (int i = 0; i < 4; ++i)
                    {
                        const char hex = input_[position_++];
                        codePoint <<= 4;
                        if (hex >= '0' && hex <= '9') codePoint |= hex - '0';
                        else if (hex >= 'a' && hex <= 'f') codePoint |= 10 + hex - 'a';
                        else if (hex >= 'A' && hex <= 'F') codePoint |= 10 + hex - 'A';
                        else
                        {
                            error = Error("invalid Unicode escape");
                            return false;
                        }
                    }
                    AppendUtf8(output, codePoint);
                    break;
                }
                default:
                    error = Error("invalid escape sequence");
                    return false;
                }
            }
            error = Error("unterminated string");
            return false;
        }

        bool ParseNumber(JsonValue& output, std::string& error)
        {
            const std::size_t start = position_;
            if (input_[position_] == '-') ++position_;
            while (position_ < input_.size() &&
                std::isdigit(static_cast<unsigned char>(input_[position_])))
                ++position_;
            if (position_ < input_.size() && input_[position_] == '.')
            {
                ++position_;
                while (position_ < input_.size() &&
                    std::isdigit(static_cast<unsigned char>(input_[position_])))
                    ++position_;
            }
            if (position_ < input_.size() &&
                (input_[position_] == 'e' || input_[position_] == 'E'))
            {
                ++position_;
                if (position_ < input_.size() &&
                    (input_[position_] == '+' || input_[position_] == '-'))
                    ++position_;
                while (position_ < input_.size() &&
                    std::isdigit(static_cast<unsigned char>(input_[position_])))
                    ++position_;
            }

            try
            {
                output.value = std::stod(std::string(input_.substr(start, position_ - start)));
                return true;
            }
            catch (...)
            {
                error = Error("invalid number");
                return false;
            }
        }

        std::string_view input_;
        std::size_t position_ = 0;
    };

    std::string Lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    }

    std::string NormalizeAlgorithm(std::string value)
    {
        value = Lower(std::move(value));
        value.erase(std::remove_if(value.begin(), value.end(),
            [](unsigned char ch) { return ch == '-' || ch == '_' || std::isspace(ch); }),
            value.end());
        if (value == "sha256") return "SHA256";
        if (value == "sha1") return "SHA1";
        return {};
    }

    std::string NormalizeDigest(std::string value)
    {
        value = Lower(std::move(value));
        value.erase(std::remove_if(value.begin(), value.end(),
            [](unsigned char ch) { return std::isspace(ch); }), value.end());
        return value;
    }

    bool IsHexDigest(const std::string& value, std::size_t expectedLength)
    {
        return value.size() == expectedLength &&
            std::all_of(value.begin(), value.end(), [](unsigned char ch)
            {
                return std::isxdigit(ch) != 0;
            });
    }

    const JsonValue* Member(const JsonValue::Object& object, const char* key)
    {
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }

    std::string StringMember(const JsonValue::Object& object, const char* key)
    {
        const JsonValue* value = Member(object, key);
        const std::string* text = value ? value->AsString() : nullptr;
        return text ? *text : std::string{};
    }
}

bool LoadMaliciousHashesJson(
    const std::filesystem::path& path,
    MaliciousHashLoadResult& result,
    std::string& error)
{
    result = {};
    error.clear();

    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        error = "could not open malicious hash database";
        return false;
    }

    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    input.seekg(0, std::ios::beg);
    if (size < 0 || size > 4 * 1024 * 1024)
    {
        error = "malicious hash database is empty or larger than 4 MiB";
        return false;
    }

    std::string text(static_cast<std::size_t>(size), '\0');
    if (size > 0)
        input.read(text.data(), static_cast<std::streamsize>(size));
    if (!input.good() && !input.eof())
    {
        error = "failed while reading malicious hash database";
        return false;
    }
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
        text.erase(0, 3);

    JsonValue root;
    Parser parser(text);
    if (!parser.Parse(root, error))
        return false;

    const JsonValue::Object* rootObject = root.AsObject();
    if (!rootObject)
    {
        error = "top-level JSON value must be an object";
        return false;
    }

    const JsonValue* hashesValue = Member(*rootObject, "hashes");
    const JsonValue::Array* hashes = hashesValue ? hashesValue->AsArray() : nullptr;
    if (!hashes)
    {
        error = "top-level 'hashes' member must be an array";
        return false;
    }

    result.declaredEntries = hashes->size();
    std::set<std::string> seen;

    for (std::size_t index = 0; index < hashes->size(); ++index)
    {
        const JsonValue::Object* object = (*hashes)[index].AsObject();
        if (!object)
        {
            ++result.skippedEntries;
            result.warnings.push_back("entry " + std::to_string(index + 1) + " is not an object");
            continue;
        }

        const JsonValue* enabledValue = Member(*object, "enabled");
        if (enabledValue)
        {
            const bool* enabled = enabledValue->AsBool();
            if (!enabled)
            {
                ++result.skippedEntries;
                result.warnings.push_back("entry " + std::to_string(index + 1) + " has a non-boolean 'enabled' value");
                continue;
            }
            if (!*enabled)
                continue;
        }

        MaliciousHashRecord record;
        record.algorithm = NormalizeAlgorithm(StringMember(*object, "algorithm"));
        record.digest = NormalizeDigest(StringMember(*object, "digest"));
        if (record.digest.empty())
            record.digest = NormalizeDigest(StringMember(*object, "hash"));
        record.description = StringMember(*object, "description");
        record.campaign = StringMember(*object, "campaign");
        record.source = StringMember(*object, "source");

        const std::size_t expectedLength = record.algorithm == "SHA1" ? 40u : 64u;
        if (record.algorithm.empty() || !IsHexDigest(record.digest, expectedLength))
        {
            ++result.skippedEntries;
            result.warnings.push_back("entry " + std::to_string(index + 1) +
                " has an unsupported algorithm or invalid digest length/characters");
            continue;
        }

        if (record.description.empty())
            record.description = "User-supplied malicious file hash";

        if (const JsonValue* namesValue = Member(*object, "filenames"))
        {
            const JsonValue::Array* names = namesValue->AsArray();
            if (!names)
            {
                ++result.skippedEntries;
                result.warnings.push_back("entry " + std::to_string(index + 1) + " has a non-array 'filenames' value");
                continue;
            }
            for (const JsonValue& nameValue : *names)
            {
                const std::string* name = nameValue.AsString();
                if (!name || name->empty())
                    continue;
                record.filenames.push_back(Lower(*name));
            }
            std::sort(record.filenames.begin(), record.filenames.end());
            record.filenames.erase(std::unique(record.filenames.begin(), record.filenames.end()),
                record.filenames.end());
        }

        const std::string key = record.algorithm + ":" + record.digest;
        if (!seen.insert(key).second)
        {
            result.warnings.push_back("duplicate entry ignored: " + key);
            continue;
        }
        result.records.push_back(std::move(record));
    }

    if (result.records.empty())
    {
        error = "no valid enabled SHA1 or SHA256 entries were found";
        return false;
    }
    return true;
}
