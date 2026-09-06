#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

#include "middleware/content/packages/tables/activity_metadata_reader.h"
#include "middleware/content/packages/tables/activity_type_mapping.h"
#include "middleware/content/packages/tables/localized_string_reader.h"
#ifdef _WIN32
#include "state/build_data/cache/records/codec.h"
#include "state/build_data/scenarios/scenario_catalog.h"
#endif

namespace tables = sunrise::middleware::content::packages::tables;
namespace {
std::size_t checks{};
std::size_t failures{};

void expect(bool value, const char* name) {
    ++checks;
    if (!value) {
        ++failures;
        std::fprintf(stderr, "FAIL: %s\n", name);
    }
}

template <typename T> void put(std::vector<std::byte>& blob, std::size_t offset, T value) {
    if (offset > blob.size() || sizeof value > blob.size() - offset) {
        std::abort();
    }
    std::memcpy(blob.data() + offset, &value, sizeof value);
}

void array(std::vector<std::byte>& blob,
           std::size_t descriptor,
           std::size_t header,
           std::uint64_t count,
           std::uint32_t elementClass) {
    put(blob, descriptor, count);
    put(blob,
        descriptor + 8,
        static_cast<std::int64_t>(header) - static_cast<std::int64_t>(descriptor + 8));
    put(blob, header - 4, std::uint32_t{0x80809FBD});
    put(blob, header, count);
    put(blob, header + 8, elementClass);
}

/** Invented bytes only: this fixture contains no extracted game content. */
std::vector<std::byte> fixture() {
    std::vector<std::byte> blob(0x300);
    array(blob, 8, 0x30, 1, tables::kActivityIndexClass);
    put(blob, 0x40, std::uint32_t{123});
    put(blob, 0x48, std::int64_t{0x18});
    put(blob, 0x60, std::uint32_t{123});
    put(blob, 0xC8, std::int64_t{0xB8});
    put(blob, 0x13A, std::uint8_t{9});
    constexpr char name[] = "example_scenario";
    std::memcpy(blob.data() + 0x180, name, sizeof name);
    return blob;
}

void parser_tests() {
    auto blob = fixture();
    tables::Array rows{};
    tables::ActivityDefinition value{};
    expect(tables::activity_index(blob, rows), "index extent");
    auto parse = [&]() { return tables::activity_definition_at(blob, rows, 0, 54, value); };
    expect(parse() && value.hash == 123 && value.typeIndex == 9
               && value.scenarioName == "example_scenario" && value.playlist.count == 0,
           "definition and exact scenario name");
    expect(!tables::activity_definition_at(blob, rows, 1, 54, value) && value.hash == 0,
           "invalid ordinal clears output");
    expect(!tables::activity_definition_at(blob, rows, 0, 9, value), "type index bound");
    expect(!tables::activity_definition_at(std::span(blob).first(0x13A), rows, 0, 54, value),
           "truncated definition");
    put(blob, 0xC8, std::int64_t{0});
    expect(parse() && value.scenarioName.empty(), "absent scenario name");
    put(blob, 0xC8, (std::numeric_limits<std::int64_t>::max)());
    expect(!parse(), "positive relative overflow");
    put(blob, 0xC8, (std::numeric_limits<std::int64_t>::min)());
    expect(!parse(), "negative relative overflow");
    blob = fixture();
    put(blob, 0x48, std::int64_t{0});
    expect(!parse(), "absent definition");
    blob = fixture();
    put(blob, 0x60, std::uint32_t{124});
    expect(!parse(), "repeated identity mismatch");
    blob = fixture();
    put(blob, 0x180, '/');
    expect(!parse(), "non-package name rejected");
    blob = fixture();
    std::memset(blob.data() + 0x180, 'a', 41);
    expect(!parse(), "unterminated name rejected");
    put(blob, 0x1A8, '\0');
    expect(parse() && value.scenarioName.size() == 40, "40-byte key boundary");
    blob = fixture();
    array(blob, 8, 0x30, 1, tables::kActivityTypeRowClass);
    expect(!tables::activity_index(blob, rows), "wrong index class");
    blob = fixture();
    expect(tables::activity_index(blob, rows), "restore valid index");
    put(blob, 0x78, std::int64_t{0x138}); // playlist at 0x1B0
    array(blob, 0x1B8, 0x1E0, 1, tables::kActivityPlaylistRowClass);
    put(blob, 0x1F8, std::int16_t{0});
    expect(parse() && value.playlist.count == 1, "playlist descriptor");
    std::uint16_t child = 0;
    expect(tables::activity_playlist_child_at(blob, value.playlist, 0, 1, child) && child == 0,
           "self-reference is a valid child index");
    put(blob, 0x1F8, std::int16_t{-1});
    expect(!tables::activity_playlist_child_at(blob, value.playlist, 0, 1, child),
           "negative child");
    put(blob, 0x1F8, std::int16_t{1});
    expect(!tables::activity_playlist_child_at(blob, value.playlist, 0, 1, child),
           "child past table");
    array(blob, 0x1B8, 0x1E0, 1, tables::kActivityIndexClass);
    expect(!parse(), "wrong playlist class");

    blob.assign(256, std::byte{});
    array(blob, 8, 0x30, 1, tables::kActivityTypeUiRowClass);
    put(blob, 0x40, std::uint32_t{456});
    put(blob, 0x44, std::uint16_t{2});
    put(blob, 0x48, std::uint32_t{789});
    tables::ActivityTypeName name{};
    expect(tables::activity_types(blob, true, rows)
               && tables::activity_type_name_at(blob, rows, 0, name) && name.hash == 456
               && name.containerIndex == 2 && name.resourceHash == 789,
           "type UI name reference");
    expect(!tables::activity_types(std::span(blob).first(191), true, rows), "truncated UI row");
    array(blob, 8, 0x30, 1, tables::kActivityTypeRowClass);
    std::uint32_t hash = 0;
    expect(tables::activity_types(blob, false, rows)
               && tables::activity_type_hash_at(blob, rows, 0, hash) && hash == 456,
           "stable native type identity");
    array(blob, 8, 0x30, 1, tables::kInvestmentStringRegistryRowClass);
    put(blob, 0x44, std::uint32_t{0x80800033});
    expect(tables::activity_string_container_tag(blob, 0, hash) && hash == 0x80800033,
           "registry container reference");
    expect(!tables::activity_string_container_tag(blob, 1, hash), "registry index bound");
    put(blob, 0x44, std::uint32_t{1});
    expect(!tables::activity_string_container_tag(blob, 0, hash), "registry invalid tag");
}

void graph_tests() {
    std::array<tables::ActivityGraphNode, 4> nodes{};
    nodes[0] = {tables::kUnmappedActivityScenario, 1, 0, 3};
    nodes[1] = {0, 2, 3, 1};
    nodes[2] = {1, 3, 4, 1};
    nodes[3] = {2, 4, 5, 1};
    std::array<std::uint16_t, 6> edges{1, 2, 1, 3, 3, 0};
    std::array<std::uint8_t, 3> reachable{};
    std::array<std::uint8_t, 4> visited{};
    std::array<std::uint16_t, 4> queue{};
    auto walk = [&]() {
        return tables::activity_playlist_scenarios(nodes, edges, 0, reachable, visited, queue);
    };
    expect(walk() && reachable == std::array<std::uint8_t, 3>{1, 1, 1},
           "cycle, diamond, and repeated edge terminate with every scenario");
    expect(walk() && reachable == std::array<std::uint8_t, 3>{1, 1, 1},
           "repeat traversal resets scratch");
    edges[5] = 3;
    expect(walk() && reachable[2] == 1, "self cycle terminates");
    edges[5] = 4;
    expect(!walk() && reachable == decltype(reachable){}, "bad edge clears partial result");
    edges[5] = 0;
    nodes[2].firstChild = 100;
    expect(!walk() && reachable == decltype(reachable){}, "bad child range clears result");
    nodes[2].firstChild = 4;
    nodes[2].scenarioIndex = 3;
    expect(!walk(), "scenario index bound");
    nodes[2].scenarioIndex = 1;
    expect(!tables::activity_playlist_scenarios(
               nodes, edges, 0, reachable, visited, std::span(queue).first(3)),
           "queue capacity");
    expect(!tables::activity_playlist_scenarios(nodes, edges, 4, reachable, visited, queue),
           "root index bound");
}

/** Title metadata and string readers, exercised with invented resources rather than game data. */
void label_tests() {
    std::vector<std::byte> metadata(0x50);
    put(metadata, 8, std::uint32_t{123});
    array(metadata, 0x10, 0x30, 2, tables::kActivityDefinitionTagClass);
    put(metadata, 0x40, std::uint32_t{0x80800011});
    put(metadata, 0x44, std::uint32_t{0x80800022});
    tables::ActivityMetadata activity{};
    std::uint32_t tag = 0;
    expect(tables::activity_metadata(metadata, activity) && activity.displayNameHash == 123,
           "title metadata resource hash");
    expect(tables::activity_definition_tag_at(metadata, activity, 1, tag) && tag == 0x80800022,
           "title metadata scenario reference");
    expect(!tables::activity_definition_tag_at(metadata, activity, 2, tag),
           "title metadata tag ordinal bound");
    put(metadata, 0x38, std::uint32_t{0x80800001});
    expect(!tables::activity_metadata(metadata, activity), "title metadata class validation");

    std::vector<std::byte> header(0x50);
    array(header, 8, 0x30, 2, 0x80800001);
    put(header, 0x18, std::uint32_t{0x80800033});
    put(header, 0x40, std::uint32_t{123});
    put(header, 0x44, std::uint32_t{456});
    tables::LocalizedStrings strings{};
    expect(tables::localized_strings(header, strings)
               && tables::localized_hash_at(header, strings, 1, tag) && tag == 456,
           "localized resource ordinal");
    expect(tables::localized_english_tag(header, tag) && tag == 0x80800033,
           "verified English slot");
    std::vector<std::byte> language(0xE0);
    array(language, 0x48, 0x70, 1, tables::kStringCombinationClass);
    put(language, 0x80, std::int64_t{0x20});
    put(language, 0x88, std::int64_t{1});
    put(language, 0xA8, std::int64_t{0x28});
    put(language, 0xB4, std::uint16_t{4});
    put(language, 0xB6, std::uint16_t{4});
    put(language, 0xB8, std::uint16_t{1});
    constexpr char encoded[] = "Sdrs"; // The verified ASCII shift decodes this synthetic text.
    std::memcpy(language.data() + 0xD0, encoded, 4);
    std::array<char, 4> decoded{};
    std::uint8_t length = 0;
    std::uint64_t count = 0;
    auto decode = [&]() { return tables::localized_ascii_string_at(language, 0, decoded, length); };
    expect(tables::localized_string_count(language, count) && count == 1,
           "language combination count");
    expect(decode() && std::string_view(decoded.data(), length) == "Test",
           "exact-capacity shifted ASCII has no required terminator");
    expect(!tables::localized_ascii_string_at(language, 0, std::span(decoded).first(3), length),
           "localized output overflow rejected");
    put(language, 0xB6, std::uint16_t{3});
    expect(!decode() && length == 0 && decoded == decltype(decoded){},
           "mismatched localized lengths clear output");
    put(language, 0xB6, std::uint16_t{4});
    put(language, 0xD2, std::uint8_t{0xFF});
    expect(!decode() && length == 0 && decoded == decltype(decoded){},
           "unsupported encoding clears partially decoded text");
    put(language, 0xA8, (std::numeric_limits<std::int64_t>::max)());
    expect(!decode(), "localized pointer overflow rejected");
}

#ifdef _WIN32
void cache_tests() {
    namespace layouts = sunrise::state::build_data::scenarios;
    namespace records = sunrise::state::build_data::cache::records;
    layouts::Definition row{};
    row.name[0] = 'x';
    row.nameLength = 1;
    row.activityUseCount = 2;
    row.activityUses[0].typeHash = 10;
    row.activityUses[0].sources = layouts::kDirectActivityUse;
    row.activityUses[0].label[0] = 'A';
    row.activityUses[0].labelLength = 1;
    row.activityUses[1].typeHash = 20;
    row.activityUses[1].sources = layouts::kActivityUseSourceMask;
    records::ScenarioRecord disk{};
    records::ScenarioRecord diskAgain{};
    layouts::Definition restored{};
    auto valid = [](const auto& value) { return layouts::valid(std::span(&value, 1), {}); };
    expect(valid(row), "canonical many-to-many uses with unnamed fallback");
    expect(records::encode(row, disk) && records::decode(disk, restored) && valid(restored)
               && restored.activityUseCount == 2 && restored.activityUses == row.activityUses,
           "cache round trip preserves identity, labels, and provenance");
    expect(records::encode(restored, diskAgain) && std::memcmp(&disk, &diskAgain, sizeof disk) == 0,
           "canonical cache byte equality");
    disk.activityUseCount = 33;
    expect(!records::decode(disk, restored), "cache use-count bound");
    row.activityUses[1].typeHash = 10;
    expect(!valid(row), "duplicate type identity rejected");
    row.activityUses[1].typeHash = 5;
    expect(!valid(row), "noncanonical ordering rejected");
    row.activityUses[1].typeHash = 20;
    row.activityUses[1].sources = 4;
    expect(!valid(row), "unknown provenance bits rejected");
    row.activityUses[1].sources = layouts::kPlaylistActivityUse;
    row.activityUses[0].label[1] = 'z';
    expect(!valid(row), "label tail must be zero");
    row.activityUses[0].label[1] = 0;
    row.activityUseCount = 1;
    expect(!valid(row), "unused use rows must be zero");
    row.activityUses[1] = {};
    expect(valid(row), "canonical unused rows");

    row.activityLabel[0] = '\n';
    row.activityLabelLength = 1;
    expect(!valid(row), "nonprintable activity title rejected");
    row.activityLabel[0] = '\0';
    expect(!valid(row), "embedded title terminator rejected");
    row.activityLabel.fill('T');
    row.activityLabelLength = static_cast<std::uint8_t>(row.activityLabel.size());
    expect(valid(row) && records::encode(row, disk) && records::decode(disk, restored)
               && restored.activityLabel == row.activityLabel
               && restored.activityLabelLength == row.activityLabelLength,
           "full-capacity title survives cache without a terminator");
    disk.activityLabelLength = static_cast<std::uint8_t>(row.activityLabel.size() + 1);
    expect(!records::decode(disk, restored), "cache title length bound");
    row.activityLabelLength = 1;
    expect(!valid(row), "unused title tail must be zero");
}

/** New display metadata must not change scenario identity or admit invalid replacements. */
void consumer_tests() {
    namespace layouts = sunrise::state::build_data::scenarios;
    layouts::clear();
    layouts::Definition row{};
    row.name[0] = 'x';
    row.nameLength = 1;
    row.activityLabel[0] = 'T';
    row.activityLabelLength = 1;
    row.activityUseCount = 2;
    row.activityUses[0] = {10, {'A'}, 1, layouts::kDirectActivityUse};
    row.activityUses[1] = {20, {'A'}, 1, layouts::kPlaylistActivityUse};
    layouts::Definition found{};
    expect(layouts::replace(std::span(&row, 1), {}) && layouts::find("x", found)
               && found.activityUseCount == 2 && found.activityUses == row.activityUses,
           "catalog preserves distinct identities with equal English names");
    row.activityUses[1].typeHash = 10;
    expect(!layouts::replace(std::span(&row, 1), {}) && layouts::find("x", found)
               && found.activityUses[1].typeHash == 20,
           "invalid replacement preserves the previous catalog");
    expect(!layouts::find("T", found) && found.activityUseCount == 0,
           "display title is never a lookup key and misses clear output");
    layouts::clear();
}
#endif
} // namespace

int main() {
    parser_tests();
    graph_tests();
    label_tests();
#ifdef _WIN32
    cache_tests();
    consumer_tests();
#endif
    std::printf("Activity metadata tests: %zu checks, %zu failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
