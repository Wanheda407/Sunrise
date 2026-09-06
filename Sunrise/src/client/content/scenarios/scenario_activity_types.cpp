#include <algorithm>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../middleware/content/packages/tables/localized_string_reader.h"
#include "activity_type_build.h"

namespace sunrise::client::content::scenarios {
namespace {

namespace reader = middleware::content::packages::reader;
namespace tables = middleware::content::packages::tables;
namespace layouts = state::build_data::scenarios;

/** Bounds package reads and graph roots per worker slice, keeping shutdown responsive. */
constexpr std::size_t kTypeReadBudget = 8;
constexpr std::size_t kActivityWorkBudget = 24;
constexpr std::uint32_t kAbsentNameHash = 0x811C9DC5U;
static_assert(layouts::kNameCapacity == tables::kActivityScenarioNameCapacity);

/** Records a UI root, refusing ambiguity instead of choosing the class sweep's first result. */
bool collect_ui_root(void* context, std::uint32_t tag) noexcept {
    auto& storage = *static_cast<ActivityTypeStorage*>(context);
    storage.uiRootTag = tag;
    return ++storage.uiRootCount == 1;
}

/** Reads a root reference's blob and checks its package-entry class. */
[[nodiscard]] bool read_class(const reader::Source& source,
                              reader::Scratch& scratch,
                              std::uint32_t tag,
                              std::uint32_t expectedClass,
                              std::vector<std::byte>& output) noexcept {
    std::uint32_t actualClass = 0;
    return tables::package_of(tag) != tables::kAbsentPackageId
           && reader::read_tag(source, scratch, tag, output, actualClass)
           && actualClass == expectedClass;
}

/** Resolves the separately authored UI root using the existing package class sweep. */
[[nodiscard]] bool load_ui(const reader::Source& source,
                           reader::Scratch& scratch,
                           ActivityTypeStorage& storage) noexcept {
    reader::ScanResult scan{};
    if (!reader::scan_class(
            source.directory, tables::kInvestmentUiRootClass, collect_ui_root, &storage, scan)
        || storage.uiRootCount != 1
        || !read_class(
            source, scratch, storage.uiRootTag, tables::kInvestmentUiRootClass, storage.header)) {
        return false;
    }
    std::uint32_t typeTag = 0;
    std::uint32_t registryTag = 0;
    return tables::activity_reference_tag(storage.header, tables::kActivityTypeUiTagOffset, typeTag)
           && tables::activity_reference_tag(
               storage.header, tables::kInvestmentStringRegistryTagOffset, registryTag)
           && read_class(
               source, scratch, typeTag, tables::kActivityTypeUiTableClass, storage.uiTypes)
           && tables::activity_types(storage.uiTypes, true, storage.uiTypeArray)
           && storage.uiTypeArray.count == storage.nativeTypeArray.count
           && read_class(source,
                         scratch,
                         registryTag,
                         tables::kInvestmentStringRegistryClass,
                         storage.registry);
}

/** Reads the authoritative tables through the root already located by the package pass. */
[[nodiscard]] bool load_tables(const reader::Source& source,
                               reader::Scratch& scratch,
                               std::span<const std::byte> root,
                               ActivityTypeStorage& storage) noexcept {
    std::uint32_t activityTag = 0;
    std::uint32_t typeTag = 0;
    if (!tables::slot_tag(root, tables::kActivityTableSlot, activityTag)
        || !tables::slot_tag(root, tables::kActivityTypeTableSlot, typeTag)
        || !read_class(
            source, scratch, activityTag, tables::kActivityTableClass, storage.activities)
        || !tables::activity_index(storage.activities, storage.activityArray)
        || !read_class(
            source, scratch, typeTag, tables::kActivityTypeTableClass, storage.nativeTypes)
        || !tables::activity_types(storage.nativeTypes, false, storage.nativeTypeArray)) {
        return false;
    }
    for (std::size_t index = 0; index < storage.nativeTypeArray.count; ++index) {
        auto& type = storage.types[index];
        if (!tables::activity_type_hash_at(
                storage.nativeTypes, storage.nativeTypeArray, index, type.typeHash)
            || type.typeHash == 0) {
            return false;
        }
        for (std::size_t earlier = 0; earlier < index; ++earlier) {
            if (storage.types[earlier].typeHash == type.typeHash) {
                return false;
            }
        }
    }
    storage.uiLoaded = load_ui(source, scratch, storage);
    storage.loaded = true;
    return true;
}

/** Reads only the referenced English container; equal text is never treated as type identity. */
[[nodiscard]] bool resolve_type_name(const reader::Source& source,
                                     reader::Scratch& scratch,
                                     ActivityTypeStorage& storage,
                                     std::size_t index) noexcept {
    tables::ActivityTypeName name{};
    auto& type = storage.types[index];
    if (!tables::activity_type_name_at(storage.uiTypes, storage.uiTypeArray, index, name)
        || name.hash != type.typeHash) {
        return false;
    }
    if (name.containerIndex == 0xFFFFU || name.resourceHash == kAbsentNameHash
        || name.resourceHash == 0) {
        return true;
    }
    std::uint32_t headerTag = 0;
    std::uint32_t languageTag = 0;
    tables::LocalizedStrings strings{};
    if (!tables::activity_string_container_tag(storage.registry, name.containerIndex, headerTag)
        || !read_class(source, scratch, headerTag, tables::kLocalizedStringsClass, storage.header)
        || !tables::localized_strings(storage.header, strings)
        || !tables::localized_english_tag(storage.header, languageTag)) {
        return false;
    }
    std::uint64_t ordinal = strings.hashes.count;
    for (std::uint64_t row = 0; row < strings.hashes.count; ++row) {
        std::uint32_t hash = 0;
        if (!tables::localized_hash_at(storage.header, strings, row, hash)) {
            return false;
        }
        if (hash == name.resourceHash) {
            if (ordinal != strings.hashes.count) {
                return false;
            }
            ordinal = row;
        }
    }
    std::uint64_t count = 0;
    if (ordinal == strings.hashes.count
        || !reader::read_tag(source, scratch, languageTag, storage.language)
        || !tables::localized_string_count(storage.language, count) || count != strings.hashes.count
        || !tables::localized_ascii_string_at(
            storage.language, ordinal, type.label, type.labelLength)) {
        return false;
    }
    if (type.labelLength != 0) {
        ++storage.namesDecoded;
    }
    return true;
}

/** Parses one activity and resolves its exact package key against the compacted scenario rows. */
[[nodiscard]] bool resolve_activity(ActivityTypeStorage& storage,
                                    std::span<const layouts::Definition> rows,
                                    std::size_t index) noexcept {
    tables::ActivityDefinition activity{};
    if (!tables::activity_definition_at(storage.activities,
                                        storage.activityArray,
                                        index,
                                        storage.nativeTypeArray.count,
                                        activity)
        || activity.playlist.count > storage.edges.size() - storage.edgeCount) {
        return false;
    }
    auto& node = storage.nodes[index];
    node.typeIndex = activity.typeIndex;
    node.firstChild = static_cast<std::uint32_t>(storage.edgeCount);
    node.childCount = static_cast<std::uint16_t>(activity.playlist.count);
    for (std::size_t edge = 0; edge < activity.playlist.count; ++edge) {
        std::uint16_t child = 0;
        if (!tables::activity_playlist_child_at(
                storage.activities, activity.playlist, edge, storage.activityArray.count, child)) {
            return false;
        }
        storage.edges[storage.edgeCount++] = child;
    }
    storage.playlists += node.childCount != 0 ? 1U : 0U;
    for (std::size_t row = 0; row < rows.size(); ++row) {
        if (activity.scenarioName
            == std::string_view(rows[row].name.data(), rows[row].nameLength)) {
            node.scenarioIndex = static_cast<std::uint16_t>(row);
            storage.uses[row][node.typeIndex] |= layouts::kDirectActivityUse;
            break;
        }
    }
    return true;
}

/** Publishes a canonical set per scenario. An overflowing set is wholly unclassified. */
void assign_uses(ActivityTypeStorage& storage, std::span<layouts::Definition> rows) noexcept {
    for (std::size_t row = 0; row < rows.size(); ++row) {
        auto& definition = rows[row];
        bool direct = false;
        for (std::size_t index = 0; index < storage.nativeTypeArray.count; ++index) {
            const std::uint8_t sources = storage.uses[row][index];
            if (sources == 0) {
                continue;
            }
            direct = direct || (sources & layouts::kDirectActivityUse) != 0;
            if (definition.activityUseCount == definition.activityUses.size()) {
                definition.activityUses = {};
                definition.activityUseCount = 0;
                ++storage.overflowScenarios;
                break;
            }
            auto& use = definition.activityUses[definition.activityUseCount++];
            use = storage.types[index];
            use.sources = sources;
        }
        const auto uses = std::span(definition.activityUses).first(definition.activityUseCount);
        std::sort(uses.begin(), uses.end(), [](const auto& left, const auto& right) noexcept {
            return left.typeHash < right.typeHash;
        });
        storage.directScenarios += direct ? 1U : 0U;
        storage.mappedScenarios += !uses.empty() ? 1U : 0U;
    }
}

/** Reports the result and releases package bytes; bounded graph storage contains no borrowed data.
 */
void finish(ActivityTypeStorage& storage, const char* result, bool warning) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=build_data stage=activity_types activities=%llu parsed=%zu types=%llu ui=%u "
        "names=%zu name_fail=%zu playlists=%zu edges=%zu direct_scenarios=%zu mapped=%zu "
        "overflow=%zu result=%s",
        static_cast<unsigned long long>(storage.activityArray.count),
        storage.activityCursor,
        static_cast<unsigned long long>(storage.nativeTypeArray.count),
        storage.uiLoaded ? 1U : 0U,
        storage.namesDecoded,
        storage.nameFailures,
        storage.playlists,
        storage.edgeCount,
        storage.directScenarios,
        storage.mappedScenarios,
        storage.overflowScenarios,
        result);
    if (written > 0) {
        core::log::write(
            core::log::Channel::state,
            warning ? core::log::Level::warn : core::log::Level::info,
            {line.data(), (std::min)(static_cast<std::size_t>(written), line.size() - 1)});
    }
    for (auto* blob : {&storage.activities,
                       &storage.nativeTypes,
                       &storage.uiTypes,
                       &storage.registry,
                       &storage.header,
                       &storage.language}) {
        blob->clear();
        blob->shrink_to_fit();
    }
    storage.built = true;
}

} // namespace

bool build_activity_types(const reader::Source& source,
                          reader::Scratch& scratch,
                          std::span<const std::byte> investmentRoot,
                          ActivityTypeStorage& storage,
                          std::span<layouts::Definition> rows) noexcept {
    if (storage.built) {
        return true;
    }
    if (rows.size() > layouts::kDefinitionCapacity) {
        finish(storage, "scenario_capacity", true);
        return true;
    }
    if (!storage.loaded) {
        // The package pass locates its root after starting the independent scenario pass.
        if (investmentRoot.empty()) {
            return false;
        }
        if (!load_tables(source, scratch, investmentRoot, storage)) {
            finish(storage, "tables", true);
            return true;
        }
        return false;
    }
    for (std::size_t work = 0;
         storage.typeCursor < storage.nativeTypeArray.count && work < kTypeReadBudget;
         ++work, ++storage.typeCursor) {
        if (storage.uiLoaded && !resolve_type_name(source, scratch, storage, storage.typeCursor)) {
            storage.types[storage.typeCursor].label = {};
            storage.types[storage.typeCursor].labelLength = 0;
            ++storage.nameFailures;
        }
    }
    if (storage.typeCursor < storage.nativeTypeArray.count) {
        return false;
    }
    for (std::size_t work = 0;
         storage.activityCursor < storage.activityArray.count && work < kActivityWorkBudget;
         ++work, ++storage.activityCursor) {
        if (!resolve_activity(storage, rows, storage.activityCursor)) {
            finish(storage, "activity_or_edges", true);
            return true;
        }
    }
    if (storage.activityCursor < storage.activityArray.count) {
        return false;
    }
    const auto nodes = std::span(storage.nodes).first(storage.activityCursor);
    const auto edges = std::span(storage.edges).first(storage.edgeCount);
    for (std::size_t work = 0; storage.playlistCursor < nodes.size() && work < kActivityWorkBudget;
         ++work, ++storage.playlistCursor) {
        const auto& node = nodes[storage.playlistCursor];
        if (node.childCount == 0) {
            continue;
        }
        const auto reachable = std::span(storage.reachable).first(rows.size());
        if (!tables::activity_playlist_scenarios(
                nodes, edges, storage.playlistCursor, reachable, storage.visited, storage.queue)) {
            finish(storage, "playlist_graph", true);
            return true;
        }
        for (std::size_t row = 0; row < rows.size(); ++row) {
            if (reachable[row] != 0) {
                storage.uses[row][node.typeIndex] |= layouts::kPlaylistActivityUse;
            }
        }
    }
    if (storage.playlistCursor < nodes.size()) {
        return false;
    }
    assign_uses(storage, rows);
    const bool partial =
        !storage.uiLoaded || storage.nameFailures != 0 || storage.overflowScenarios != 0;
    finish(storage, partial ? "partial" : "ok", partial);
    return true;
}

} // namespace sunrise::client::content::scenarios
