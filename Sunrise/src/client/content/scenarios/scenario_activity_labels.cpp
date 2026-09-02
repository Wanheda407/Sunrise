#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../middleware/content/packages/tables/activity_metadata_reader.h"
#include "../../../middleware/content/packages/tables/localized_string_reader.h"
#include "internal.h"

namespace sunrise::client::content::scenarios {
namespace {

namespace packages = middleware::content::packages;
namespace tables = packages::tables;

/** Resource-hash sentinel used when content intentionally carries no player-facing text. */
constexpr std::uint32_t kAbsentResourceHash = 0x811C9DC5U;
/** Records one activity metadata tag discovered by the class sweep. */
bool collect_activity(void* context, std::uint32_t tag) noexcept {
    auto& storage = *static_cast<ActivityLabelStorage*>(context);
    if (storage.activityTagCount >= storage.activityTags.size()) {
        storage.activityTagOverflow = true;
        return false;
    }
    storage.activityTags[storage.activityTagCount++] = tag;
    return true;
}

/** Records one installed localized-string container. */
bool collect_strings(void* context, std::uint32_t tag) noexcept {
    auto& storage = *static_cast<ActivityLabelStorage*>(context);
    if (storage.stringTagCount >= storage.stringTags.size()) {
        storage.stringTagOverflow = true;
        return false;
    }
    storage.stringTags[storage.stringTagCount++] = tag;
    return true;
}

/** @return One row's bounded player-facing label. */
[[nodiscard]] std::string_view label_of(const layouts::Definition& row) noexcept {
    return {row.activityLabel.data(), row.activityLabelLength};
}

/** @return True when extraction completed with a malformed, ambiguous, or unreadable input. */
[[nodiscard]] bool partial(const ActivityLabelStorage& storage) noexcept {
    return storage.activityReadFailures != 0 || storage.activityParseFailures != 0
           || storage.definitionTagFailures != 0 || storage.mappingConflicts != 0
           || storage.stringHeaderReadFailures != 0 || storage.stringHeaderParseFailures != 0
           || storage.languageTagFailures != 0 || storage.stringHashFailures != 0
           || storage.stringDataReadFailures != 0 || storage.stringDataParseFailures != 0
           || storage.labelsRejected != 0 || storage.conflicts != 0;
}

/** Reports the complete bounded extraction result. */
void report(const ActivityLabelStorage& storage, const char* result, bool warning) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=build_data stage=activity_labels activities=%zu strings=%zu targets=%zu assigned=%zu "
        "read_fail=%zu parse_fail=%zu tag_fail=%zu map_conflicts=%zu header_read_fail=%zu "
        "header_parse_fail=%zu language_fail=%zu hash_fail=%zu data_read_fail=%zu "
        "data_parse_fail=%zu rejected=%zu placeholders=%zu label_conflicts=%zu result=%s",
        storage.activityTagCount,
        storage.stringTagCount,
        storage.targetHashCount,
        storage.assigned,
        storage.activityReadFailures,
        storage.activityParseFailures,
        storage.definitionTagFailures,
        storage.mappingConflicts,
        storage.stringHeaderReadFailures,
        storage.stringHeaderParseFailures,
        storage.languageTagFailures,
        storage.stringHashFailures,
        storage.stringDataReadFailures,
        storage.stringDataParseFailures,
        storage.labelsRejected,
        storage.labelsPlaceholders,
        storage.conflicts,
        result);
    if (written > 0) {
        core::log::write(
            core::log::Channel::state,
            warning ? core::log::Level::warn : core::log::Level::info,
            {line.data(), (std::min)(static_cast<std::size_t>(written), line.size() - 1)});
    }
}

/** Associates one activity's display-name hash with the scenario tag it references. */
void resolve_activity(const reader::Source& source,
                      reader::Scratch& scratch,
                      std::uint32_t tag,
                      ActivityLabelStorage& storage,
                      std::span<layouts::Definition> rows) noexcept {
    if (!reader::read_tag(source, scratch, tag, storage.activity)) {
        ++storage.activityReadFailures;
        return;
    }
    tables::ActivityMetadata activity{};
    if (!tables::activity_metadata(storage.activity, activity)) {
        ++storage.activityParseFailures;
        return;
    }
    if (activity.displayNameHash == 0 || activity.displayNameHash == kAbsentResourceHash) {
        return;
    }
    for (std::uint64_t index = 0; index < activity.definitionTags.count; ++index) {
        std::uint32_t definitionTag = 0;
        if (!tables::activity_definition_tag_at(storage.activity, activity, index, definitionTag)) {
            ++storage.definitionTagFailures;
            continue;
        }
        for (std::size_t row = 0; row < rows.size(); ++row) {
            if (rows[row].tag != definitionTag) {
                continue;
            }
            if (storage.ambiguousMappings[row] != 0) {
                continue;
            }
            if (storage.displayNameHashes[row] == 0) {
                storage.displayNameHashes[row] = activity.displayNameHash;
            } else if (storage.displayNameHashes[row] != activity.displayNameHash) {
                storage.displayNameHashes[row] = 0;
                storage.ambiguousMappings[row] = 1;
                ++storage.mappingConflicts;
            }
        }
    }
}

/** Builds the sorted unique set used to reject irrelevant localized-string rows. */
void build_target_hashes(ActivityLabelStorage& storage,
                         std::span<const layouts::Definition> rows) noexcept {
    storage.targetHashes = {};
    storage.targetHashCount = 0;
    for (std::size_t row = 0; row < rows.size(); ++row) {
        const std::uint32_t hash = storage.displayNameHashes[row];
        if (hash != 0 && storage.targetHashCount < storage.targetHashes.size()) {
            storage.targetHashes[storage.targetHashCount++] = hash;
        }
    }
    auto targets = std::span(storage.targetHashes).first(storage.targetHashCount);
    std::sort(targets.begin(), targets.end());
    storage.targetHashCount =
        static_cast<std::size_t>(std::unique(targets.begin(), targets.end()) - targets.begin());
    storage.targetHashesBuilt = true;
}

/** @return True when at least one unambiguous scenario maps to this resource hash. */
[[nodiscard]] bool maps_hash(const ActivityLabelStorage& storage, std::uint32_t hash) noexcept {
    const auto targets = std::span(storage.targetHashes).first(storage.targetHashCount);
    return std::binary_search(targets.begin(), targets.end(), hash);
}

/** @return True when a printable ASCII label contains an English letter or decimal digit. */
[[nodiscard]] bool meaningful_label(std::span<const char> label) noexcept {
    for (const char value : label) {
        if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
            || (value >= '0' && value <= '9')) {
            return true;
        }
    }
    return false;
}

/** Applies one decoded string to every scenario waiting for its resource hash. */
void assign_label(ActivityLabelStorage& storage,
                  std::span<layouts::Definition> rows,
                  std::uint32_t hash,
                  std::span<const char> label) noexcept {
    for (std::size_t row = 0; row < rows.size(); ++row) {
        if (storage.displayNameHashes[row] != hash) {
            continue;
        }
        if (rows[row].activityLabelLength == 0) {
            std::copy(label.begin(), label.end(), rows[row].activityLabel.begin());
            rows[row].activityLabelLength = static_cast<std::uint8_t>(label.size());
            ++storage.assigned;
        } else if (label_of(rows[row]) != std::string_view(label.data(), label.size())) {
            rows[row].activityLabel = {};
            rows[row].activityLabelLength = 0;
            storage.displayNameHashes[row] = 0;
            if (storage.assigned != 0) {
                --storage.assigned;
            }
            ++storage.conflicts;
        }
    }
}

/** Searches one installed string container for the activity hashes still missing labels. */
void resolve_strings(const reader::Source& source,
                     reader::Scratch& scratch,
                     std::uint32_t tag,
                     ActivityLabelStorage& storage,
                     std::span<layouts::Definition> rows) noexcept {
    if (!reader::read_tag(source, scratch, tag, storage.stringHeader)) {
        ++storage.stringHeaderReadFailures;
        return;
    }
    tables::LocalizedStrings strings{};
    if (!tables::localized_strings(storage.stringHeader, strings)) {
        ++storage.stringHeaderParseFailures;
        return;
    }
    bool wanted = false;
    for (std::uint64_t index = 0; index < strings.hashes.count; ++index) {
        std::uint32_t hash = 0;
        if (!tables::localized_hash_at(storage.stringHeader, strings, index, hash)) {
            ++storage.stringHashFailures;
            return;
        }
        wanted = wanted || maps_hash(storage, hash);
    }
    if (!wanted) {
        return;
    }
    std::uint32_t languageTag = 0;
    if (!tables::localized_english_tag(storage.stringHeader, languageTag)) {
        ++storage.languageTagFailures;
        return;
    }
    if (!reader::read_tag(source, scratch, languageTag, storage.languageStrings)) {
        ++storage.stringDataReadFailures;
        return;
    }
    std::uint64_t stringCount = 0;
    if (!tables::localized_string_count(storage.languageStrings, stringCount)
        || stringCount != strings.hashes.count) {
        ++storage.stringDataParseFailures;
        return;
    }
    for (std::uint64_t index = 0; index < strings.hashes.count; ++index) {
        std::uint32_t hash = 0;
        if (!tables::localized_hash_at(storage.stringHeader, strings, index, hash)) {
            ++storage.stringHashFailures;
            return;
        }
        if (!maps_hash(storage, hash)) {
            continue;
        }
        std::array<char, layouts::kActivityLabelCapacity> label{};
        std::uint8_t labelLength = 0;
        if (!tables::localized_ascii_string_at(
                storage.languageStrings, index, label, labelLength)) {
            ++storage.labelsRejected;
            continue;
        }
        const auto text = std::span(label).first(labelLength);
        if (!meaningful_label(text)) {
            ++storage.labelsPlaceholders;
            continue;
        }
        assign_label(storage, rows, hash, text);
    }
}

/** Releases the dynamic tag-read buffers once the domain is complete. */
void release_buffers(ActivityLabelStorage& storage) noexcept {
    storage.activity.clear();
    storage.activity.shrink_to_fit();
    storage.stringHeader.clear();
    storage.stringHeader.shrink_to_fit();
    storage.languageStrings.clear();
    storage.languageStrings.shrink_to_fit();
}

} // namespace

/** Extracts localized activity labels and associates them with scenario rows by definition tag. */
bool build_activity_labels(const reader::Source& source,
                           reader::Scratch& scratch,
                           ActivityLabelStorage& storage,
                           std::span<layouts::Definition> rows) noexcept {
    if (storage.built) {
        return true;
    }
    if (!storage.activitiesScanned) {
        reader::ScanResult scan{};
        if (!reader::scan_class(source.directory,
                                tables::kActivityMetadataClass,
                                &collect_activity,
                                &storage,
                                scan)) {
            storage.built = true;
            report(storage,
                   storage.activityTagOverflow ? "activity_capacity" : "activity_sweep",
                   true);
            return true;
        }
        storage.activitiesScanned = true;
    }
    std::size_t reads = 0;
    while (storage.activityCursor < storage.activityTagCount && reads < kLabelReadBudget) {
        resolve_activity(
            source, scratch, storage.activityTags[storage.activityCursor], storage, rows);
        ++storage.activityCursor;
        ++reads;
    }
    if (storage.activityCursor < storage.activityTagCount) {
        return false;
    }
    if (!storage.targetHashesBuilt) {
        build_target_hashes(storage, rows);
    }
    if (storage.targetHashCount == 0) {
        release_buffers(storage);
        storage.built = true;
        report(storage, partial(storage) ? "partial" : "empty", true);
        return true;
    }

    if (!storage.stringsScanned) {
        reader::ScanResult scan{};
        if (!reader::scan_class(source.directory,
                                tables::kLocalizedStringsClass,
                                &collect_strings,
                                &storage,
                                scan)) {
            storage.built = true;
            release_buffers(storage);
            report(storage, storage.stringTagOverflow ? "string_capacity" : "string_sweep", true);
            return true;
        }
        storage.stringsScanned = true;
    }
    reads = 0;
    while (storage.stringCursor < storage.stringTagCount && reads < kLabelReadBudget) {
        resolve_strings(source, scratch, storage.stringTags[storage.stringCursor], storage, rows);
        ++storage.stringCursor;
        ++reads;
    }
    if (storage.stringCursor < storage.stringTagCount) {
        return false;
    }
    release_buffers(storage);
    storage.built = true;
    const bool incomplete = partial(storage);
    report(storage, incomplete ? "partial" : "ok", incomplete);
    return true;
}

} // namespace sunrise::client::content::scenarios
