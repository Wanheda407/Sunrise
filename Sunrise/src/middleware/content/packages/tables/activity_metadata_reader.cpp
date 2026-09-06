#include "activity_metadata_reader.h"

#include "internal.h"

namespace sunrise::middleware::content::packages::tables {
namespace {

/** Activity field offsets measured from the archived Shadowkeep client packages. */
constexpr std::size_t kDisplayNameHashOffset = 0x08;
constexpr std::size_t kDefinitionTagDescriptorOffset = 0x10;

/** Recovered inline strides and fields for build 86657.20.08.23. */
constexpr std::size_t kIndexStride = 16;
constexpr std::size_t kUiTypeStride = 128;
constexpr std::size_t kPlaylistStride = 56;
constexpr std::size_t kScenarioPointer = 0x68;
constexpr std::size_t kTypeIndex = 0xDA;
constexpr std::size_t kPlaylistPointer = 0x18;

/** Resolves a signed self-relative pointer without signed overflow, including INT64_MIN. */
[[nodiscard]] bool relative(std::span<const std::byte> blob,
                            std::size_t field,
                            std::size_t& target,
                            bool& absent) noexcept {
    target = 0;
    absent = false;
    std::int64_t displacement = 0;
    if (!read(blob, field, displacement)) {
        return false;
    }
    if (displacement == 0) {
        absent = true;
        return true;
    }
    if (displacement > 0) {
        const auto distance = static_cast<std::uint64_t>(displacement);
        if (distance >= blob.size() - field) {
            return false;
        }
        target = field + static_cast<std::size_t>(distance);
    } else {
        const auto distance = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
        if (distance > field) {
            return false;
        }
        target = field - static_cast<std::size_t>(distance);
    }
    return target < blob.size();
}

/** Validates a bounded array's class and entire inline row extent before indexing it. */
[[nodiscard]] bool fits(std::span<const std::byte> blob,
                        const Array& array,
                        std::uint32_t elementClass,
                        std::size_t stride,
                        std::size_t capacity) noexcept {
    return array.elementClass == elementClass && array.count <= capacity
           && array.dataOffset <= blob.size()
           && array.count <= (blob.size() - array.dataOffset) / stride;
}

/** Reads the exact package key; display titles and alternate activity-path strings do not join. */
[[nodiscard]] bool scenario_name(std::span<const std::byte> blob,
                                 std::size_t definition,
                                 std::string_view& output) noexcept {
    std::size_t offset = 0;
    bool absent = false;
    if (!relative(blob, definition + kScenarioPointer, offset, absent)) {
        return false;
    }
    if (absent) {
        return true;
    }
    for (std::size_t length = 0; length <= kActivityScenarioNameCapacity; ++length) {
        if (length >= blob.size() - offset) {
            return false;
        }
        const char value = static_cast<char>(blob[offset + length]);
        if (value == '\0') {
            output = {reinterpret_cast<const char*>(blob.data() + offset), length};
            return true;
        }
        if (length == kActivityScenarioNameCapacity
            || !((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
                 || value == '_')) {
            return false;
        }
    }
    return false;
}

} // namespace

bool activity_index(std::span<const std::byte> blob, Array& output) noexcept {
    output = {};
    Array candidate{};
    if (!find_array_at(blob, kTableArrayDescriptor, candidate)
        || !fits(blob, candidate, kActivityIndexClass, kIndexStride, kActivityIndexCapacity)) {
        return false;
    }
    output = candidate;
    return true;
}

bool activity_definition_at(std::span<const std::byte> blob,
                            const Array& array,
                            std::size_t index,
                            std::size_t typeCount,
                            ActivityDefinition& output) noexcept {
    output = {};
    if (!fits(blob, array, kActivityIndexClass, kIndexStride, kActivityIndexCapacity)
        || index >= array.count || typeCount == 0 || typeCount > kActivityTypeCapacity) {
        return false;
    }
    ActivityDefinition candidate{};
    const std::size_t entry = array.dataOffset + index * kIndexStride;
    std::size_t definition = 0;
    bool absent = false;
    std::uint32_t hash = 0;
    if (!read(blob, entry, hash) || !relative(blob, entry + 8, definition, absent) || absent
        || blob.size() - definition <= kTypeIndex || !read(blob, definition, candidate.hash)
        || candidate.hash != hash || !read(blob, definition + kTypeIndex, candidate.typeIndex)
        || candidate.typeIndex >= typeCount
        || !scenario_name(blob, definition, candidate.scenarioName)) {
        return false;
    }
    std::size_t playlist = 0;
    if (!relative(blob, definition + kPlaylistPointer, playlist, absent)) {
        return false;
    }
    if (!absent) {
        // The descriptor is after the playlist prefix. Empty descriptors need no dereference.
        if (blob.size() - playlist < 24) {
            return false;
        }
        std::uint64_t count = 0;
        if (!read(blob, playlist + 8, count)) {
            return false;
        }
        if (count != 0
            && (!find_array_at(blob, playlist + 8, candidate.playlist)
                || !fits(blob,
                         candidate.playlist,
                         kActivityPlaylistRowClass,
                         kPlaylistStride,
                         kActivityIndexCapacity))) {
            return false;
        }
    }
    output = candidate;
    return true;
}

bool activity_playlist_child_at(std::span<const std::byte> blob,
                                const Array& playlist,
                                std::size_t index,
                                std::size_t activityCount,
                                std::uint16_t& output) noexcept {
    output = 0;
    std::int16_t child = -1;
    if (!fits(blob, playlist, kActivityPlaylistRowClass, kPlaylistStride, kActivityIndexCapacity)
        || index >= playlist.count || activityCount > kActivityIndexCapacity
        || !read(blob, playlist.dataOffset + index * kPlaylistStride + 8, child) || child < 0
        || static_cast<std::size_t>(child) >= activityCount) {
        return false;
    }
    output = static_cast<std::uint16_t>(child);
    return true;
}

bool activity_types(std::span<const std::byte> blob, bool ui, Array& output) noexcept {
    output = {};
    Array candidate{};
    if (!find_array_at(blob, kTableArrayDescriptor, candidate)
        || !fits(blob,
                 candidate,
                 ui ? kActivityTypeUiRowClass : kActivityTypeRowClass,
                 ui ? kUiTypeStride : kIndexStride,
                 kActivityTypeCapacity)) {
        return false;
    }
    output = candidate;
    return true;
}

bool activity_type_hash_at(std::span<const std::byte> blob,
                           const Array& array,
                           std::size_t index,
                           std::uint32_t& output) noexcept {
    output = 0;
    return fits(blob, array, kActivityTypeRowClass, kIndexStride, kActivityTypeCapacity)
           && index < array.count && read(blob, array.dataOffset + index * kIndexStride, output);
}

bool activity_type_name_at(std::span<const std::byte> blob,
                           const Array& array,
                           std::size_t index,
                           ActivityTypeName& output) noexcept {
    output = {};
    if (!fits(blob, array, kActivityTypeUiRowClass, kUiTypeStride, kActivityTypeCapacity)
        || index >= array.count) {
        return false;
    }
    const std::size_t offset = array.dataOffset + index * kUiTypeStride;
    ActivityTypeName candidate{};
    if (!read(blob, offset, candidate.hash) || !read(blob, offset + 4, candidate.containerIndex)
        || !read(blob, offset + 8, candidate.resourceHash)) {
        return false;
    }
    output = candidate;
    return true;
}

bool activity_reference_tag(std::span<const std::byte> blob,
                            std::size_t offset,
                            std::uint32_t& output) noexcept {
    output = 0;
    std::uint32_t candidate = 0;
    if (!read(blob, offset, candidate) || package_of(candidate) == kAbsentPackageId) {
        return false;
    }
    output = candidate;
    return true;
}

bool activity_string_container_tag(std::span<const std::byte> blob,
                                   std::uint16_t index,
                                   std::uint32_t& output) noexcept {
    output = 0;
    Array array{};
    /** The registry has 3,108 rows; its name references use 16-bit ordinals. */
    constexpr std::size_t kRegistryCapacity = 65535;
    return find_array_at(blob, kTableArrayDescriptor, array)
           && fits(blob, array, kInvestmentStringRegistryRowClass, 8, kRegistryCapacity)
           && index < array.count
           && activity_reference_tag(
               blob, array.dataOffset + static_cast<std::size_t>(index) * 8 + 4, output);
}

/** Reads one archived activity definition. */
bool activity_metadata(std::span<const std::byte> blob, ActivityMetadata& output) noexcept {
    output = {};
    if (!read(blob, kDisplayNameHashOffset, output.displayNameHash)
        || !find_array_at(blob, kDefinitionTagDescriptorOffset, output.definitionTags)
        || output.definitionTags.elementClass != kActivityDefinitionTagClass
        || output.definitionTags.count > kActivityDefinitionTagCapacity) {
        output = {};
        return false;
    }
    return true;
}

/** Reads one tag from an activity's definition array. */
bool activity_definition_tag_at(std::span<const std::byte> blob,
                                const ActivityMetadata& activity,
                                std::uint64_t index,
                                std::uint32_t& tag) noexcept {
    tag = 0;
    std::size_t offset = 0;
    return element_offset(activity.definitionTags.dataOffset,
                          activity.definitionTags.count,
                          kActivityDefinitionTagStride,
                          index,
                          offset)
           && read(blob, offset, tag);
}

} // namespace sunrise::middleware::content::packages::tables
