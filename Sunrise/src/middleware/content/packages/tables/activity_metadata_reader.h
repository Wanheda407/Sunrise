#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "definition_index_table.h"

namespace sunrise::middleware::content::packages::tables {

/** Tag class of an activity definition in the archived Shadowkeep package set. */
inline constexpr std::uint32_t kActivityMetadataClass = 0x80808AAEU;
/** Element class of the definition-tag array each activity owns. */
inline constexpr std::uint32_t kActivityDefinitionTagClass = 0x80808491U;
/** A definition-tag array element is one bare 32-bit tag handle. */
inline constexpr std::size_t kActivityDefinitionTagStride = sizeof(std::uint32_t);
/** Corrupt activity metadata cannot cause an unbounded tag walk. */
inline constexpr std::size_t kActivityDefinitionTagCapacity = 64;

/** Activity fields needed to associate one player-facing name with its client scenario. */
struct ActivityMetadata {
    std::uint32_t displayNameHash{};
    Array definitionTags{};
};

/**
 * Reads one archived activity definition.
 * @param blob Whole activity definition.
 * @param output Receives the display-name hash and definition-tag array.
 * @return True when both fields are structurally valid.
 */
[[nodiscard]] bool activity_metadata(std::span<const std::byte> blob,
                                     ActivityMetadata& output) noexcept;

/**
 * Reads one tag from an activity's definition array.
 * @param blob Whole activity definition.
 * @param activity Parsed activity metadata.
 * @param index Tag ordinal.
 * @param tag Receives the tag handle.
 * @return True when the element lies inside the blob.
 */
[[nodiscard]] bool activity_definition_tag_at(std::span<const std::byte> blob,
                                              const ActivityMetadata& activity,
                                              std::uint64_t index,
                                              std::uint32_t& tag) noexcept;

/** Archived investment-root slots naming activities and their native types. */
inline constexpr std::size_t kActivityTableSlot = 4;
inline constexpr std::size_t kActivityTypeTableSlot = 5;
/** Package-entry classes, distinct from the inline array element classes. */
inline constexpr std::uint32_t kActivityTableClass = 0x808076F0U;
inline constexpr std::uint32_t kActivityTypeTableClass = 0x80807773U;
inline constexpr std::uint32_t kActivityTypeUiTableClass = 0x80805F3CU;
inline constexpr std::uint32_t kInvestmentStringRegistryClass = 0x80805F98U;
inline constexpr std::uint32_t kInvestmentUiRootClass = 0x80805BB1U;
/** UI-root references are tag handles, not the numeric investment root's slot ordinals. */
inline constexpr std::size_t kActivityTypeUiTagOffset = 0x70;
inline constexpr std::size_t kInvestmentStringRegistryTagOffset = 0x490;
/** Inline array element classes verified against the archived native consumers. */
inline constexpr std::uint32_t kActivityIndexClass = 0x808076FCU;
inline constexpr std::uint32_t kActivityTypeRowClass = 0x80807778U;
inline constexpr std::uint32_t kActivityTypeUiRowClass = 0x80805F40U;
inline constexpr std::uint32_t kActivityPlaylistRowClass = 0x80807736U;
inline constexpr std::uint32_t kInvestmentStringRegistryRowClass = 0x80805F9EU;
/** Headroom above 1,170 activities; indices in playlist rows are signed 16-bit values. */
inline constexpr std::size_t kActivityIndexCapacity = 4096;
/** Native definitions carry one byte of type index; it is not a public API mode enum. */
inline constexpr std::size_t kActivityTypeCapacity = 256;
/** Scenario names are bounded by the 40-byte selection field. */
inline constexpr std::size_t kActivityScenarioNameCapacity = 40;

/** Borrowed fields of one activity definition; views remain valid only while its blob lives. */
struct ActivityDefinition {
    std::uint32_t hash{};
    std::uint8_t typeIndex{};
    std::string_view scenarioName{};
    Array playlist{};
};

/** One native type's ordinary UI name reference, not its conditional secondary display name. */
struct ActivityTypeName {
    std::uint32_t hash{};
    std::uint16_t containerIndex{};
    std::uint32_t resourceHash{};
};

/** Reads and validates the complete extent of the activity index array. */
[[nodiscard]] bool activity_index(std::span<const std::byte> blob, Array& output) noexcept;
/** Reads one definition, including its optional scenario name and playlist descriptor. */
[[nodiscard]] bool activity_definition_at(std::span<const std::byte> blob,
                                          const Array& array,
                                          std::size_t index,
                                          std::size_t typeCount,
                                          ActivityDefinition& output) noexcept;
/** Reads a playlist's child activity index and rejects negative/out-of-table references. */
[[nodiscard]] bool activity_playlist_child_at(std::span<const std::byte> blob,
                                              const Array& playlist,
                                              std::size_t index,
                                              std::size_t activityCount,
                                              std::uint16_t& output) noexcept;
/** Reads the native type table, or its parallel UI table when ui is true. */
[[nodiscard]] bool activity_types(std::span<const std::byte> blob, bool ui, Array& output) noexcept;
/** Reads a stable type hash from the native type table. */
[[nodiscard]] bool activity_type_hash_at(std::span<const std::byte> blob,
                                         const Array& array,
                                         std::size_t index,
                                         std::uint32_t& output) noexcept;
/** Reads the normal localized name reference from one UI type row. */
[[nodiscard]] bool activity_type_name_at(std::span<const std::byte> blob,
                                         const Array& array,
                                         std::size_t index,
                                         ActivityTypeName& output) noexcept;
/** Reads one bounded tag reference, rejecting values outside the installed definition range. */
[[nodiscard]] bool activity_reference_tag(std::span<const std::byte> blob,
                                          std::size_t offset,
                                          std::uint32_t& output) noexcept;
/** Resolves a UI name's string-container index through the investment string registry. */
[[nodiscard]] bool activity_string_container_tag(std::span<const std::byte> blob,
                                                 std::uint16_t index,
                                                 std::uint32_t& output) noexcept;

} // namespace sunrise::middleware::content::packages::tables
