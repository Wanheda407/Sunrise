#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "../../../middleware/content/packages/reader/reader.h"
#include "../../../middleware/content/packages/tables/activity_metadata_reader.h"
#include "../../../middleware/content/packages/tables/activity_type_mapping.h"
#include "../../../state/build_data/scenarios/definition.h"

namespace sunrise::client::content::scenarios {

/** Fixed pass storage, owned by the existing scenario worker and kept off its stack. */
struct ActivityTypeStorage {
    std::vector<std::byte> activities{};
    std::vector<std::byte> nativeTypes{};
    std::vector<std::byte> uiTypes{};
    std::vector<std::byte> registry{};
    std::vector<std::byte> header{};
    std::vector<std::byte> language{};
    middleware::content::packages::tables::Array activityArray{};
    middleware::content::packages::tables::Array nativeTypeArray{};
    middleware::content::packages::tables::Array uiTypeArray{};
    std::array<state::build_data::scenarios::ActivityUse,
               middleware::content::packages::tables::kActivityTypeCapacity>
        types{};
    std::array<middleware::content::packages::tables::ActivityGraphNode,
               middleware::content::packages::tables::kActivityIndexCapacity>
        nodes{};
    std::array<std::uint16_t, middleware::content::packages::tables::kActivityPlaylistEdgeCapacity>
        edges{};
    std::size_t edgeCount{};
    std::array<std::uint8_t, middleware::content::packages::tables::kActivityIndexCapacity>
        visited{};
    std::array<std::uint16_t, middleware::content::packages::tables::kActivityIndexCapacity>
        queue{};
    std::array<std::uint8_t, state::build_data::scenarios::kDefinitionCapacity> reachable{};
    /** Evidence flags for each scenario/native type pair, before publishing stable hash keys. */
    std::array<
        std::array<std::uint8_t, middleware::content::packages::tables::kActivityTypeCapacity>,
        state::build_data::scenarios::kDefinitionCapacity>
        uses{};
    std::size_t typeCursor{};
    std::size_t activityCursor{};
    std::size_t playlistCursor{};
    std::size_t namesDecoded{};
    std::size_t nameFailures{};
    std::size_t directScenarios{};
    std::size_t mappedScenarios{};
    std::size_t overflowScenarios{};
    std::size_t playlists{};
    std::uint32_t uiRootTag{};
    std::size_t uiRootCount{};
    bool loaded{};
    bool uiLoaded{};
    bool built{};
};

/**
 * Resolves direct and playlist activity uses within bounded scenario-worker slices.
 * @param source Installed package directory and borrowed block keys.
 * @param scratch Existing package-reader scratch.
 * @param investmentRoot Root already resolved by the shared investment extraction pass.
 * @param storage Persistent pass storage, never retaining keys or borrowed package views.
 * @param rows Compacted live scenario rows, unchanged except for their activity-use metadata.
 * @return True when extraction finishes, including a diagnosed fallback to unclassified rows.
 */
[[nodiscard]] bool
build_activity_types(const middleware::content::packages::reader::Source& source,
                     middleware::content::packages::reader::Scratch& scratch,
                     std::span<const std::byte> investmentRoot,
                     ActivityTypeStorage& storage,
                     std::span<state::build_data::scenarios::Definition> rows) noexcept;

} // namespace sunrise::client::content::scenarios
