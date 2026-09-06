#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::content::packages::tables {

/** A definition that does not name a scenario in the caller's catalogue. */
inline constexpr std::uint16_t kUnmappedActivityScenario = 0xFFFFU;
/** Headroom above 1,407 measured playlist edges, with a fixed traversal work bound. */
inline constexpr std::size_t kActivityPlaylistEdgeCapacity = 16384;

/** Reduced activity graph node. Child ranges refer to the caller's flat edge array. */
struct ActivityGraphNode {
    std::uint16_t scenarioIndex{kUnmappedActivityScenario};
    std::uint8_t typeIndex{};
    std::uint32_t firstChild{};
    std::uint16_t childCount{};
};

/**
 * Marks scenarios reached by one playlist, including a name on the playlist itself.
 * Every node is visited at most once. Self-cycles, diamonds, and repeated edges are valid.
 * @param nodes Complete activity graph, with validated native type indices.
 * @param children Flat child-index array.
 * @param root Activity whose playlist uses are being collected.
 * @param reachable One byte per caller scenario, cleared before traversal and on failure.
 * @param visited Scratch with at least one byte per node, cleared before traversal.
 * @param queue Scratch with at least one index per node; no recursion or heap allocation.
 * @return True when all reached references are bounded and the traversal completed.
 */
[[nodiscard]] bool activity_playlist_scenarios(std::span<const ActivityGraphNode> nodes,
                                               std::span<const std::uint16_t> children,
                                               std::size_t root,
                                               std::span<std::uint8_t> reachable,
                                               std::span<std::uint8_t> visited,
                                               std::span<std::uint16_t> queue) noexcept;

} // namespace sunrise::middleware::content::packages::tables
