#include "activity_type_mapping.h"

#include <algorithm>

#include "activity_metadata_reader.h"

namespace sunrise::middleware::content::packages::tables {

bool activity_playlist_scenarios(std::span<const ActivityGraphNode> nodes,
                                 std::span<const std::uint16_t> children,
                                 std::size_t root,
                                 std::span<std::uint8_t> reachable,
                                 std::span<std::uint8_t> visited,
                                 std::span<std::uint16_t> queue) noexcept {
    std::fill(reachable.begin(), reachable.end(), std::uint8_t{0});
    std::fill(visited.begin(), visited.end(), std::uint8_t{0});
    if (nodes.size() > kActivityIndexCapacity || root >= nodes.size()
        || children.size() > kActivityPlaylistEdgeCapacity || visited.size() < nodes.size()
        || queue.size() < nodes.size()) {
        return false;
    }
    std::size_t queued = 1;
    queue[0] = static_cast<std::uint16_t>(root);
    visited[root] = 1;
    for (std::size_t cursor = 0; cursor < queued; ++cursor) {
        const ActivityGraphNode& node = nodes[queue[cursor]];
        if (node.firstChild > children.size() || node.childCount > children.size() - node.firstChild
            || (node.scenarioIndex != kUnmappedActivityScenario
                && node.scenarioIndex >= reachable.size())) {
            std::fill(reachable.begin(), reachable.end(), std::uint8_t{0});
            return false;
        }
        if (node.scenarioIndex != kUnmappedActivityScenario) {
            reachable[node.scenarioIndex] = 1;
        }
        for (const std::uint16_t child : children.subspan(node.firstChild, node.childCount)) {
            if (child >= nodes.size()) {
                std::fill(reachable.begin(), reachable.end(), std::uint8_t{0});
                return false;
            }
            if (visited[child] == 0) {
                // Visited is marked when enqueued, so duplicates cannot exhaust the queue.
                visited[child] = 1;
                queue[queued++] = child;
            }
        }
    }
    return true;
}

} // namespace sunrise::middleware::content::packages::tables
