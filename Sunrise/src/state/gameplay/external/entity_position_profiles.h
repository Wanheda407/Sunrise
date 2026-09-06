#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sunrise::state::gameplay::entity_position_profiles {
using Fingerprint = std::array<std::byte, 32>;
struct Row final {
    std::string activity;
    std::uint16_t cell{};
    std::array<std::uint8_t, 3> axisBits{};
    std::uint8_t bubble{255};
    bool operator==(const Row&) const = default;
};
using Rows = std::vector<Row>;
/** Bounds heap-owned catalogue and shared-cache scratch storage. */
inline constexpr std::size_t kMaximumRows = 65536;
/** Package names reserve one final null byte on disk. */
inline constexpr std::size_t kNameCapacity = 128;
/** Rejects duplicates and widths outside the native 31-bit bound. */
[[nodiscard]] bool validate(std::span<const Row> rows) noexcept;
/** Publishes only one complete, validated extraction. */
[[nodiscard]] bool publish(Rows rows, const Fingerprint& fingerprint) noexcept;
/** Checks whether the installed content already owns the published rows. */
[[nodiscard]] bool ready(const Fingerprint& fingerprint) noexcept;
/** Clears package-derived values before a new build is loaded. */
void reset() noexcept;
/** Restored rows remain unavailable until their package fingerprint is confirmed. */
[[nodiscard]] bool restore(std::span<const Row> rows, const Fingerprint& fingerprint) noexcept;
/** Confirms a restored shared-cache domain against the installed packages. */
[[nodiscard]] bool confirm(const Fingerprint& fingerprint) noexcept;
/** Reports whether validated package data is available for shared-cache publication. */
[[nodiscard]] bool available() noexcept;
/** Copies active rows and their fingerprint into shared-cache scratch. */
[[nodiscard]] bool
snapshot(std::span<Row> output, std::size_t& count, Fingerprint& fingerprint) noexcept;
/** Returns the exact map-to-scenario bubble join for one native cell. */
[[nodiscard]] bool
lookup_bubble(std::string_view activity, std::uint16_t cell, std::uint8_t& bubble) noexcept;
/** Looks up only package-validated widths for this exact activity and cell. */
[[nodiscard]] bool lookup(std::string_view activity,
                          std::uint16_t cell,
                          std::array<std::uint8_t, 3>& axisBits) noexcept;
} // namespace sunrise::state::gameplay::entity_position_profiles
