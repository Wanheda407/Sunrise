#pragma once
#include <span>
#include <string>
#include <vector>

#include "../../../../state/gameplay/external/entity_position_profiles.h"
namespace sunrise::middleware::content::packages::position_profiles {
struct NamedTag final {
    std::string name;
    std::uint32_t tag{}, classId{};
    bool basePackage{};
};
struct KeyTag final {
    std::uint64_t key{};
    std::uint32_t tag{}, classId{};
};
using Read = bool (*)(void*, std::uint32_t, std::uint32_t, std::vector<std::byte>&) noexcept;
/** Reads the package array marker, element class, and full extent. */
[[nodiscard]] bool array(std::span<const std::byte> bytes,
                         std::size_t field,
                         std::size_t stride,
                         std::uint32_t elementClass,
                         std::vector<std::size_t>& offsets) noexcept;
/** Joins exact scenario cell owners to complete package bounds. */
[[nodiscard]] bool extract(std::span<const NamedTag> names,
                           std::span<const KeyTag> keys,
                           Read read,
                           void* context,
                           state::gameplay::entity_position_profiles::Rows& rows) noexcept;
} // namespace sunrise::middleware::content::packages::position_profiles
