#pragma once

#include "../../../middleware/content/packages/reader/reader.h"

namespace sunrise::client::content::scenarios {

/**
 * Extracts every destination's bubble layout from the installed packages, once.
 * Layout collection, optional activity metadata, and roster extraction share one publication.
 *
 * @param source Package directory and borrowed block keys.
 * @param scratch Lock-owned block storage shared with the item build.
 * @param investmentRoot Root
 * already resolved by the shared investment package pass.
 * @return True when State already holds
 * the domain or a full pass publishes it.
 */
[[nodiscard]] bool build(const middleware::content::packages::reader::Source& source,
                         middleware::content::packages::reader::Scratch& scratch,
                         std::span<const std::byte> investmentRoot) noexcept;

} // namespace sunrise::client::content::scenarios
