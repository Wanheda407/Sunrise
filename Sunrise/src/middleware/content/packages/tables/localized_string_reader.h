#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "definition_index_table.h"

namespace sunrise::middleware::content::packages::tables {

/** Tag class of a localized string-container header. */
inline constexpr std::uint32_t kLocalizedStringsClass = 0x80809A88U;
/** Element class of the combination rows in one language's string data. */
inline constexpr std::uint32_t kStringCombinationClass = 0x80809A8EU;
/** Resource hashes in an installed localized-string container. */
struct LocalizedStrings {
    Array hashes{};
};

/**
 * Reads one localized string-container header.
 * @param blob Whole string-container definition.
 * @param output Receives the hash array.
 * @return True when the hash index is structurally valid.
 */
[[nodiscard]] bool localized_strings(std::span<const std::byte> blob,
                                     LocalizedStrings& output) noexcept;

/**
 * Reads the verified English language tag from a localized string-container header.
 * @param blob Whole string-container definition.
 * @param tag Receives the selected language-data tag.
 * @return True when the selected slot contains a definition tag.
 */
[[nodiscard]] bool localized_english_tag(std::span<const std::byte> blob,
                                         std::uint32_t& tag) noexcept;

/** Reads one resource hash from a parsed string-container header. */
[[nodiscard]] bool localized_hash_at(std::span<const std::byte> headerBlob,
                                     const LocalizedStrings& header,
                                     std::uint64_t index,
                                     std::uint32_t& hash) noexcept;

/**
 * Reads the number of string combinations in one language-data definition.
 * @param languageBlob Whole language-data definition.
 * @param count Receives the bounded combination count.
 * @return True when the combination array is structurally valid.
 */
[[nodiscard]] bool localized_string_count(std::span<const std::byte> languageBlob,
                                          std::uint64_t& count) noexcept;

/**
 * Decodes one printable-ASCII string by its ordinal in parallel hash and combination arrays.
 * @param languageBlob Selected language-data definition.
 * @param index String ordinal from the container header.
 * @param output Cleared first and receives the decoded bytes without a terminator.
 * @param length Receives the decoded byte count.
 * @return True when the complete printable ASCII string fits.
 */
[[nodiscard]] bool localized_ascii_string_at(std::span<const std::byte> languageBlob,
                                             std::uint64_t index,
                                             std::span<char> output,
                                             std::uint8_t& length) noexcept;

} // namespace sunrise::middleware::content::packages::tables
