#include "localized_string_reader.h"

#include <algorithm>
#include <limits>

#include "internal.h"

namespace sunrise::middleware::content::packages::tables {
namespace {

/** Localized-string field offsets recovered from the archived Shadowkeep package ABI. */
constexpr std::size_t kHashDescriptorOffset = 0x08;
constexpr std::size_t kEnglishTagOffset = 0x18;
constexpr std::size_t kCombinationDescriptorOffset = 0x48;
constexpr std::size_t kCombinationStride = 0x10;
constexpr std::size_t kCombinationPartCountOffset = 0x08;
constexpr std::size_t kPartStride = 0x20;
constexpr std::size_t kPartDataPointerOffset = 0x08;
constexpr std::size_t kPartByteLengthOffset = 0x14;
constexpr std::size_t kPartStringLengthOffset = 0x16;
constexpr std::size_t kPartCipherShiftOffset = 0x18;
/** Resource hashes are bare 32-bit values in the header array. */
constexpr std::size_t kHashStride = sizeof(std::uint32_t);
/** Bounds corrupt string headers before they can produce an unbounded hash walk. */
constexpr std::uint64_t kHashCapacity = 16'384;
/** Bounds corrupted combination metadata before it can produce a long walk. */
constexpr std::int64_t kPartCapacity = 64;
constexpr std::uint16_t kPartByteCapacity = 4096;

/** Resolves one signed pointer relative to its own field. */
[[nodiscard]] bool pointer_target(std::span<const std::byte> blob,
                                  std::size_t pointerOffset,
                                  std::size_t& target) noexcept {
    target = 0;
    std::int64_t relative = 0;
    if (pointerOffset > static_cast<std::size_t>((std::numeric_limits<std::int64_t>::max)())
        || !read(blob, pointerOffset, relative) || relative == 0) {
        return false;
    }
    const std::int64_t base = static_cast<std::int64_t>(pointerOffset);
    constexpr std::int64_t kMaximum = (std::numeric_limits<std::int64_t>::max)();
    constexpr std::int64_t kMinimum = (std::numeric_limits<std::int64_t>::min)();
    if ((relative > 0 && base > kMaximum - relative)
        || (relative < 0 && base < kMinimum - relative)) {
        return false;
    }
    const std::int64_t resolved = base + relative;
    if (resolved < 0 || static_cast<std::uint64_t>(resolved) >= blob.size()) {
        return false;
    }
    target = static_cast<std::size_t>(resolved);
    return true;
}

/** Appends one decoded ASCII part to the bounded output. */
[[nodiscard]] bool append_part(std::span<const std::byte> blob,
                               std::size_t part,
                               std::span<char> output,
                               std::size_t& used) noexcept {
    std::uint16_t byteLength = 0;
    std::uint16_t stringLength = 0;
    std::uint16_t cipherShift = 0;
    std::size_t data = 0;
    if (!pointer_target(blob, part + kPartDataPointerOffset, data)
        || !read(blob, part + kPartByteLengthOffset, byteLength)
        || !read(blob, part + kPartStringLengthOffset, stringLength)
        || !read(blob, part + kPartCipherShiftOffset, cipherShift) || byteLength == 0
        || byteLength > kPartByteCapacity || stringLength == 0 || stringLength != byteLength
        || used > output.size() || output.size() - used < byteLength) {
        return false;
    }
    for (std::size_t index = 0; index < byteLength; ++index) {
        std::uint8_t encoded = 0;
        if (!read(blob, data + index, encoded) || encoded > 0x7F) {
            return false;
        }
        const std::uint8_t decoded = static_cast<std::uint8_t>(encoded + cipherShift);
        if (decoded < 0x20 || decoded > 0x7E) {
            return false;
        }
        output[used++] = static_cast<char>(decoded);
    }
    return true;
}

} // namespace

/** Reads one localized string-container header. */
bool localized_strings(std::span<const std::byte> blob, LocalizedStrings& output) noexcept {
    output = {};
    if (!find_array_at(blob, kHashDescriptorOffset, output.hashes)
        || output.hashes.count > kHashCapacity) {
        output = {};
        return false;
    }
    return true;
}

/** Reads the verified English language tag from a localized string-container header. */
bool localized_english_tag(std::span<const std::byte> blob, std::uint32_t& tag) noexcept {
    tag = 0;
    return read(blob, kEnglishTagOffset, tag) && package_of(tag) != kAbsentPackageId;
}

/** Reads one resource hash from a parsed string-container header. */
bool localized_hash_at(std::span<const std::byte> headerBlob,
                       const LocalizedStrings& header,
                       std::uint64_t index,
                       std::uint32_t& hash) noexcept {
    hash = 0;
    std::size_t offset = 0;
    return element_offset(header.hashes.dataOffset, header.hashes.count, kHashStride, index, offset)
           && read(headerBlob, offset, hash);
}

/** Reads the number of string combinations in one language-data definition. */
bool localized_string_count(std::span<const std::byte> languageBlob,
                            std::uint64_t& count) noexcept {
    count = 0;
    Array combinations{};
    if (!find_array_at(languageBlob, kCombinationDescriptorOffset, combinations)
        || combinations.elementClass != kStringCombinationClass
        || combinations.count > kHashCapacity) {
        return false;
    }
    count = combinations.count;
    return true;
}

/** Decodes one printable-ASCII string by its ordinal in the parallel arrays. */
bool localized_ascii_string_at(std::span<const std::byte> languageBlob,
                               std::uint64_t index,
                               std::span<char> output,
                               std::uint8_t& length) noexcept {
    std::fill(output.begin(), output.end(), '\0');
    length = 0;
    if (output.empty() || output.size() > (std::numeric_limits<std::uint8_t>::max)()) {
        return false;
    }
    Array combinations{};
    if (!find_array_at(languageBlob, kCombinationDescriptorOffset, combinations)
        || combinations.elementClass != kStringCombinationClass
        || combinations.count > kHashCapacity || index >= combinations.count) {
        return false;
    }
    std::size_t combination = 0;
    std::size_t firstPart = 0;
    std::int64_t partCount = 0;
    if (!element_offset(
            combinations.dataOffset, combinations.count, kCombinationStride, index, combination)
        || !pointer_target(languageBlob, combination, firstPart)
        || !read(languageBlob, combination + kCombinationPartCountOffset, partCount)
        || partCount <= 0 || partCount > kPartCapacity) {
        return false;
    }
    std::size_t used = 0;
    for (std::int64_t part = 0; part < partCount; ++part) {
        const auto ordinal = static_cast<std::size_t>(part);
        if (ordinal > ((std::numeric_limits<std::size_t>::max)() - firstPart) / kPartStride
            || !append_part(languageBlob, firstPart + ordinal * kPartStride, output, used)) {
            std::fill(output.begin(), output.end(), '\0');
            return false;
        }
    }
    if (used == 0) {
        return false;
    }
    length = static_cast<std::uint8_t>(used);
    return true;
}

} // namespace sunrise::middleware::content::packages::tables
