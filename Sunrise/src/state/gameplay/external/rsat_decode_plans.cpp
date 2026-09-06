#include "rsat_decode_plans.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <regex>
#include <string>
#include <tuple>

#include "../../../middleware/crypto/sha256.h"

namespace sunrise::state::gameplay::rsat_decode_plans {
namespace {
static_assert(sizeof(AdditionalSchema) == 28);
static_assert(sizeof(AdditionalField) == 40);
static_assert(sizeof(PlanRow) == 24);
static_assert(sizeof(SchemaRow) == 16);
static_assert(sizeof(external::SobjectDecodeEntry) == 20);
/** Cache version 2 has a 136-byte header. */
constexpr std::size_t kHeaderSize = 136;
/** A cache load cannot reserve more than 16 MiB. */
constexpr std::size_t kMaximumBytes = 16 * 1024 * 1024;
std::uint32_t word(const std::vector<std::byte>& bytes, std::size_t offset) noexcept {
    std::uint32_t result{};
    std::memcpy(&result, bytes.data() + offset, sizeof(result));
    return result;
}
} // namespace
/**
 * Loads the cache beside its admitted SDK, using that directory's extraction manifest.
 * @param artifactDirectory Directory owning the mapped SDK and its generated children.
 * @param sdkBuild Expected SDK build digest.
 * @return False clears readiness when any required artifact is missing or invalid.
 */
bool Cache::load_installed(std::wstring_view artifactDirectory, const Digest& sdkBuild) noexcept {
    *this = {};
    if (artifactDirectory.empty()) return false;
    try {
        const auto cachePath =
            std::filesystem::path(artifactDirectory) / L"rsat_decode_plans.cache";
        std::ifstream manifest(cachePath.wstring() + L".json", std::ios::binary | std::ios::ate);
        /** An extraction manifest cannot exceed 1 MiB. */
        constexpr std::streamoff kMaximumManifestBytes = 1024 * 1024;
        if (!manifest || manifest.tellg() <= 0 || manifest.tellg() > kMaximumManifestBytes)
            return false;
        std::string contents(static_cast<std::size_t>(manifest.tellg()), '\0');
        manifest.seekg(0);
        if (!manifest.read(contents.data(), static_cast<std::streamsize>(contents.size())))
            return false;
        const auto digest = [&](const char* name, Digest& output) {
            const std::regex pattern(std::string("\"") + name + "\"\\s*:\\s*\"([0-9a-fA-F]{64})\"");
            std::sregex_iterator found(contents.begin(), contents.end(), pattern), end;
            if (found == end) return false;
            const std::string hex = (*found)[1];
            if (++found != end) return false;
            for (std::size_t index = 0; index < output.size(); ++index)
                output[index] =
                    static_cast<std::byte>(std::stoul(hex.substr(index * 2, 2), nullptr, 16));
            return true;
        };
        Digest declaredSdk{}, evidence{};
        return digest("sdkBuildHash", declaredSdk) && declaredSdk == sdkBuild
               && digest("evidenceFingerprint", evidence) && load(cachePath, sdkBuild, evidence);
    } catch (...) {
        return false;
    }
}

/**
 * Loads only a cache bound to the expected SDK and extraction evidence.
 * @param path Cache file.
 * @param sdkBuild Expected SDK build digest.
 * @param evidence Expected package and executable evidence digest.
 * @return False leaves this cache unavailable.
 */
bool Cache::load(const std::filesystem::path& path,
                 const Digest& sdkBuild,
                 const Digest& evidence) noexcept {
    *this = {};
    try {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream) return false;
        const auto length = stream.tellg();
        if (length < static_cast<std::streamoff>(kHeaderSize)
            || length > static_cast<std::streamoff>(kMaximumBytes))
            return false;
        std::vector<std::byte> bytes(static_cast<std::size_t>(length));
        stream.seekg(0);
        if (!stream.read(reinterpret_cast<char*>(bytes.data()), length)) return false;
        if (std::memcmp(bytes.data(), "SRRSATP2", 8) || word(bytes, 8) != 2
            || word(bytes, 12) != 86657 || std::memcmp(bytes.data() + 16, sdkBuild.data(), 32)
            || std::memcmp(bytes.data() + 48, evidence.data(), 32))
            return false;
        Digest digest{};
        if (!middleware::crypto::sha256::hash(std::span(bytes).subspan(kHeaderSize), digest)
            || std::memcmp(bytes.data() + 80, digest.data(), 32))
            return false;
        const auto np = word(bytes, 112), ne = word(bytes, 116);
        const auto ns = word(bytes, 120), nf = word(bytes, 124);
        const auto na = word(bytes, 128), nx = word(bytes, 132);
        const std::uint64_t expected = kHeaderSize + std::uint64_t(np) * 24 + std::uint64_t(ne) * 20
                                       + std::uint64_t(ns) * 16 + std::uint64_t(nf) * 4
                                       + std::uint64_t(na) * 28 + std::uint64_t(nx) * 40;
        if (expected != bytes.size()) return false;
        Cache next;
        next.plans_.resize(np);
        next.entries_.resize(ne);
        next.schemas_.resize(ns);
        next.fields_.resize(nf);
        next.additionalSchemas_.resize(na);
        next.additionalFields_.resize(nx);
        std::size_t at = kHeaderSize;
        auto copy = [&](auto& target) {
            const auto size = target.size() * sizeof(target[0]);
            if (size) std::memcpy(target.data(), bytes.data() + at, size);
            at += size;
        };
        copy(next.plans_);
        copy(next.entries_);
        copy(next.schemas_);
        copy(next.fields_);
        copy(next.additionalSchemas_);
        copy(next.additionalFields_);
        for (std::size_t i = 0; i < next.additionalSchemas_.size(); ++i) {
            const auto& row = next.additionalSchemas_[i];
            if (row.first > nx || row.count > nx - row.first || row.array > 16384
                || (row.array && row.count != 1)
                || (i && next.additionalSchemas_[i - 1].handle >= row.handle))
                return false;
        }
        for (const auto& row : next.additionalFields_) {
            if (row.type > 63 || row.presence > 1 || row.parameter2 > 255) return false;
        }
        for (std::size_t i = 0; i < next.schemas_.size(); ++i) {
            const auto& row = next.schemas_[i];
            if (row.first > nf || row.count > nf - row.first
                || (i && next.schemas_[i - 1].handle >= row.handle))
                return false;
        }
        for (std::size_t i = 0; i < next.plans_.size(); ++i) {
            const auto& row = next.plans_[i];
            if (row.first > ne || row.count > ne - row.first || row.active > 1
                || (row.active ? (!row.count || !row.bits || row.bits > 1048576)
                               : (row.count || row.bits)))
                return false;
            if (i
                && std::tie(next.plans_[i - 1].component, next.plans_[i - 1].schema)
                       >= std::tie(row.component, row.schema))
                return false;
            for (std::uint32_t j = 0; j < row.count; ++j) {
                const auto& entry = next.entries_[row.first + j];
                if (!entry.repeatCount || entry.repeatCount > 16384 || entry.guardBit >= row.bits
                    || entry.firstFieldBit > row.bits
                    || std::uint64_t(entry.firstFieldBit)
                               + std::uint64_t(entry.repeatCount - 1) * entry.fieldBitStride
                           > row.bits)
                    return false;
                const auto found = std::lower_bound(
                    next.schemas_.begin(),
                    next.schemas_.end(),
                    entry.schemaHandle,
                    [](const auto& item, auto handle) { return item.handle < handle; });
                if (found == next.schemas_.end() || found->handle != entry.schemaHandle)
                    return false;
            }
        }
        next.ready_ = true;
        *this = std::move(next);
        return true;
    } catch (...) {
        return false;
    }
}
/**
 * Resolves a component plan without consuming absent or unknown wire data.
 * @param component Component definition handle.
 * @param schema Selection package tag.
 * @param output Receives a borrowed plan on success.
 * @return False for an unavailable cache or unknown pair.
 */
bool Cache::plan(std::uint32_t component,
                 std::uint32_t schema,
                 external::SobjectDecodePlan& output) const noexcept {
    if (!ready_) return false;
    const auto key = std::pair(component, schema);
    const auto it =
        std::lower_bound(plans_.begin(), plans_.end(), key, [](const auto& row, const auto& value) {
            return std::pair(row.component, row.schema) < value;
        });
    if (it == plans_.end() || std::pair(it->component, it->schema) != key) return false;
    output = {std::span(entries_).subspan(it->first, it->count), it->bits, it->active != 0};
    return true;
}
/**
 * Resolves the serialized size for one schema.
 * @param handle Schema handle.
 * @param size Receives the serialized byte count.
 * @return False when the schema is unknown.
 */
bool Cache::schema(std::uint32_t handle, std::uint32_t& size) const noexcept {
    if (!ready_) return false;
    const auto it =
        std::lower_bound(schemas_.begin(), schemas_.end(), handle, [](const auto& row, auto value) {
            return row.handle < value;
        });
    if (it == schemas_.end() || it->handle != handle) return false;
    size = it->size;
    return true;
}
/**
 * Resolves a field bitmap offset within its schema.
 * @param handle Schema handle.
 * @param ordinal Field index within the schema.
 * @param bit Receives the bitmap offset.
 * @return False when the field is unknown.
 */
bool Cache::field(std::uint32_t handle, std::uint32_t ordinal, std::uint32_t& bit) const noexcept {
    if (!ready_) return false;
    const auto it =
        std::lower_bound(schemas_.begin(), schemas_.end(), handle, [](const auto& row, auto value) {
            return row.handle < value;
        });
    if (it == schemas_.end() || it->handle != handle || ordinal >= it->count) return false;
    bit = fields_[it->first + ordinal];
    return true;
}
bool resolve_plan(const void* context,
                  std::uint32_t component,
                  std::uint32_t schema,
                  external::SobjectDecodePlan& output) noexcept {
    return context && static_cast<const Cache*>(context)->plan(component, schema, output);
}
bool resolve_schema_layout(const void* context,
                           std::uint32_t handle,
                           std::uint32_t& size) noexcept {
    return context && static_cast<const Cache*>(context)->schema(handle, size);
}
bool resolve_field_layout(const void* context,
                          std::uint32_t handle,
                          std::uint32_t ordinal,
                          std::uint32_t& bit) noexcept {
    return context && static_cast<const Cache*>(context)->field(handle, ordinal, bit);
}
/**
 * Supplies an own package codec outside the executable schema table.
 * @param handle Package schema handle.
 * @param output Receives the serialized schema view.
 * @return False when the package schema is unknown.
 */
bool Cache::additional_schema(std::uint32_t handle, runtime::SchemaView& output) const noexcept {
    if (!ready_) return false;
    const auto it = std::lower_bound(additionalSchemas_.begin(),
                                     additionalSchemas_.end(),
                                     handle,
                                     [](const auto& row, auto key) { return row.handle < key; });
    if (it == additionalSchemas_.end() || it->handle != handle) return false;
    output = {handle, handle, it->array, 0x80000000U | it->first, it->count, it->serialized};
    return true;
}
/**
 * Supplies an own package field with its serialized offset and bitmap index.
 * @param row Field row marked with the package bit.
 * @param output Receives the field view.
 * @param nested Receives the nested schema handle.
 * @return False when the field row is unknown.
 */
bool Cache::additional_field(std::uint32_t row,
                             runtime::FieldView& output,
                             std::uint32_t& nested) const noexcept {
    if (!ready_ || !(row & 0x80000000U)) return false;
    const auto index = row & 0x7FFFFFFFU;
    if (index >= additionalFields_.size()) return false;
    const auto& field = additionalFields_[index];
    output = {};
    output.row = row;
    output.structOffset = field.serializedOffset;
    output.biasOrDynamic = field.bias;
    output.widthOrCountOffset = field.width;
    output.typeCode = field.type;
    output.presence = field.presence;
    output.parameter2 = static_cast<std::uint8_t>(field.parameter2);
    output.bitmapOffset = field.bitmapOffset;
    output.hasBitmapOffset = true;
    nested = field.nested;
    return true;
}
bool resolve_additional_schema(const void* context,
                               std::uint32_t handle,
                               runtime::SchemaView& output) noexcept {
    return context && static_cast<const Cache*>(context)->additional_schema(handle, output);
}
bool resolve_additional_field(const void* context,
                              std::uint32_t row,
                              runtime::FieldView& output,
                              std::uint32_t& nested) noexcept {
    return context && static_cast<const Cache*>(context)->additional_field(row, output, nested);
}
} // namespace sunrise::state::gameplay::rsat_decode_plans
