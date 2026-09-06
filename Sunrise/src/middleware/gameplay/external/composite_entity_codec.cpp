#include "composite_entity_codec.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <span>

#include "../../encoding/bit_raw.h"

namespace sunrise::middleware::gameplay::external {
namespace {

namespace format = state::activity_sdk::format;
namespace wire = actor_wire;
namespace bits = middleware::encoding::bits;

/** Marks a retained mirror body so another callback's layout cannot be read as one. */
constexpr std::uint32_t kMirrorIdentity = 0x4345324DU;
/** The transform's packed angle code is seven bits. */
constexpr std::uint8_t kAngleWidth = 7;
/** Position components travel as raw 32-bit floats. */
constexpr std::uint8_t kFloatWidth = 32;
/** A transform names X, Y and Z. The fourth homogeneous lane is implied. */
constexpr std::size_t kPositionComponents = 3;
/** The walker view stores the type code and codec parameter 2 as one byte each. */
constexpr std::uint32_t kMaximumByteField = 0xFFU;
/** A schema reference the mirror retains must fit one 32-bit tag. */
constexpr std::uint64_t kMaximumSemanticTag = 0xFFFFFFFFULL;

/** Private header distinguishes retained mirror bodies from other payload layouts. */
struct MirrorHeader final {
    std::uint32_t identity{kMirrorIdentity};
    std::uint32_t semanticTag{};
    std::uint16_t bitCount{};
    std::uint16_t reserved{};
};

/** One validated header and its exact body bytes. */
struct MirrorView final {
    MirrorHeader header{};
    std::span<const std::byte> bytes{};
};

/** One reflection walk is bound to an SDK view and codec family. */
struct ResolverContext final {
    const CompositeEntityCodecContext* catalog{};
    format::RuntimeCodecFamily family{format::RuntimeCodecFamily::activity};
    std::span<std::uint8_t> presence{};
    std::uint32_t firstFieldBit{};
    std::uint32_t componentTag{};
};

/** Finds one unique runtime schema handle in the pinned view. */
[[nodiscard]] const format::RuntimeSchema*
runtime_schema(const CompositeEntityCodecContext& context, std::uint32_t handle) noexcept {
    for (const format::RuntimeSchema& row : context.runtimeSchemas) {
        if (row.handle == handle) {
            return &row;
        }
    }
    return nullptr;
}

/** Finds one installed RSAT in its generated tag order. */
[[nodiscard]] const format::SobjectRsat* sobject_rsat(const CompositeEntityCodecContext& context,
                                                      std::uint32_t tag) noexcept {
    const auto found =
        std::lower_bound(context.sobjectRsats.begin(),
                         context.sobjectRsats.end(),
                         tag,
                         [](const auto& row, auto value) { return row.rsatTag < value; });
    return found != context.sobjectRsats.end() && found->rsatTag == tag ? &*found : nullptr;
}

/** Builds one bounded canonical body while the input is decoded. */
class MirrorBuilder final {
public:
    state::gameplay::entity_identity::ActorSourceReference actorSource{};
    /** Opens an empty fixed-capacity bit writer. */
    MirrorBuilder() noexcept : writer_(bytes_) {}

    /** Appends one scalar field. */
    [[nodiscard]] bool append(std::uint64_t value, std::uint8_t width) noexcept {
        return writer_.write(value, width);
    }

    /** Appends an exact meaningful-bit prefix from byte storage. */
    [[nodiscard]] bool append(std::span<const std::byte> bytes, std::size_t bitCount) noexcept {
        bits::Reader reader(bytes);
        return bits::copy(reader, writer_, bitCount);
    }

    /** Seals the canonical body into callback-owned payload state. */
    [[nodiscard]] bool finish(std::uint32_t semanticTag, TypePayload& output) noexcept {
        std::size_t byteCount = 0;
        if (!writer_.finish(byteCount) || writer_.bit_count() > kMaximumTypePayloadBits
            || byteCount + sizeof(MirrorHeader) > output.state.size()) {
            return false;
        }
        MirrorHeader header{};
        header.semanticTag = semanticTag;
        header.bitCount = static_cast<std::uint16_t>(writer_.bit_count());
        TypePayload candidate{};
        std::memcpy(candidate.state.data(), &header, sizeof(header));
        std::memcpy(candidate.state.data() + sizeof(header), bytes_.data(), byteCount);
        candidate.byteCount = static_cast<std::uint16_t>(sizeof(header) + byteCount);
        candidate.actorSource = actorSource;
        output = candidate;
        return true;
    }

private:
    std::array<std::byte, kMaximumTypePayloadBits / 8U> bytes_{};
    bits::Writer writer_;
};

/** Compares every field protected by a staged registry commit. */
[[nodiscard]] bool same_slot(const EntityBaselineSlot& left,
                             const EntityBaselineSlot& right) noexcept {
    return left.allocationEpoch == right.allocationEpoch
           && left.hasAllocationEpoch == right.hasAllocationEpoch
           && left.allocationDomain == right.allocationDomain
           && left.serialDomain == right.serialDomain && left.rsatTag == right.rsatTag
           && left.allocationSequence == right.allocationSequence
           && left.incarnation == right.incarnation && left.type == right.type
           && left.occupied == right.occupied && left.known == right.known
           && left.hasPacketSequence == right.hasPacketSequence
           && left.packetSequence == right.packetSequence
           && left.packetOrdinal == right.packetOrdinal
           && left.sobjectPlacement == right.sobjectPlacement
           && left.anchorPresent == right.anchorPresent && left.anchorOrder == right.anchorOrder
           && left.anchor.slot == right.anchor.slot
           && left.anchor.incarnation == right.anchor.incarnation;
}

/** Checks the complete 17-bit entity-token domain. */
[[nodiscard]] bool valid_token(const EntityToken& token) noexcept {
    return token.slot <= kMaximumEntitySlot && token.incarnation <= kMaximumEntityIncarnation;
}

/** Validates and opens one callback-owned canonical mirror. */
[[nodiscard]] bool load_mirror(const TypePayload& payload, MirrorView& output) noexcept {
    if (payload.byteCount < sizeof(MirrorHeader) || payload.byteCount > payload.state.size()) {
        return false;
    }
    MirrorHeader header{};
    std::memcpy(&header, payload.state.data(), sizeof(header));
    const std::size_t byteCount = (static_cast<std::size_t>(header.bitCount) + 7U) / 8U;
    if (header.identity != kMirrorIdentity || header.reserved != 0
        || header.bitCount > kMaximumTypePayloadBits
        || payload.byteCount != sizeof(header) + byteCount) {
        return false;
    }
    output.header = header;
    output.bytes = {payload.state.data() + sizeof(header), byteCount};
    return true;
}

/** Reads one field and retains the same wire bits. */
[[nodiscard]] bool read_and_append(bits::Reader& reader,
                                   MirrorBuilder& mirror,
                                   std::uint8_t width,
                                   std::uint64_t& output) noexcept {
    return reader.read(width, output) && mirror.append(output, width);
}

/** Reads and retains one required boolean field. */
[[nodiscard]] bool read_flag(bits::Reader& reader, MirrorBuilder& mirror, bool& output) noexcept {
    std::uint64_t value = 0;
    if (!read_and_append(reader, mirror, kFlagWidth, value)) {
        return false;
    }
    output = value != 0;
    return true;
}

/** Resolves one schema only when it supports the selected codec family. */
[[nodiscard]] bool
find_schema(const void* raw, std::uint32_t handle, wire::runtime::SchemaView& output) noexcept {
    const auto* const context = static_cast<const ResolverContext*>(raw);
    if (context == nullptr || context->catalog == nullptr) {
        return false;
    }
    const format::RuntimeSchema* row = runtime_schema(*context->catalog, handle);
    if (row == nullptr && context->catalog->resolveAdditionalSchema != nullptr) {
        return context->catalog->resolveAdditionalSchema(
                   context->catalog->planContext, handle, output)
               && output.handle == handle && output.row == handle;
    }
    constexpr std::uint32_t kAllowedFlags =
        format::kRuntimeSchemaExact | format::kRuntimeSchemaArrayRegion;
    const bool arrayRegion =
        row != nullptr && (row->flags & format::kRuntimeSchemaArrayRegion) != 0;
    if (row == nullptr || (row->flags & format::kRuntimeSchemaExact) == 0
        || (row->flags & ~kAllowedFlags) != 0 || arrayRegion != (row->arrayElementCount != 0)
        || (context->family == format::RuntimeCodecFamily::activity
            && (row->codecFamilies & static_cast<std::uint32_t>(context->family)) == 0)) {
        return false;
    }
    const auto schemas = context->catalog->runtimeSchemas;
    const auto fields = context->catalog->runtimeFields;
    if (row < schemas.data() || row >= schemas.data() + schemas.size()
        || row->fields.first > fields.size()
        || row->fields.count > fields.size() - row->fields.first) {
        return false;
    }
    output.row = static_cast<std::uint32_t>(row - schemas.data());
    output.handle = row->handle;
    output.arrayLength = row->arrayElementCount;
    output.firstField = row->fields.first;
    output.fieldCount = row->fields.count;
    output.structSize = row->decodedSize;
    if (context->family != format::RuntimeCodecFamily::activity
        && context->catalog->resolveSchemaLayout != nullptr
        && !context->catalog->resolveSchemaLayout(
            context->catalog->planContext, row->handle, output.structSize))
        return false;
    return true;
}

/** Resolves one schema by its stable generated row index. */
[[nodiscard]] bool
read_schema(const void* raw, std::uint32_t rowIndex, wire::runtime::SchemaView& output) noexcept {
    const auto* const context = static_cast<const ResolverContext*>(raw);
    if (context == nullptr || context->catalog == nullptr) {
        return false;
    }
    if (rowIndex >= context->catalog->runtimeSchemas.size())
        return find_schema(raw, rowIndex, output) && output.row == rowIndex;
    return find_schema(raw, context->catalog->runtimeSchemas[rowIndex].handle, output)
           && output.row == rowIndex;
}

/** Converts one SDK field row into the generic runtime walker view. */
[[nodiscard]] bool
read_field(const void* raw, std::uint32_t rowIndex, wire::runtime::FieldView& output) noexcept {
    const auto* const context = static_cast<const ResolverContext*>(raw);
    if (context == nullptr || context->catalog == nullptr) {
        return false;
    }
    if (rowIndex >= context->catalog->runtimeFields.size()) {
        std::uint32_t nested = format::kAbsentIndex;
        if (context->catalog->resolveAdditionalField == nullptr
            || !context->catalog->resolveAdditionalField(
                context->catalog->planContext, rowIndex, output, nested)
            || output.row != rowIndex)
            return false;
        if (nested != format::kAbsentIndex) {
            wire::runtime::SchemaView target{};
            if (!find_schema(raw, nested, target)) return false;
            output.nestedSchemaRow = target.row;
        }
        if (context->family == format::RuntimeCodecFamily::sobjectModeOne && output.typeCode == 20)
            output.typeCode = 18;
        if (context->family == format::RuntimeCodecFamily::sobjectModeOne && output.typeCode == 29)
            output.typeCode = 43;
        return true;
    }
    const format::RuntimeField& row = context->catalog->runtimeFields[rowIndex];
    if (row.schemaIndex >= context->catalog->runtimeSchemas.size()
        || (row.flags & format::kRuntimeFieldExact) == 0 || row.typeCode > kMaximumByteField) {
        return false;
    }
    std::uint32_t nestedRow = wire::runtime::kAbsentRuntimeRow;
    if (row.nestedHandle != format::kAbsentIndex) {
        wire::runtime::SchemaView nested{};
        if (!find_schema(raw, row.nestedHandle, nested)) {
            return false;
        }
        nestedRow = nested.row;
    }
    std::int32_t bias = 0;
    if (row.bias != format::kAbsentSignedValue) {
        if (row.bias < (std::numeric_limits<std::int32_t>::min)()
            || row.bias > (std::numeric_limits<std::int32_t>::max)()) {
            return false;
        }
        bias = static_cast<std::int32_t>(row.bias);
    }
    const bool dynamicArray = (row.flags & format::kRuntimeFieldDynamicArray) != 0;
    const bool quantized =
        row.typeCode == static_cast<std::uint32_t>(format::RuntimeFieldType::quantizedFloat)
        || row.typeCode == 42;
    output = {};
    output.row = rowIndex;
    output.nestedSchemaRow = nestedRow;
    output.structOffset = context->family == format::RuntimeCodecFamily::activity
                              ? row.structOffset
                              : row.alternateOffset;
    if (context->family != format::RuntimeCodecFamily::activity
        && context->catalog->resolveFieldLayout != nullptr) {
        output.hasBitmapOffset = context->catalog->resolveFieldLayout(
            context->catalog->planContext,
            context->catalog->runtimeSchemas[row.schemaIndex].handle,
            row.ordinal,
            output.bitmapOffset);
    }
    output.biasOrDynamic = quantized      ? static_cast<std::int32_t>(row.codecParameters[0])
                           : dynamicArray ? 1
                                          : bias;
    output.widthOrCountOffset = quantized || dynamicArray || row.typeCode == 44
                                    ? static_cast<std::int32_t>(row.codecParameters[1])
                                : row.bits == format::kAbsentIndex
                                    ? 0
                                    : static_cast<std::int32_t>(row.bits);
    output.typeCode = static_cast<std::uint8_t>(row.typeCode);
    if (context->family == format::RuntimeCodecFamily::sobjectModeOne && output.typeCode == 20)
        output.typeCode = 18;
    if (context->family == format::RuntimeCodecFamily::sobjectModeOne && output.typeCode == 29)
        output.typeCode = 43;
    output.presence =
        static_cast<std::uint8_t>((row.flags & format::kRuntimeFieldPresenceBit) != 0);
    output.parameter2 = static_cast<std::uint8_t>(
        row.codecParameters[2] <= kMaximumByteField ? row.codecParameters[2] : 0);
    return true;
}

/** Accepts a union selector only when its family-specific SDK row exists. */
[[nodiscard]] bool validate_type(const void* raw, std::uint8_t typeCode) noexcept {
    const auto* const context = static_cast<const ResolverContext*>(raw);
    if (context == nullptr || context->catalog == nullptr) {
        return false;
    }
    const std::uint32_t family = static_cast<std::uint32_t>(context->family);
    return std::any_of(context->catalog->runtimeTypes.begin(),
                       context->catalog->runtimeTypes.end(),
                       [family, typeCode](const format::RuntimeTypeDefinition& row) {
                           return row.typeCode == typeCode && (row.codecFamilies & family) != 0;
                       });
}

/** Accepts one exact family-specific unsupported type only when it consumes no bits. */
[[nodiscard]] bool zero_bit_type(const void* raw, std::uint8_t typeCode) noexcept {
    const auto* const context = static_cast<const ResolverContext*>(raw);
    if (context == nullptr || context->catalog == nullptr) {
        return false;
    }
    const std::uint32_t family = static_cast<std::uint32_t>(context->family);
    const format::RuntimeTypeDefinition* match = nullptr;
    for (const format::RuntimeTypeDefinition& row : context->catalog->runtimeTypes) {
        if (row.typeCode != typeCode || (row.codecFamilies & family) == 0) {
            continue;
        }
        if (match != nullptr) {
            return false;
        }
        match = &row;
    }
    return match != nullptr && (match->flags & format::kRuntimeTypeDefinitionExact) != 0
           && (match->flags & format::kRuntimeTypeUnsupported) != 0 && match->fixedBits == 0
           && match->minimumBits == 0 && match->maximumBits == 0 && match->reserved == 0;
}

/** Per-field presence updates the component's compiled selection bitmap. */
static bool record_presence(const void* raw, std::uint32_t bit, bool present) noexcept {
    const auto& context = *static_cast<const ResolverContext*>(raw);
    if (bit >= context.presence.size()) return false;
    context.presence[bit] = present ? 1 : 0;
    return true;
}

/** T11 reference aliases share wire forms without changing other codec families. */
static std::uint8_t canonical_type(const void* raw, std::uint8_t type) noexcept {
    const auto& context = *static_cast<const ResolverContext*>(raw);
    if (context.family == format::RuntimeCodecFamily::sobjectModeOne) {
        if (type == 20) return 18;
        if (type == 29) return 43;
    }
    return type;
}

/** The native action selector chooses one exact SDK-declared payload schema. */
static bool
resolve_command_payload(const void* raw, std::uint8_t selector, std::uint32_t& output) noexcept {
    output = 0;
    const auto& context = *static_cast<const ResolverContext*>(raw);
    if (context.catalog->catalog == nullptr) return false;
    bool found = false;
    for (const auto& command : context.catalog->catalog->actor_command_definitions()) {
        if (command.selector != selector) continue;
        if (found || command.flags != format::kActorCommandDefinitionExact
            || command.payloadHandle == 0 || command.payloadHandle == format::kAbsentIndex)
            return false;
        found = true;
        output = command.payloadHandle;
    }
    return found;
}

/** Builds borrowed reflection callbacks over one stable resolver context. */
[[nodiscard]] wire::RuntimeSchemaResolver make_resolver(ResolverContext& context) noexcept {
    wire::RuntimeSchemaResolver resolver{};
    resolver.context = &context;
    resolver.findSchema = find_schema;
    resolver.readSchema = read_schema;
    resolver.readField = read_field;
    resolver.validateType = validate_type;
    resolver.isZeroBitType = zero_bit_type;
    resolver.positionProfile = &context.catalog->positionProfile;
    resolver.recordPresence = context.presence.empty() ? nullptr : record_presence;
    resolver.firstFieldBit = context.firstFieldBit;
    resolver.canonicalType = canonical_type;
    resolver.nativeCommandEmptyShortcut =
        context.family == format::RuntimeCodecFamily::sobjectModeOne;
    resolver.resolveCommandPayload = resolve_command_payload;
    return resolver;
}

/** Decodes, re-encodes, and retains one complete reflected schema body. */
[[nodiscard]] bool append_schema(bits::Reader& reader,
                                 MirrorBuilder& mirror,
                                 ResolverContext& resolverContext,
                                 std::uint32_t schemaHandle,
                                 std::uint32_t* semanticTag) noexcept {
    const wire::RuntimeSchemaResolver resolver = make_resolver(resolverContext);
    std::array<wire::RuntimeDecodedValue, wire::kRuntimeValueCapacity> values{};
    wire::RuntimeDecodeResult result{};
    if (!wire::decode_full_schema_prefix(schemaHandle, reader, resolver, values, result)
        || result.status != wire::CodecStatus::complete || result.valuesTruncated
        || result.valueCount > values.size()) {
#if defined(SUNRISE_ACTIVITY_SDK_TESTING)
        if (resolverContext.catalog->schemaValues != nullptr && result.valueCount <= values.size())
            resolverContext.catalog->schemaValues(schemaHandle,
                                                  std::span(values).first(result.valueCount));
        if (resolverContext.catalog->schemaFailure != nullptr) {
            const auto field = result.valueCount != 0 && result.valueCount <= values.size()
                                   ? values[result.valueCount - 1].fieldRow
                                   : format::kAbsentIndex;
            resolverContext.catalog->schemaFailure(schemaHandle,
                                                   field,
                                                   result,
                                                   result.valueCount != 0
                                                           && result.valueCount <= values.size()
                                                       ? &values[result.valueCount - 1]
                                                       : nullptr);
        }
#endif
        return false;
    }
    std::array<wire::RuntimeDraftValue, wire::kRuntimeValueCapacity> draft{};
#if defined(SUNRISE_ACTIVITY_SDK_TESTING)
    if (resolverContext.catalog->schemaValues != nullptr)
        resolverContext.catalog->schemaValues(schemaHandle,
                                              std::span(values).first(result.valueCount));
#endif
    for (std::size_t index = 0; index < result.valueCount; ++index) {
        static_cast<wire::RuntimeDraftValue&>(draft[index]) = values[index];
    }
    std::array<std::byte, kMaximumTypePayloadBits / 8U> encoded{};
    std::size_t written = 0;
    std::size_t writtenBits = 0;
    wire::CodecStatus status = wire::CodecStatus::malformed;
    if (!wire::encode_full_schema(
            schemaHandle,
            std::span<const wire::RuntimeDraftValue>{draft.data(), result.valueCount},
            resolver,
            encoded,
            written,
            writtenBits,
            status)
        || status != wire::CodecStatus::complete || writtenBits != result.bitsConsumed
        || !mirror.append(std::span<const std::byte>{encoded.data(), written}, writtenBits)) {
#if defined(SUNRISE_ACTIVITY_SDK_TESTING)
        if (resolverContext.catalog->schemaFailure != nullptr) {
            result.status = status;
            resolverContext.catalog->schemaFailure(
                schemaHandle, static_cast<std::uint32_t>(writtenBits), result, nullptr);
        }
#endif
        return false;
    }
    if (semanticTag != nullptr) {
        const std::uint64_t nullableType =
            static_cast<std::uint32_t>(format::RuntimeFieldType::nullableTag);
        bool selected = false;
        bool found = false;
        std::uint32_t tag = 0;
        for (std::size_t index = 0; index < result.valueCount; ++index) {
            const wire::RuntimeDecodedValue& value = values[index];
            if (value.role == wire::ValueRole::variantSelector
                && value.unsignedValue == nullableType) {
                selected = true;
            } else if (selected && value.role == wire::ValueRole::schemaReference && value.present
                       && value.unsignedValue <= kMaximumSemanticTag) {
                if (found) {
                    return false;
                }
                found = true;
                tag = static_cast<std::uint32_t>(value.unsignedValue);
            }
        }
        if (!found || tag == 0 || tag == format::kAbsentIndex) {
            return false;
        }
        *semanticTag = tag;
    }
    if (resolverContext.componentTag == 0x80C70EDCU && schemaHandle == 0x80C70EDCU) {
        wire::runtime::SchemaView component{}, source{}, reference{};
        wire::runtime::FieldView componentField{}, sourceField{};
        if (!find_schema(&resolverContext, schemaHandle, component) || component.fieldCount != 1
            || !read_field(&resolverContext, component.firstField, componentField)
            || componentField.typeCode != 1 || componentField.structOffset != 0
            || !read_schema(&resolverContext, componentField.nestedSchemaRow, source)
            || source.handle != 0x808090E6U || source.fieldCount == 0
            || !read_field(&resolverContext, source.firstField, sourceField)
            || sourceField.typeCode != 1 || sourceField.structOffset != 0
            || !read_schema(&resolverContext, sourceField.nestedSchemaRow, reference)
            || reference.handle != 0x80809C42U || reference.fieldCount != 3)
            return false;
        std::array<const wire::RuntimeDecodedValue*, 3> fields{};
        for (const auto& value : std::span(values).first(result.valueCount)) {
            if (value.schemaHandle != reference.handle || value.role != wire::ValueRole::scalar)
                continue;
            if (value.fieldRow < reference.firstField || value.fieldRow >= reference.firstField + 3
                || value.occurrence != 0 || !value.present)
                return false;
            auto& field = fields[value.fieldRow - reference.firstField];
            if (field != nullptr) return false;
            field = &value;
        }
        if (fields[0] != nullptr && fields[1] != nullptr && fields[2] != nullptr) {
            const auto key = fields[0]->unsignedValue;
            const auto type = fields[1]->signedValue;
            const auto index = fields[2]->signedValue;
            if (key == 0x811C9DC5U && type == -1 && index == -1) {
                mirror.actorSource = {};
                mirror.actorSource.known = true;
            } else if (key != 0 && key != 0xFFFFFFFFU && key <= 0xFFFFFFFFU && type >= 0
                       && type <= 126 && index >= 0 && index <= 32767) {
                mirror.actorSource.key = static_cast<std::uint32_t>(key);
                mirror.actorSource.type = static_cast<std::uint8_t>(type);
                mirror.actorSource.index = static_cast<std::uint16_t>(index);
                mirror.actorSource.known = true;
                mirror.actorSource.present = true;
            }
        }
    }
    return true;
}

/** Resolves one exact channel-2 type contract from the SDK. */
[[nodiscard]] const format::EntityTypeDefinition*
entity_definition(const CompositeEntityCodecContext& context, EntityType type) noexcept {
    for (const format::EntityTypeDefinition& row : context.entityTypes) {
        if (row.entityType == static_cast<std::uint32_t>(type)) {
            return (row.flags & format::kEntityTypeDefinitionExact) != 0 ? &row : nullptr;
        }
    }
    return nullptr;
}

/** Decodes one retained typed mirror through its published executable schema. */
bool decode_composite_entity_payload_impl(const state::activity_sdk::Snapshot& catalog,
                                          EntityType type,
                                          TypePayloadPart part,
                                          const TypePayload& payload,
                                          std::span<wire::RuntimeDecodedValue> values,
                                          wire::RuntimeDecodeResult& result) noexcept {
    result = {};
    if (catalog == nullptr) {
        return false;
    }
    CompositeEntityCodecContext context{};
    context.catalog = catalog;
    context.entityTypes = catalog->entity_type_definitions();
    context.sobjectRsats = catalog->sobject_rsats();
    context.sobjectDescriptors = catalog->sobject_rsat_descriptors();
    context.rsatSchemas = catalog->rsat_schemas();
    context.rsatFields = catalog->rsat_fields();
    context.sobjectBindings = catalog->sobject_rsat_field_bindings();
    context.runtimeSchemas = catalog->runtime_schemas();
    context.runtimeFields = catalog->runtime_fields();
    context.runtimeTypes = catalog->runtime_type_definitions();
    context.ready = true;
    const format::EntityTypeDefinition* definition = entity_definition(context, type);
    const std::uint32_t schemaHandle = definition == nullptr ? format::kAbsentIndex
                                       : part == TypePayloadPart::baseline
                                           ? definition->baselineSchema
                                           : definition->updateSchema;
    MirrorView mirror{};
    if (schemaHandle == format::kAbsentIndex || !load_mirror(payload, mirror)) {
        return false;
    }
    ResolverContext resolverContext{&context,
                                    part == TypePayloadPart::baseline
                                        ? format::RuntimeCodecFamily::activity
                                        : format::RuntimeCodecFamily::sobjectModeOne};
    const wire::RuntimeSchemaResolver resolver = make_resolver(resolverContext);
    if (part == TypePayloadPart::update) {
        bits::Reader reader(mirror.bytes);
        std::uint64_t present = 0;
        if (mirror.header.bitCount == 0 || !reader.read(1, present)) return false;
        if (!present) {
            result.status = wire::CodecStatus::complete;
            result.bitsConsumed = 1;
            return mirror.header.bitCount == 1;
        }
        const bool decoded =
            wire::decode_full_schema_prefix(schemaHandle, reader, resolver, values, result);
        ++result.bitsConsumed;
        return decoded && result.status == wire::CodecStatus::complete && !result.valuesTruncated
               && result.bitsConsumed == mirror.header.bitCount;
    }
    return wire::decode_full_schema(
               schemaHandle, mirror.bytes, mirror.header.bitCount, resolver, values, result)
           && (result.status == wire::CodecStatus::complete
               || result.status == wire::CodecStatus::completeWithPadding)
           && !result.valuesTruncated;
}

/** Channel-2 update contexts set native mode one before calling the SObject decoder. */
[[nodiscard]] format::RuntimeCodecFamily sobject_family() noexcept {
    return format::RuntimeCodecFamily::sobjectModeOne;
}

/** Raw float lanes must stay finite when retained for replay. */
[[nodiscard]] bool append_float(bits::Reader& reader, MirrorBuilder& mirror) noexcept {
    std::uint64_t raw = 0;
    return read_and_append(reader, mirror, kFloatWidth, raw)
           && std::isfinite(std::bit_cast<float>(static_cast<std::uint32_t>(raw)));
}

/** Native float-four encoding distinguishes points, directions, and explicit W. */
[[nodiscard]] bool append_position(bits::Reader& reader,
                                   MirrorBuilder& mirror,
                                   const PositionProfile& profile) noexcept {
    bool point = false, direction = false;
    if (!read_flag(reader, mirror, point) || (!point && !read_flag(reader, mirror, direction)))
        return false;
    bool compressed = false;
    if (!direction && profile.selectorPresent) {
        if (!read_flag(reader, mirror, compressed)) return false;
    }
    for (std::size_t index = 0; index < kPositionComponents; ++index) {
        if (compressed) {
            if (!profile.hasWidths || profile.axisBits[index] >= kFloatWidth) return false;
            std::uint64_t raw = 0;
            if (!read_and_append(reader, mirror, profile.axisBits[index], raw)) return false;
        } else if (!append_float(reader, mirror))
            return false;
    }
    return point || direction || append_float(reader, mirror);
}

/** Placement baselines permit independent transform, parent, and stream-source deltas. */
[[nodiscard]] bool append_sobject_prefix(bits::Reader& reader,
                                         MirrorBuilder& mirror,
                                         const CompositeEntityCodecContext& context) noexcept {
    bool transform = false;
    bool rotationShortcut = false;
    bool ignoredFlag = false;
    std::uint64_t ignored = 0;
    if (!read_flag(reader, mirror, transform)) return false;
    if (transform) {
        // The general axis is a 19-bit native unit-vector code.
        constexpr std::uint8_t kAxisWidth = 19;
        if (!read_flag(reader, mirror, rotationShortcut)
            || (rotationShortcut ? !read_flag(reader, mirror, ignoredFlag)
                                 : !read_and_append(reader, mirror, kAxisWidth, ignored))
            || !read_and_append(reader, mirror, kAngleWidth, ignored)
            || !append_position(reader, mirror, context.positionProfile))
            return false;
    }
    // The ordered roots follow the native SObject update reader.
    constexpr std::array<std::uint32_t, 2> kRelationSchemas{0x8080949BU, 0x8080949AU};
    ResolverContext resolver{&context, sobject_family()};
    for (const auto schema : kRelationSchemas) {
        bool present = false;
        if (!read_flag(reader, mirror, present)
            || (present && !append_schema(reader, mirror, resolver, schema, nullptr)))
            return false;
    }
    return true;
}

/** The native compiled plan decides whether a component has any wire presence at all. */
static bool append_compiled_component(const CompositeEntityCodecContext& context,
                                      const SobjectDecodePlan& plan,
                                      bits::Reader& reader,
                                      MirrorBuilder& mirror,
                                      std::uint32_t componentTag) noexcept {
    if (!plan.active) return true;
    bool present = false;
    if (!read_flag(reader, mirror, present)) return false;
    if (!present) return true;
    // The component bitmap is bounded by the same work budget as its retained wire payload.
    std::array<std::uint8_t, kMaximumTypePayloadBits> bitmap{};
    if (plan.bitmapBits == 0 || plan.bitmapBits > bitmap.size()) return false;
    bitmap[0] = 1;
    ResolverContext resolver{&context, sobject_family(), std::span(bitmap).first(plan.bitmapBits)};
    resolver.componentTag = componentTag;
    for (const auto& entry : plan.entries) {
        if (entry.guardBit >= plan.bitmapBits || entry.repeatCount > wire::kRuntimeValueCapacity)
            return false;
        if (bitmap[entry.guardBit] == 0) continue;
        for (std::uint32_t index = 0; index < entry.repeatCount; ++index) {
            const auto base = static_cast<std::uint64_t>(entry.firstFieldBit)
                              + static_cast<std::uint64_t>(index) * entry.fieldBitStride;
            if (base > plan.bitmapBits) return false;
            resolver.firstFieldBit = static_cast<std::uint32_t>(base);
            if (!append_schema(reader, mirror, resolver, entry.schemaHandle, nullptr)) return false;
        }
    }
    return true;
}

/** Walks every ordered RSAT presence bit and each present component schema. */
[[nodiscard]] bool append_sobject_components(const CompositeEntityCodecContext& context,
                                             std::uint32_t rsatTag,
                                             bits::Reader& reader,
                                             MirrorBuilder& mirror) noexcept {
    const format::SobjectRsat* rsat = sobject_rsat(context, rsatTag);
    if (rsat == nullptr || rsat->flags != format::kSobjectRsatExact) {
        return false;
    }
    if (rsat->descriptors.first > context.sobjectDescriptors.size()
        || rsat->descriptors.count > context.sobjectDescriptors.size() - rsat->descriptors.first) {
        return false;
    }
    const auto descriptors =
        context.sobjectDescriptors.subspan(rsat->descriptors.first, rsat->descriptors.count);
    if (context.resolvePlan == nullptr) return false;
    for (const format::SobjectRsatDescriptor& descriptor : descriptors) {
        SobjectDecodePlan plan{};
        if (!context.resolvePlan(
                context.planContext, descriptor.componentTag, descriptor.schemaTag, plan)
            || !append_compiled_component(context, plan, reader, mirror, descriptor.componentTag)) {
#if defined(SUNRISE_ACTIVITY_SDK_TESTING)
            if (context.schemaFailure != nullptr) {
                wire::RuntimeDecodeResult failure{};
                failure.status = wire::CodecStatus::needsRuntimeSchema;
                context.schemaFailure(
                    descriptor.schemaTag, descriptor.componentTag, failure, nullptr);
            }
#endif
            return false;
        }
    }
    return true;
}
/** Resolves one update-only type-0 RSAT from committed session state. */
[[nodiscard]] bool registry_sobject_tag(const CompositeEntityCodecContext& context,
                                        const EntityToken& token,
                                        std::uint32_t& output) noexcept {
    if (context.registry == nullptr || !valid_token(token)) {
        return false;
    }
    const EntityBaselineSlot& slot = context.registry->slots[token.slot];
    if (!slot.occupied || slot.incarnation != token.incarnation || slot.type != EntityType::sobject
        || slot.rsatTag == 0) {
        return false;
    }
    output = slot.rsatTag;
    return true;
}

/** Dispatches one baseline or update through its SDK-selected grammar. */
[[nodiscard]] bool read_payload_impl(const CompositeEntityCodecContext& context,
                                     const EntityToken& token,
                                     EntityType type,
                                     TypePayloadPart part,
                                     const TypePayload* baseline,
                                     bits::Reader& reader,
                                     TypePayload& output) noexcept {
    const format::EntityTypeDefinition* definition = entity_definition(context, type);
    if (definition == nullptr || (definition->flags & format::kEntityTypeStockEmittable) == 0) {
        return false;
    }
    MirrorBuilder mirror{};
    std::uint32_t semanticTag = 0;
    if (part == TypePayloadPart::baseline) {
        if (baseline != nullptr || definition->baselineSchema == format::kAbsentIndex) {
            return false;
        }
        ResolverContext resolver{&context, format::RuntimeCodecFamily::activity};
        if (!append_schema(reader,
                           mirror,
                           resolver,
                           definition->baselineSchema,
                           type == EntityType::sobject ? &semanticTag : nullptr)) {
            return false;
        }
        if (type == EntityType::sobject) {
            bool placementIdentity = false;
            if (!read_flag(reader, mirror, placementIdentity)) {
                return false;
            }
        }
        return mirror.finish(semanticTag, output);
    }
    if ((definition->flags & format::kEntityTypeUpdateSupported) == 0) {
        return false;
    }
    if ((definition->flags & format::kEntityTypeUpdateUsesSobjectRsat) != 0) {
        if (type != EntityType::sobject) {
            return false;
        }
        if (baseline != nullptr) {
            MirrorView baselineView{};
            if (!load_mirror(*baseline, baselineView)) {
                return false;
            }
            semanticTag = baselineView.header.semanticTag;
        } else if (!registry_sobject_tag(context, token, semanticTag)) {
            return false;
        }
        bool placementIdentity = false;
        if (baseline != nullptr) {
            MirrorView view{};
            if (!load_mirror(*baseline, view) || view.header.bitCount != kSobjectBaselineBits)
                return false;
            placementIdentity = (std::to_integer<unsigned>(view.bytes[4]) & 1U) != 0;
        } else {
            placementIdentity = context.registry->slots[token.slot].sobjectPlacement;
        }
        return semanticTag != 0
               && (!placementIdentity || append_sobject_prefix(reader, mirror, context))
               && append_sobject_components(context, semanticTag, reader, mirror)
               && mirror.finish(semanticTag, output);
    }
    if (definition->updateSchema == format::kAbsentIndex) {
        return false;
    }
    bool present = false;
    if (!read_flag(reader, mirror, present)) return false;
    ResolverContext resolver{&context, sobject_family()};
    return (!present || append_schema(reader, mirror, resolver, definition->updateSchema, nullptr))
           && mirror.finish(0, output);
}

/** TypePayloadCodec reader adapter with no registry mutation. */
[[nodiscard]] bool read_payload(const void* raw,
                                const EntityToken& token,
                                EntityType type,
                                TypePayloadPart part,
                                const TypePayload* baseline,
                                bits::Reader& reader,
                                TypePayload& output) noexcept {
    const auto* const context = static_cast<const CompositeEntityCodecContext*>(raw);
    return context != nullptr && context->ready
           && read_payload_impl(*context, token, type, part, baseline, reader, output);
}

/** Replays exactly the meaningful bits from one validated mirror. */
[[nodiscard]] bool write_mirror(bits::Writer& writer, const MirrorView& mirror) noexcept {
    bits::Reader reader(mirror.bytes);
    return bits::copy(reader, writer, mirror.header.bitCount);
}

/** Revalidates a mirror through reflection before replaying it. */
[[nodiscard]] bool write_payload(const void* raw,
                                 const EntityToken& token,
                                 EntityType type,
                                 TypePayloadPart part,
                                 const TypePayload* baseline,
                                 const TypePayload& payload,
                                 bits::Writer& writer) noexcept {
    const auto* const context = static_cast<const CompositeEntityCodecContext*>(raw);
    MirrorView view{};
    if (context == nullptr || !context->ready || !load_mirror(payload, view)) {
        return false;
    }
    bits::Reader verifier(view.bytes);
    TypePayload canonical{};
    MirrorView canonicalView{};
    if (!read_payload_impl(*context, token, type, part, baseline, verifier, canonical)
        || !load_mirror(canonical, canonicalView) || canonical.byteCount != payload.byteCount
        || std::memcmp(canonical.state.data(), payload.state.data(), payload.byteCount) != 0
        || canonical.actorSource != payload.actorSource) {
        return false;
    }
    return write_mirror(writer, view);
}

/** A cell profile is borrowed for one body and never changes another record's codec context. */
static bool read_cell_payload(const void* raw,
                              const EntityToken& token,
                              EntityType type,
                              TypePayloadPart part,
                              const TypePayload* baseline,
                              std::uint16_t cell,
                              bits::Reader& reader,
                              TypePayload& output) noexcept {
    const auto* context = static_cast<const CompositeEntityCodecContext*>(raw);
    if (context == nullptr || !context->ready) return false;
    if (context->resolvePosition == nullptr)
        return read_payload(context, token, type, part, baseline, reader, output);
    CompositeEntityCodecContext selected = *context;
    if (!context->resolvePosition(
            context->positionContext, context->source, cell, selected.positionProfile))
        return false;
    return read_payload(&selected, token, type, part, baseline, reader, output);
}

/** Replay selects the same package cell profile used to decode the retained body. */
static bool write_cell_payload(const void* raw,
                               const EntityToken& token,
                               EntityType type,
                               TypePayloadPart part,
                               const TypePayload* baseline,
                               const TypePayload& payload,
                               std::uint16_t cell,
                               bits::Writer& writer) noexcept {
    const auto* context = static_cast<const CompositeEntityCodecContext*>(raw);
    if (context == nullptr || !context->ready) return false;
    if (context->resolvePosition == nullptr)
        return write_payload(context, token, type, part, baseline, payload, writer);
    CompositeEntityCodecContext selected = *context;
    if (!context->resolvePosition(
            context->positionContext, context->source, cell, selected.positionProfile))
        return false;
    return write_payload(&selected, token, type, part, baseline, payload, writer);
}

/** Resolves an update-only entity type from its session registry. */
[[nodiscard]] bool
resolve_type(const void* raw, const EntityToken& token, EntityType& output) noexcept {
    const auto* const context = static_cast<const CompositeEntityCodecContext*>(raw);
    if (context == nullptr || context->registry == nullptr || !valid_token(token)) {
        return false;
    }
    const EntityBaselineSlot& slot = context->registry->slots[token.slot];
    if (!slot.occupied || slot.incarnation != token.incarnation
        || entity_definition(*context, slot.type) == nullptr) {
        return false;
    }
    output = slot.type;
    return true;
}

/** Compares wrapping allocation sequences within the unambiguous half-range. */
[[nodiscard]] bool serial_is_newer(std::uint8_t candidate, std::uint8_t current) noexcept {
    /** Half of the byte sequence space. A larger gap cannot be ordered. */
    constexpr std::uint8_t kOrderableDistance = 0x80U;
    const std::uint8_t distance = static_cast<std::uint8_t>(candidate - current);
    return distance != 0 && distance < kOrderableDistance;
}

/** Validates the complete row closure required by the composite codec. */
[[nodiscard]] bool valid_catalog_rows(const CompositeEntityCodecContext& context) noexcept {
    if (context.entityTypes.size() != static_cast<std::size_t>(EntityType::count)
        || context.sobjectRsats.empty() || context.sobjectDescriptors.empty()
        || context.sobjectBindings.size() != context.rsatFields.size()
        || context.runtimeSchemas.empty() || context.runtimeFields.empty()
        || context.runtimeTypes.empty()
        || (context.positionCompression != SobjectPositionCompression::disabled
            && context.positionCompression != SobjectPositionCompression::enabledRaw)) {
        return false;
    }
    std::array<bool, static_cast<std::size_t>(EntityType::count)> found{};
    for (const format::EntityTypeDefinition& row : context.entityTypes) {
        if (row.entityType >= found.size() || found[row.entityType]
            || (row.flags & format::kEntityTypeDefinitionExact) == 0) {
            return false;
        }
        const bool stock = (row.flags & format::kEntityTypeStockEmittable) != 0;
        const bool update = (row.flags & format::kEntityTypeUpdateSupported) != 0;
        const bool dynamic = (row.flags & format::kEntityTypeUpdateUsesSobjectRsat) != 0;
        if ((stock && row.baselineSchema == format::kAbsentIndex)
            || (dynamic && (!update || row.updateSchema != format::kAbsentIndex))
            || (!dynamic && update && row.updateSchema == format::kAbsentIndex)) {
            return false;
        }
        if (stock && runtime_schema(context, row.baselineSchema) == nullptr) {
            return false;
        }
        if (!dynamic && update && runtime_schema(context, row.updateSchema) == nullptr) {
            return false;
        }
        found[row.entityType] = true;
    }
    return std::all_of(found.begin(), found.end(), [](bool value) { return value; });
}

/** Pins one authenticated SDK snapshot and resets stale registry ownership. */
[[nodiscard]] bool bind_context(CompositeEntityCodecContext& context,
                                EntityBaselineRegistry& registry,
                                const state::activity_sdk::Snapshot& catalog,
                                SobjectPositionCompression positionCompression) noexcept {
    if (catalog == nullptr
        || (positionCompression != SobjectPositionCompression::disabled
            && positionCompression != SobjectPositionCompression::enabledRaw)) {
        return false;
    }
    if (registry.catalog != catalog) {
        registry.catalog = catalog;
        registry.slots.fill({});
    }
    context.catalog = catalog;
    context.entityTypes = catalog->entity_type_definitions();
    context.sobjectRsats = catalog->sobject_rsats();
    context.sobjectDescriptors = catalog->sobject_rsat_descriptors();
    context.rsatSchemas = catalog->rsat_schemas();
    context.rsatFields = catalog->rsat_fields();
    context.sobjectBindings = catalog->sobject_rsat_field_bindings();
    context.runtimeSchemas = catalog->runtime_schemas();
    context.runtimeFields = catalog->runtime_fields();
    context.runtimeTypes = catalog->runtime_type_definitions();
    context.registry = &registry;
    context.positionCompression = positionCompression;
    context.ready = valid_catalog_rows(context);
    return context.ready;
}

/** Finds or creates one bounded session without evicting another session. */
[[nodiscard]] CompositeEntitySession*
session(CompositeEntitySessionStore& store,
        std::uint64_t groupSessionId,
        bool create,
        const state::gameplay::entity_identity::Source& source = {}) noexcept {
    if (groupSessionId == 0 || store.catalog == nullptr) {
        return nullptr;
    }
    CompositeEntitySession* empty = nullptr;
    for (CompositeEntitySession& candidate : store.sessions) {
        if (candidate.occupied && candidate.groupSessionId == groupSessionId
            && candidate.source == source) {
            return &candidate;
        }
        if (!candidate.occupied && empty == nullptr) {
            empty = &candidate;
        }
    }
    if (!create || empty == nullptr
        || !bind_context(empty->codec, empty->registry, store.catalog, store.positionCompression)) {
        return nullptr;
    }
    empty->groupSessionId = groupSessionId;
    empty->codec.positionProfile = store.positionProfile;
    empty->codec.resolvePosition = store.resolvePosition;
    empty->codec.positionContext = store.positionContext;
    empty->codec.source = source;
    empty->codec.resolvePlan = store.resolvePlan;
    empty->codec.resolveSchemaLayout = store.resolveSchemaLayout;
    empty->codec.resolveFieldLayout = store.resolveFieldLayout;
    empty->codec.resolveAdditionalSchema = store.resolveAdditionalSchema;
    empty->codec.resolveAdditionalField = store.resolveAdditionalField;
    empty->codec.planContext = store.planContext;
    empty->source = source;
    empty->occupied = true;
    return empty;
}

} // namespace

/** Decodes one retained typed mirror through its published executable schema. */
bool decode_composite_entity_payload(const state::activity_sdk::Snapshot& catalog,
                                     EntityType type,
                                     TypePayloadPart part,
                                     const TypePayload& payload,
                                     std::span<wire::RuntimeDecodedValue> values,
                                     wire::RuntimeDecodeResult& result) noexcept {
    return decode_composite_entity_payload_impl(catalog, type, part, payload, values, result);
}

/**
 * Reads only the private create-mirror layout, never a legacy typed payload.
 * @param payload Composite SObject baseline retained by the wire decoder.
 * @param output Receives its RSAT tag, or zero on failure.
 * @return True when the complete create mirror carries a valid tag.
 */
bool composite_sobject_rsat(const TypePayload& payload, std::uint32_t& output) noexcept {
    output = 0;
    MirrorView view{};
    if (!load_mirror(payload, view) || view.header.bitCount != kSobjectBaselineBits
        || view.header.semanticTag == 0 || view.header.semanticTag == format::kAbsentIndex) {
        return false;
    }
    output = view.header.semanticTag;
    return true;
}

/** Binds the currently published authenticated SDK. */
bool initialize_composite_entity_codec(CompositeEntityCodecContext& context,
                                       EntityBaselineRegistry& registry,
                                       SobjectPositionCompression positionCompression) noexcept {
    state::activity_sdk::Snapshot catalog = state::activity_sdk::snapshot();
    return bind_context(context, registry, catalog, positionCompression);
}

/** Binds one caller-pinned authenticated SDK. */
bool initialize_composite_entity_codec_from_catalog(
    CompositeEntityCodecContext& context,
    EntityBaselineRegistry& registry,
    const state::activity_sdk::Snapshot& catalog,
    SobjectPositionCompression positionCompression) noexcept {
    return bind_context(context, registry, catalog, positionCompression);
}

#if defined(SUNRISE_ACTIVITY_SDK_TESTING)
/** Binds deterministic row spans in focused test binaries only. */
bool initialize_composite_entity_codec_for_test(
    CompositeEntityCodecContext& context,
    EntityBaselineRegistry& registry,
    const CompositeEntityCatalogFixture& fixture,
    SobjectPositionCompression positionCompression) noexcept {
    CompositeEntityCodecContext candidate{};
    candidate.entityTypes = fixture.entityTypes;
    candidate.sobjectRsats = fixture.sobjectRsats;
    candidate.sobjectDescriptors = fixture.sobjectDescriptors;
    candidate.rsatSchemas = fixture.rsatSchemas;
    candidate.rsatFields = fixture.rsatFields;
    candidate.sobjectBindings = fixture.sobjectBindings;
    candidate.runtimeSchemas = fixture.runtimeSchemas;
    candidate.runtimeFields = fixture.runtimeFields;
    candidate.runtimeTypes = fixture.runtimeTypes;
    candidate.resolvePlan = fixture.resolvePlan;
    candidate.planContext = fixture.planContext;
    candidate.registry = &registry;
    candidate.positionCompression = positionCompression;
    candidate.ready = valid_catalog_rows(candidate);
    if (!candidate.ready) {
        return false;
    }
    std::destroy_at(&registry);
    std::construct_at(&registry);
    context = candidate;
    return true;
}
#endif

/** Retained parent attachments preserve native tail-insertion order for implicit token groups. */
static bool resolve_anchor_group(const void* raw,
                                 const EntityToken& anchor,
                                 std::span<EntityToken> output,
                                 std::size_t& count) noexcept {
    count = 0;
    const auto* context = static_cast<const CompositeEntityCodecContext*>(raw);
    if (context == nullptr || context->registry == nullptr || !valid_token(anchor)
        || output.empty())
        return false;
    const auto& slots = context->registry->slots;
    if (!slots[anchor.slot].occupied || slots[anchor.slot].incarnation != anchor.incarnation)
        return false;
    std::array<EntityToken, kEntityBatchCapacity> parents{};
    std::array<std::uint64_t, kEntityBatchCapacity> siblingOrders{};
    std::size_t depth = 0;
    EntityToken next = anchor;
    for (;;) {
        if (count == output.size() || count == kEntityBatchCapacity) {
            count = 0;
            return false;
        }
        for (std::size_t index = 0; index < count; ++index) {
            if (output[index].slot == next.slot) {
                count = 0;
                return false;
            }
        }
        output[count++] = next;
        parents[depth] = next;
        siblingOrders[depth] = 0;
        for (;;) {
            const auto parent = parents[depth];
            std::size_t child = slots.size();
            std::uint64_t earliest = (std::numeric_limits<std::uint64_t>::max)();
            for (std::size_t index = 0; index < slots.size(); ++index) {
                const auto& slot = slots[index];
                if (slot.occupied && slot.anchorPresent && slot.anchor.slot == parent.slot
                    && slot.anchor.incarnation == parent.incarnation
                    && slot.anchorOrder > siblingOrders[depth] && slot.anchorOrder < earliest) {
                    earliest = slot.anchorOrder;
                    child = index;
                }
            }
            if (child != slots.size()) {
                siblingOrders[depth] = earliest;
                if (++depth == parents.size()) {
                    count = 0;
                    return false;
                }
                next = {static_cast<std::uint16_t>(child), slots[child].incarnation};
                break;
            }
            if (depth == 0) return true;
            --depth;
        }
    }
}

/** Builds pure callbacks over one stable codec context. */
TypePayloadCodec
make_composite_entity_payload_codec(const CompositeEntityCodecContext& context) noexcept {
    TypePayloadCodec codec{};
    codec.context = &context;
    codec.resolveType = resolve_type;
    codec.read = read_payload;
    codec.write = write_payload;
    codec.readForCell = read_cell_payload;
    codec.writeForCell = write_cell_payload;
    codec.maximumBaselineBits = kMaximumTypePayloadBits;
    codec.maximumUpdateBits = kMaximumTypePayloadBits;
    codec.resolveAnchorGroup = resolve_anchor_group;
    return codec;
}

/** Validates one record against its original or earlier staged slot state. */
static bool stage_entity_record_mutation(const CompositeEntityCodecContext& context,
                                         const EntityRecord& record,
                                         const EntityBaselineSlot& current,
                                         EntityBaselineChange& output,
                                         bool resetSerial) noexcept {
    output = {};
    if (!context.ready || context.registry == nullptr
        || (context.catalog != nullptr && context.registry->catalog != context.catalog)
        || !valid_token(record.token)) {
        return false;
    }
    EntityBaselineChange candidate{};
    candidate.expected = current;
    candidate.replacement = current;
    candidate.slot = record.token.slot;

    if ((record.flags & entityCreate) != 0) {
        const format::EntityTypeDefinition* definition = entity_definition(context, record.type);
        if (definition == nullptr || (definition->flags & format::kEntityTypeStockEmittable) == 0) {
            return false;
        }
        if (!resetSerial && (current.known || current.occupied)) {
            const bool duplicate = current.occupied
                                   && current.incarnation == record.token.incarnation
                                   && current.allocationSequence == record.allocationSequence
                                   && current.type == record.type;
            if (!duplicate
                && !serial_is_newer(record.allocationSequence, current.allocationSequence)) {
                return false;
            }
        }
        std::uint32_t rsatTag = 0;
        bool placement = true;
        if (record.type == EntityType::sobject) {
            MirrorView baseline{};
            if (!load_mirror(record.baseline, baseline) || baseline.header.semanticTag == 0
                || sobject_rsat(context, baseline.header.semanticTag) == nullptr) {
                return false;
            }
            rsatTag = baseline.header.semanticTag;
            placement = (std::to_integer<unsigned>(baseline.bytes.back()) & 1U) != 0;
        }
        if (current.occupied && current.incarnation == record.token.incarnation
            && current.allocationSequence == record.allocationSequence
            && current.type == record.type
            && (current.rsatTag != rsatTag || current.sobjectPlacement != placement)) {
            return false;
        }
        candidate.replacement.rsatTag = rsatTag;
        candidate.replacement.allocationSequence = record.allocationSequence;
        candidate.replacement.incarnation = record.token.incarnation;
        candidate.replacement.type = record.type;
        candidate.replacement.occupied = true;
        candidate.replacement.known = true;
        candidate.replacement.sobjectPlacement = placement;
        const bool retainedObject = resetSerial && current.occupied
                                    && current.incarnation == record.token.incarnation
                                    && current.type == record.type && current.rsatTag == rsatTag;
        if (!retainedObject
            && (!current.occupied || current.incarnation != record.token.incarnation
                || current.allocationSequence != record.allocationSequence)) {
            candidate.replacement.anchor = {};
            candidate.replacement.anchorPresent = false;
        }
    } else {
        if (!current.occupied || current.incarnation != record.token.incarnation) {
            return false;
        }
        const format::EntityTypeDefinition* definition = entity_definition(context, current.type);
        if (definition == nullptr
            || ((record.flags & entityUpdate) != 0
                && (definition->flags & format::kEntityTypeUpdateSupported) == 0)) {
            return false;
        }
    }
    if ((record.flags & entityAnchor) != 0) {
        candidate.replacement.anchor = record.anchorPresent ? record.anchor : EntityToken{};
        candidate.replacement.anchorPresent = record.anchorPresent;
    }
    output = candidate;
    return true;
}

/** Every record is staged before any baseline slot changes. */
bool stage_entity_baseline_mutation(const CompositeEntityCodecContext& context,
                                    const EntityBatch& batch,
                                    EntityBaselineMutation& output) noexcept {
    output = {};
    const auto count = entity_record_count(batch);
    if (context.registry == nullptr || count == 0 || count > kEntityBatchCapacity) return false;
    EntityBaselineMutation candidate{};
    candidate.expectedAnchorOrder = context.registry->anchorOrder;
    candidate.replacementAnchorOrder = candidate.expectedAnchorOrder;
    candidate.expectedAllocationEpoch = context.registry->allocationEpoch;
    candidate.expectedHasAllocationEpoch = context.registry->hasAllocationEpoch;
    candidate.expectedAllocationDomain = context.registry->allocationDomain;
    candidate.replacementAllocationEpoch = candidate.expectedAllocationEpoch;
    candidate.replacementHasAllocationEpoch = candidate.expectedHasAllocationEpoch;
    candidate.replacementAllocationDomain = candidate.expectedAllocationDomain;
    if (batch.hasAllocationEpoch) {
        if (batch.allocationDomain == 0
            || (context.registry->hasAllocationEpoch
                && (batch.allocationEpoch != context.registry->allocationEpoch
                    || batch.allocationDomain != context.registry->allocationDomain)))
            return false;
        candidate.replacementAllocationEpoch = batch.allocationEpoch;
        candidate.replacementHasAllocationEpoch = true;
        candidate.replacementAllocationDomain = batch.allocationDomain;
    } else if (context.registry->hasAllocationEpoch)
        return false;
    std::size_t changes = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const auto& record = entity_record_at(batch, index);
        if (!valid_token(record.token)) return false;
        std::size_t selected = 0;
        for (; selected < changes; ++selected) {
            const auto& change = selected == 0 ? static_cast<const EntityBaselineChange&>(candidate)
                                               : candidate.additionalChanges[selected - 1];
            if (change.slot == record.token.slot) break;
        }
        auto& change = selected == 0 ? static_cast<EntityBaselineChange&>(candidate)
                                     : candidate.additionalChanges[selected - 1];
        EntityBaselineChange next{};
        const auto& current =
            selected < changes ? change.replacement : context.registry->slots[record.token.slot];
        const bool resetSerial =
            batch.hasAllocationEpoch && current.serialDomain != batch.allocationDomain;
        if (batch.hasAllocationEpoch && current.occupied && (record.flags & entityCreate) != 0
            && record.allocationSequence == 0)
            return false;
        if (batch.hasAllocationEpoch && !record.implicitToken && !current.occupied
            && (record.flags & (entityCreate | entityUpdate | entityRemove)) == entityRemove) {
            candidate.ignoredRecordMask |= static_cast<std::uint16_t>(1U << index);
            continue;
        }
        if (batch.hasAllocationEpoch && !record.implicitToken && !current.occupied
            && (record.flags & entityCreate) != 0
            && (record.allocationSequence == 0
                || (current.known && !resetSerial
                    && !serial_is_newer(record.allocationSequence, current.allocationSequence)))) {
            candidate.ignoredRecordMask |= static_cast<std::uint16_t>(1U << index);
            continue;
        }
        if (!stage_entity_record_mutation(context, record, current, next, resetSerial))
            return false;
        if ((record.flags & entityCreate) != 0 && batch.hasAllocationEpoch)
            next.replacement.serialDomain = batch.allocationDomain;
        if ((record.flags & entityCreate) != 0 && batch.hasAllocationEpoch
            && (!current.occupied || !current.known
                || current.incarnation != record.token.incarnation
                || current.allocationSequence != record.allocationSequence
                || current.type != record.type)) {
            next.replacement.hasAllocationEpoch = true;
            next.replacement.allocationEpoch = batch.allocationEpoch;
            next.replacement.allocationDomain = batch.allocationDomain;
        }
        const bool identicalCreateAnchor =
            (record.flags & entityCreate) != 0 && current.occupied
            && current.incarnation == record.token.incarnation
            && current.allocationSequence == record.allocationSequence
            && current.anchorPresent == next.replacement.anchorPresent
            && current.anchor.slot == next.replacement.anchor.slot
            && current.anchor.incarnation == next.replacement.anchor.incarnation;
        if (next.replacement.occupied && !identicalCreateAnchor
            && (((record.flags & entityAnchor) != 0)
                || ((record.flags & entityCreate) != 0 && !current.occupied))) {
            if (candidate.replacementAnchorOrder == (std::numeric_limits<std::uint64_t>::max)())
                return false;
            next.replacement.anchorOrder =
                next.replacement.anchorPresent ? ++candidate.replacementAnchorOrder : 0;
        }
        if (selected < changes)
            next.expected = change.expected;
        else
            ++changes;
        change = next;
    }
    const auto change_at = [&](std::size_t index) -> EntityBaselineChange& {
        return index == 0 ? static_cast<EntityBaselineChange&>(candidate)
                          : candidate.additionalChanges[index - 1];
    };
    const auto current_slot = [&](std::size_t slot) -> const EntityBaselineSlot& {
        for (std::size_t index = 0; index < changes; ++index)
            if (change_at(index).slot == slot) return change_at(index).replacement;
        return context.registry->slots[slot];
    };
    std::array<EntityToken, kEntityBatchCapacity> terminals{};
    std::size_t terminalCount = 0;
    const auto append_terminal = [&](EntityToken token) {
        for (std::size_t index = 0; index < terminalCount; ++index)
            if (terminals[index].slot == token.slot
                && terminals[index].incarnation == token.incarnation)
                return true;
        if (terminalCount == terminals.size()) return false;
        terminals[terminalCount++] = token;
        return true;
    };
    for (std::size_t index = 0; index < count; ++index) {
        const auto& record = entity_record_at(batch, index);
        if ((candidate.ignoredRecordMask & (1U << index)) == 0 && (record.flags & entityRemove) != 0
            && !append_terminal(record.token))
            return false;
    }
    for (std::size_t index = 0; index < terminalCount; ++index) {
        const auto token = terminals[index];
        const auto& before = current_slot(token.slot);
        if (!before.occupied || before.incarnation != token.incarnation) continue;
        for (std::size_t slot = 0; slot < context.registry->slots.size(); ++slot) {
            const auto& child = current_slot(slot);
            if (child.occupied && child.anchorPresent && child.anchor.slot == token.slot
                && child.anchor.incarnation == token.incarnation
                && !append_terminal({static_cast<std::uint16_t>(slot), child.incarnation}))
                return false;
        }
        std::size_t selected = 0;
        for (; selected < changes && change_at(selected).slot != token.slot; ++selected) {}
        if (selected == changes) {
            if (changes == kEntityBatchCapacity) return false;
            auto& change = change_at(changes++);
            change.slot = token.slot;
            change.expected = context.registry->slots[token.slot];
            change.replacement = change.expected;
        }
        change_at(selected).replacement.occupied = false;
        change_at(selected).replacement.known = true;
    }
    candidate.hasChanges = changes != 0;
    candidate.additionalChangeCount = static_cast<std::uint8_t>(changes == 0 ? 0 : changes - 1);
    candidate.valid = true;
    output = candidate;
    return true;
}

/** Applies a staged mutation only when its source slot has not changed. */
bool commit_accepted_entity_batch(EntityBaselineRegistry& registry,
                                  const EntityBaselineMutation& mutation) noexcept {
    if (!mutation.valid || mutation.additionalChangeCount >= kEntityBatchCapacity
        || registry.anchorOrder != mutation.expectedAnchorOrder
        || registry.allocationEpoch != mutation.expectedAllocationEpoch
        || registry.hasAllocationEpoch != mutation.expectedHasAllocationEpoch
        || registry.allocationDomain != mutation.expectedAllocationDomain)
        return false;
    for (std::size_t index = 0; mutation.hasChanges && index <= mutation.additionalChangeCount;
         ++index) {
        const auto& change = index == 0 ? static_cast<const EntityBaselineChange&>(mutation)
                                        : mutation.additionalChanges[index - 1];
        if (change.slot > kMaximumEntitySlot
            || !same_slot(registry.slots[change.slot], change.expected))
            return false;
    }
    for (std::size_t index = 0; mutation.hasChanges && index <= mutation.additionalChangeCount;
         ++index) {
        const auto& change = index == 0 ? static_cast<const EntityBaselineChange&>(mutation)
                                        : mutation.additionalChanges[index - 1];
        registry.slots[change.slot] = change.replacement;
    }
    registry.anchorOrder = mutation.replacementAnchorOrder;
    registry.allocationEpoch = mutation.replacementAllocationEpoch;
    registry.hasAllocationEpoch = mutation.replacementHasAllocationEpoch;
    registry.allocationDomain = mutation.replacementAllocationDomain;
    return true;
}

/** Direct construction avoids a multi-megabyte temporary on the caller stack. */
void reset_composite_entity_sessions(CompositeEntitySessionStore& store) noexcept {
    std::destroy_at(&store);
    std::construct_at(&store);
}

/** Pins one catalog for a new bounded session store. */
bool initialize_composite_entity_sessions(CompositeEntitySessionStore& store,
                                          SobjectPositionCompression positionCompression) noexcept {
    state::activity_sdk::Snapshot catalog = state::activity_sdk::snapshot();
    const std::unique_ptr<CompositeEntitySession> probe(new (std::nothrow)
                                                            CompositeEntitySession{});
    if (!probe || !bind_context(probe->codec, probe->registry, catalog, positionCompression)) {
        return false;
    }
    reset_composite_entity_sessions(store);
    store.catalog = std::move(catalog);
    store.positionCompression = positionCompression;
    return true;
}

/** Decodes one batch against the named session's committed baselines. */
bool read_composite_entity_batch(CompositeEntitySessionStore& store,
                                 std::uint64_t groupSessionId,
                                 bits::Reader& reader,
                                 EntityBatch& output) noexcept {
    CompositeEntitySession* selected = session(store, groupSessionId, true);
    if (selected == nullptr) {
        return false;
    }
    const TypePayloadCodec codec = make_composite_entity_payload_codec(selected->codec);
    return read_entity_batch(reader, codec, output);
}

/** Stages and commits one peer-accepted batch in its named session. */
bool accept_composite_entity_batch(const void* raw,
                                   std::uint64_t groupSessionId,
                                   const EntityBatch& batch) noexcept {
    auto* const store = const_cast<CompositeEntitySessionStore*>(
        static_cast<const CompositeEntitySessionStore*>(raw));
    if (store == nullptr) {
        return false;
    }
    CompositeEntitySession* selected = session(*store, groupSessionId, false);
    EntityBaselineMutation mutation{};
    return selected != nullptr && stage_entity_baseline_mutation(selected->codec, batch, mutation)
           && commit_accepted_entity_batch(selected->registry, mutation);
}

/** Releases every baseline owned by one ended session. */
void reset_composite_entity_session(CompositeEntitySessionStore& store,
                                    std::uint64_t groupSessionId) noexcept {
    for (auto& selected : store.sessions) {
        if (selected.occupied && selected.groupSessionId == groupSessionId) {
            std::destroy_at(&selected);
            std::construct_at(&selected);
        }
    }
}

/** Removes baselines for only the exact retired source. */
void reset_scoped_entity_session(CompositeEntitySessionStore& store,
                                 const state::gameplay::entity_identity::Source& source) noexcept {
    for (auto& selected : store.sessions) {
        if (selected.occupied && selected.source == source) {
            std::destroy_at(&selected);
            std::construct_at(&selected);
        }
    }
}

/** Only matching allocations lose occupancy; their serial and ordering evidence remains. */
std::size_t retire_scoped_entity_baselines(
    CompositeEntitySessionStore& store,
    const state::gameplay::entity_identity::Source& source,
    std::span<const state::gameplay::entity_identity::RetiredLifetime> lifetimes) noexcept {
    auto* selected = session(store, source.groupSessionId, false, source);
    if (selected == nullptr) return 0;
    std::size_t retired = 0;
    for (const auto& lifetime : lifetimes) {
        if (!valid_token({lifetime.token.slot, lifetime.token.incarnation})) continue;
        auto& slot = selected->registry.slots[lifetime.token.slot];
        if (!slot.known || !slot.occupied || slot.incarnation != lifetime.token.incarnation
            || slot.allocationSequence != lifetime.allocationSequence
            || slot.allocationEpoch != lifetime.allocationEpoch
            || slot.allocationDomain != lifetime.allocationDomain)
            continue;
        slot.occupied = false;
        ++retired;
    }
    return retired;
}

/** An absent source has no serial domain to reset; existing identity evidence remains intact. */
bool advance_scoped_entity_epoch(CompositeEntitySessionStore& store,
                                 const state::gameplay::entity_identity::Source& source,
                                 std::uint8_t expected,
                                 std::uint8_t next,
                                 std::uint64_t nextDomain) noexcept {
    if (nextDomain == 0 || next != static_cast<std::uint8_t>(expected + 1U)) return false;
    auto* selected = session(store, source.groupSessionId, false, source);
    if (selected == nullptr) return true;
    auto& registry = selected->registry;
    if (registry.hasAllocationEpoch
        && (registry.allocationEpoch != expected || nextDomain != registry.allocationDomain + 1U))
        return false;
    registry.hasAllocationEpoch = true;
    registry.allocationEpoch = next;
    registry.allocationDomain = nextDomain;
    return true;
}

/** Decodes only against this admitted source's committed baselines. */
bool read_scoped_entity_batch(CompositeEntitySessionStore& store,
                              const state::gameplay::entity_identity::Source& source,
                              bits::Reader& reader,
                              EntityBatch& output) noexcept {
    auto* selected = session(store, source.groupSessionId, true, source);
    if (selected == nullptr) return false;
    return read_entity_batch(reader, make_composite_entity_payload_codec(selected->codec), output);
}

/**
 * Expanded peer ordinals keep sparse entity updates ordered across wire-sequence wraps.
 * @param store Caller-owned baseline store, unchanged by preparation.
 * @param source Exact admitted source whose decoder already selected a session.
 * @param batch Complete decoded record.
 * @param packetSequence Original ten-bit wire sequence.
 * @param hasPacketSequence Whether the packet carries an ordered sequence.
 * @param packetOrdinal Sequence unwrapped across every accepted packet on the peer.
 * @param output Receives a source-bound mutation, cleared on failure.
 * @return True when lifetime and packet ordering permit a later commit.
 */
bool prepare_scoped_entity_batch(CompositeEntitySessionStore& store,
                                 const state::gameplay::entity_identity::Source& source,
                                 const EntityBatch& batch,
                                 std::uint16_t packetSequence,
                                 bool hasPacketSequence,
                                 std::uint64_t packetOrdinal,
                                 EntityBaselineMutation& output) noexcept {
    output = {};
    auto* selected = session(store, source.groupSessionId, false, source);
    if (selected == nullptr || !batch.recordPresent || !valid_token(batch.record.token)
        || (hasPacketSequence
            && (packetSequence >= state::gameplay::entity_identity::kPacketModulus
                || packetOrdinal == 0)))
        return false;
    EntityBaselineMutation candidate{};
    if (!stage_entity_baseline_mutation(selected->codec, batch, candidate)) return false;
    for (std::size_t index = 0; candidate.hasChanges && index <= candidate.additionalChangeCount;
         ++index) {
        auto& change = index == 0 ? static_cast<EntityBaselineChange&>(candidate)
                                  : candidate.additionalChanges[index - 1];
        if (change.expected.hasPacketSequence
            && (!hasPacketSequence || packetOrdinal <= change.expected.packetOrdinal))
            return false;
        change.replacement.hasPacketSequence = hasPacketSequence;
        change.replacement.packetSequence = hasPacketSequence ? packetSequence : 0;
        change.replacement.packetOrdinal = hasPacketSequence ? packetOrdinal : 0;
    }
    candidate.source = source;
    candidate.scoped = true;
    output = candidate;
    return true;
}

/**
 * Commit changes one existing slot only when its prepared source and prior state still match.
 * @param store Caller-owned baseline store.
 * @param source Exact source used by preparation.
 * @param mutation Prepared source-bound replacement.
 * @return True when the compare-and-commit succeeds without allocation.
 */
bool commit_scoped_entity_batch(CompositeEntitySessionStore& store,
                                const state::gameplay::entity_identity::Source& source,
                                const EntityBaselineMutation& mutation) noexcept {
    if (!mutation.scoped || mutation.source != source) return false;
    auto* selected = session(store, source.groupSessionId, false, source);
    return selected != nullptr && commit_accepted_entity_batch(selected->registry, mutation);
}

/** Commits the last fallible channel-2 operation for this source. */
bool accept_scoped_entity_batch(CompositeEntitySessionStore& store,
                                const state::gameplay::entity_identity::Source& source,
                                const EntityBatch& batch) noexcept {
    auto* selected = session(store, source.groupSessionId, false, source);
    EntityBaselineMutation mutation{};
    return selected != nullptr && stage_entity_baseline_mutation(selected->codec, batch, mutation)
           && commit_accepted_entity_batch(selected->registry, mutation);
}

} // namespace sunrise::middleware::gameplay::external
