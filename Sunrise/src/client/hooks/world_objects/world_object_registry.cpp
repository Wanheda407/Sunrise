#include "world_object_registry.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <span>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../executable/image.h"
#include "../../hooking/detour.h"
#include "../../memory/current_process_memory.h"
#include "../../patterns/image_scan.h"
#include "../../patterns/registry.h"
#include "../../patterns/signature_text.h"
#include "world_object_rebind_trace.h"

namespace sunrise::client::hooks::world_objects {
namespace {

using patterns::signature;
using patterns::signature_length;

constexpr std::uint32_t kNone = 0xFFFFFFFFU;

// Identity-bearing placements per registry clear that get an observed line. This is the positive
// control for the duplicate count, so it matches the registry's own capacity. A smaller budget is
// spent before the object lists load, and a missing duplicate then says nothing.
/** Dynamic handles tracked for teardown. One Tower bubble builds at most 73 of them. */
constexpr std::size_t kDynamicHandleCapacity = 256;
/** Stack frames reported above one off-ledger allocation. */
constexpr std::size_t kFrameCount = 4;
constexpr std::size_t kIdentityReportBudget = 16384;

constexpr std::size_t kRegistryCapacity = 16384;
constexpr std::size_t kRegistryMask = kRegistryCapacity - 1;
static_assert((kRegistryCapacity & kRegistryMask) == 0);

constexpr std::string_view kInstantiateSignatureText =
    "40 55 53 56 41 56 41 57 48 8D 6C 24 ? 48 81 EC 60 01 00 00";
constexpr auto kInstantiateSignature =
    signature<signature_length(kInstantiateSignatureText)>(kInstantiateSignatureText);

constexpr std::string_view kDestroySignatureText =
    "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 50 8B D9 8B F9";
constexpr auto kDestroySignature =
    signature<signature_length(kDestroySignatureText)>(kDestroySignatureText);

// The datum allocator every creation path shares. The instantiate hook above is one of its
// three callers, so a build reported here and not there was made by one of the other two.
constexpr std::string_view kAllocateSignatureText =
    "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC 40 01 00 00 48 8B 05 ? ? ? ? 48 33 "
    "C4 48 89 84 24 ? ? ? ? C7 01 FF FF FF FF";
constexpr auto kAllocateSignature =
    signature<signature_length(kAllocateSignatureText)>(kAllocateSignatureText);

// The logical destroy. It is the only path that releases an object's simulation entity, so a
// teardown that frees the object without passing here leaves the entity to rebuild it.
constexpr std::string_view kLogicalDestroySignatureText =
    "48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 40 48 8B 3D ? ? ? ? 8B D9";
constexpr auto kLogicalDestroySignature =
    signature<signature_length(kLogicalDestroySignatureText)>(kLogicalDestroySignatureText);

constexpr std::string_view kResolvePairSignatureText =
    "4C 8B D1 83 FA FF 74 ? 4C 8B 0D ? ? ? ? 44 8B C2 41 C1 F8 1F 8B C2 C1 E8 0D 41 81 E0 "
    "00 3C 00 00 0F B7 C8 41 81 C8 FF 03 00 00 49 8B 01 44 23 C1 45 0F AF 41 ? 0F B7 CA "
    "81 E1 FF 1F 00 00 4D 8B 44 00";
constexpr auto kResolvePairSignature =
    signature<signature_length(kResolvePairSignatureText)>(kResolvePairSignatureText);

constexpr std::string_view kValidatePairSignatureText = "48 83 EC 08 44 8B 51";
constexpr auto kValidatePairSignature =
    signature<signature_length(kValidatePairSignatureText)>(kValidatePairSignatureText);

// The longer suffix fixes the two RIP-relative operands used below at stable byte offsets.
constexpr std::string_view kDatumLayoutSignatureText =
    "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 55 41 56 41 57 48 83 EC 30 44 8B F1 8B F9 41 81 "
    "E6 FF 1F 00 00 48 8B CA 44 0F AF 35 ? ? ? ? 41 8B E9 41 8B D8 4C 8B FA 4C 03 35 ? ? "
    "? ?";
constexpr auto kDatumLayoutSignature =
    signature<signature_length(kDatumLayoutSignatureText)>(kDatumLayoutSignatureText);

using Instantiate = std::uint32_t*(__fastcall*)(std::uint32_t*,
                                                const void*,
                                                std::int32_t,
                                                std::int32_t) noexcept;
using Destroy = std::uintptr_t(__fastcall*)(std::uint32_t) noexcept;
using Allocate = Instantiate;
using LogicalDestroy = std::uintptr_t(__fastcall*)(std::uint32_t) noexcept;
using CreateEntity = bool(__fastcall*)(void*, const void*, std::uint32_t, std::uint32_t);
using EntityPolicy = std::uint32_t(__fastcall*)(void*, std::uint32_t);
using PurgeEntities = void(__fastcall*)(void*,
                                        std::int32_t,
                                        const std::uint32_t*,
                                        std::uint32_t*,
                                        std::uint32_t*,
                                        std::uint32_t*,
                                        std::uint8_t);

/** Unique native entity-create, purge, and glue-token mapping entries. */
constexpr std::string_view kCreateEntityText =
    "48 89 5C 24 08 48 89 74 24 18 55 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 "
    "8B 05 ? ? ? ?";
constexpr std::string_view kPurgeEntitiesText =
    "40 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 "
    "48 89 45 ? 48 8B 75 ? 44 8B FA 4C 8B 75 ? 48 8B F9 BA 00 20 00 00";
constexpr std::string_view kGlueMappingText =
    "81 E1 FF 1F 00 00 0F AF 0D ? ? ? ? 8B C1 48 03 05 ? ? ? ? 89 10 C3";
constexpr auto kCreateEntityPattern =
    signature<signature_length(kCreateEntityText)>(kCreateEntityText);
constexpr auto kPurgeEntitiesPattern =
    signature<signature_length(kPurgeEntitiesText)>(kPurgeEntitiesText);
constexpr auto kGlueMappingPattern =
    signature<signature_length(kGlueMappingText)>(kGlueMappingText);
/** Unique record-pool reference and native policy entry. */
constexpr std::string_view kEntityPoolText =
    "48 8D 04 5B 48 0F BF 84 46 14 01 00 00 48 6B D8 70 48 8D 05 ? ? ? ? 48 03 D8 83 7B 48 FF";
constexpr std::string_view kEntityPolicyText =
    "40 55 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 33 "
    "FF 83 FA FF";
constexpr auto kEntityPoolPattern = signature<signature_length(kEntityPoolText)>(kEntityPoolText);
constexpr auto kEntityPolicyPattern =
    signature<signature_length(kEntityPolicyText)>(kEntityPolicyText);
/** Entity indices occupy the low thirteen bits; the native mask contains 256 words. */
constexpr std::uint32_t kEntityIndexMask = 0x1FFFU;
constexpr std::size_t kEntityMaskWords = 256;
/** The simulation view stores its shared replication epoch at this byte. */
constexpr std::size_t kViewEpochOffset = 53284;
/** Each view index maps to a signed record number in a six-byte row. */
constexpr std::size_t kViewMapOffset = 276, kViewMapStride = 6;
/** Per-record diagnostics are bounded; mask-word logging retains the complete selection. */
constexpr std::size_t kPurgeTraceCapacity = 64;
/** Native global records have a fixed stride, pool bound, and view occupancy mask. */
constexpr std::size_t kEntityRecordStride = 112, kEntityRecordCapacity = 1024;
constexpr std::size_t kViewOccupiedOffset = 50464, kEntityFlagsOffset = 80;

struct EntityRecordPrefix final {
    std::uint8_t type{}, lifecycle{};
    std::uint16_t cell{};
    std::uint32_t glue{}, token{}, parent{};
};
struct PolicyTrace final {
    std::uint32_t glue{}, policy{};
    bool reported{};
};

struct HandlePair final {
    std::uint32_t generation{kNone};
    std::uint32_t handle{kNone};
};

using ResolvePair = std::uintptr_t(__fastcall*)(HandlePair*, std::uint32_t) noexcept;
using ValidatePair = std::int32_t*(__fastcall*)(const HandlePair*, std::int32_t*) noexcept;

enum class EntryState : std::uint8_t {
    empty,
    live,
    tombstone,
};

struct RegistryEntry final {
    Instance instance{};
    EntryState state{EntryState::empty};
};

/** One fixed placement identity count, separate from the handle-keyed lifetime table. */
struct IdentityEntry final {
    std::uint64_t key{};
    std::uint32_t count{};
    EntryState state{EntryState::empty};
};

struct DatumIdentity final {
    std::array<std::byte, 12> prefix{};
    std::uint32_t selfHandle{};
    std::array<std::byte, 120> middle{};
    std::uint32_t objectListTag{};
    std::uint32_t entryIndex{};
    std::uint64_t placementIdentity{};
};

static_assert(offsetof(DatumIdentity, selfHandle) == 0x0C);
static_assert(offsetof(DatumIdentity, objectListTag) == 0x88);
static_assert(offsetof(DatumIdentity, entryIndex) == 0x8C);
static_assert(offsetof(DatumIdentity, placementIdentity) == 0x90);

SRWLOCK g_lock{SRWLOCK_INIT};
std::array<RegistryEntry, kRegistryCapacity> g_entries{};
std::array<IdentityEntry, kRegistryCapacity> g_identities{};
std::size_t g_liveCount{};
std::uint64_t g_overflowCount{};
std::size_t g_identityReportBudget{kIdentityReportBudget};
std::size_t g_dynamicReportBudget{kIdentityReportBudget};
std::uint64_t g_dynamicCount{};
/**
 * Handles the dynamic path built, so the destroy detour can say which of them the client tears
 * down. A dynamic build names no placed entry, so the identity registry never holds one, and
 * whether a bubble crossing removes it is not known.
 */
std::array<std::uint32_t, kDynamicHandleCapacity> g_dynamicHandles{};
std::array<std::uint64_t, kDynamicHandleCapacity> g_dynamicOrdinals{};
std::atomic_uint32_t g_activeCalls{};
std::atomic_bool g_accepting{};
std::array<hooking::detour::Handle, 15> g_handles{};
std::atomic<Instantiate> g_instantiateOriginal{nullptr};
std::atomic<Destroy> g_destroyOriginal{nullptr};
std::atomic<Allocate> g_allocateOriginal{nullptr};
std::atomic<LogicalDestroy> g_logicalDestroyOriginal{nullptr};
std::atomic<CreateEntity> g_createEntityOriginal{nullptr};
std::atomic<PurgeEntities> g_purgeEntitiesOriginal{nullptr};
std::atomic<EntityPolicy> g_entityPolicyOriginal{nullptr};
std::uintptr_t g_entityRecordBase{};
std::array<PolicyTrace, kPurgeTraceCapacity> g_policyTrace{};
const std::uintptr_t* g_glueBaseStorage{};
const std::uint32_t* g_glueStrideStorage{};
thread_local std::uint32_t t_entityGlue{kNone};
thread_local std::uint32_t t_entityNetwork{kNone};
std::size_t g_logicalDestroyReportBudget{kIdentityReportBudget};

/** Set while this thread is inside the instantiate detour, whose allocation is already reported. */
thread_local bool t_inInstantiate{};
std::size_t g_allocateReportBudget{kIdentityReportBudget};
ResolvePair g_resolvePair{};
ValidatePair g_validatePair{};
const std::uintptr_t* g_datumBaseStorage{};
// Main module base, so a caller address is reported as an RVA and stays comparable
// against the IDB across runs.
std::uintptr_t g_moduleBase{};
const std::uint32_t* g_datumStrideStorage{};

/** Native diagnostic entry points retain their original Windows x64 return registers. */
using Observer = std::uintptr_t(__fastcall*)(void*, void*, const std::uint8_t*);
using Rebind = std::uintptr_t(__fastcall*)();
using IteratorValue = std::uintptr_t(__fastcall*)(void*, std::uint32_t*);
using SourceRef = std::uint8_t(__fastcall*)(std::uint32_t, void*);
using ResolveSource = std::uint8_t(__fastcall*)(const void*, void*);
using Predicate = std::uintptr_t(__fastcall*)(std::uint32_t);
using BindActor = void(__fastcall*)(void*, std::uint32_t);
using Teardown = std::uintptr_t(__fastcall*)(void*);
using ActorOwner = std::uint32_t*(__fastcall*)(std::uint32_t*, std::uint32_t);
using SliceManager = void*(__fastcall*)();
using CurrentBubble = std::uint32_t*(__fastcall*)(void*, std::uint32_t*);
std::atomic<Observer> g_observerOriginal{};
std::atomic<Rebind> g_rebindOriginal{};
std::atomic<IteratorValue> g_iteratorOriginal{};
std::atomic<SourceRef> g_sourceOriginal{};
std::atomic<ResolveSource> g_resolveSourceOriginal{};
std::atomic<Predicate> g_predicateOriginal{};
std::atomic<BindActor> g_bindOriginal{};
std::atomic<Teardown> g_teardownOriginal{};
ActorOwner g_actorOwner{};
const std::uintptr_t* g_actorBaseStorage{};
const std::uint32_t* g_actorStrideStorage{};
SliceManager g_sliceManager{};
CurrentBubble g_currentBubble{};
/** Rebind callers are checked against their resolved function-relative return offsets. */
std::uintptr_t g_rebindAddress{}, g_observerAddress{};
/** Each diagnostic run admits 128 passes and 4096 actor/member rows. */
constexpr std::uint32_t kRebindPassBudget = 128, kRebindRowBudget = 4096;
std::atomic_uint32_t g_rebindPasses{}, g_rebindRows{}, g_observerReports{};
/** Native squad collections contain at most 80 generation-checked eight-byte actor references. */
constexpr std::size_t kSquadMembers = 80, kSquadCountOffset = 0x314, kSquadRefsOffset = 0x318;
struct ActorSource final {
    std::uint32_t key{kNone};
    std::uint8_t type{0xFF}, padding{};
    std::uint16_t index{0xFFFF};
};
static_assert(sizeof(ActorSource) == 8);
struct RebindTrace final {
    trace::Association association{};
    ActorSource source{};
    void* activity{};
    std::uint32_t bubble{kNone}, pass{}, visited{}, bound{};
    int sourceResult{-1}, resolveResult{-1}, predicate{-1};
    std::int32_t countBefore{-1}, countAfter{-1};
    std::array<std::uint64_t, 2> bindingBefore{}, bindingAfter{};
    bool bindCalled{}, bindingBeforeKnown{}, bindingAfterKnown{};
    std::uint32_t flags{}, flagsAfter{};
    bool flagsKnown{}, flagsAfterKnown{}, sourceKnown{};
};
thread_local RebindTrace* t_rebindTrace{};
struct ObserverTrace final {
    void* activity{};
    std::uint32_t bubble{kNone};
};
thread_local ObserverTrace* t_observerTrace{};

/** Counts one in-flight detour call, so teardown can wait for the hooks to drain. */
class ActiveCall final {
public:
    ActiveCall() noexcept {
        g_activeCalls.fetch_add(1, std::memory_order_acq_rel);
    }
    ~ActiveCall() {
        g_activeCalls.fetch_sub(1, std::memory_order_acq_rel);
    }

    ActiveCall(const ActiveCall&) = delete;
    ActiveCall& operator=(const ActiveCall&) = delete;
};

/** @return A stable open-address bucket for a native handle. */
[[nodiscard]] constexpr std::size_t bucket(std::uint32_t handle) noexcept {
    return (static_cast<std::size_t>(handle) * 2654435761U) & kRegistryMask;
}

/** Clears every retained identity. Caller owns g_lock exclusively. */
void clear_registry() noexcept {
    g_entries = {};
    g_identities = {};
    g_liveCount = 0;
    g_identityReportBudget = kIdentityReportBudget;
    g_dynamicReportBudget = kIdentityReportBudget;
    g_allocateReportBudget = kIdentityReportBudget;
    g_logicalDestroyReportBudget = kIdentityReportBudget;
    g_dynamicCount = 0;
}

/** @return True when the datum retained a real placed-entry identity. */
[[nodiscard]] constexpr bool has_placement_identity(const Instance& instance) noexcept {
    return instance.placementIdentity != 0
           && instance.placementIdentity != kAbsentPlacementIdentity;
}

/**
 * Combines one placement into a nonzero registry key.
 * A real placed-entry identity wins: a mirrored map variant repeats it under a different
 * object-list tag, which the tuple alone would count twice. No identity means the tuple key.
 */
[[nodiscard]] constexpr std::uint64_t identity_key(const Instance& instance) noexcept {
    if (has_placement_identity(instance)) {
        return instance.placementIdentity;
    }
    return (static_cast<std::uint64_t>(instance.objectListTag) << 32U) | instance.entryIndex;
}

/** Adjusts one placement count and reports the first simultaneous duplicate. */
void adjust_identity(const Instance& instance, bool increment) noexcept {
    const std::uint64_t key = identity_key(instance);
    const std::size_t first =
        static_cast<std::size_t>((key ^ (key >> 32U)) * 2654435761U) & kRegistryMask;
    std::size_t tombstone = kRegistryCapacity;
    for (std::size_t probe = 0; probe < kRegistryCapacity; ++probe) {
        const std::size_t index = (first + probe) & kRegistryMask;
        IdentityEntry& entry = g_identities[index];
        if (entry.state == EntryState::live && entry.key == key) {
            if (increment) {
                ++entry.count;
                if (entry.count == 2) {
                    std::array<char, 192> line{};
                    const int written = std::snprintf(
                        line.data(),
                        line.size(),
                        "ev=world_object stage=placement result=duplicate list=0x%08X "
                        "entry=%u identity=0x%016llX count=%u",
                        instance.objectListTag,
                        instance.entryIndex,
                        static_cast<unsigned long long>(instance.placementIdentity),
                        entry.count);
                    if (written > 0) {
                        core::log::write(core::log::Channel::client,
                                         core::log::Level::debug,
                                         {line.data(), static_cast<std::size_t>(written)});
                    }
                }
            } else if (entry.count > 1) {
                --entry.count;
            } else {
                entry.state = EntryState::tombstone;
                entry.count = 0;
            }
            return;
        }
        if (entry.state == EntryState::tombstone && tombstone == kRegistryCapacity) {
            tombstone = index;
        }
        if (entry.state != EntryState::empty) {
            continue;
        }
        if (!increment) {
            return;
        }
        IdentityEntry& destination =
            g_identities[tombstone == kRegistryCapacity ? index : tombstone];
        destination = {key, 1, EntryState::live};
        return;
    }
    if (increment && tombstone < kRegistryCapacity) {
        g_identities[tombstone] = {key, 1, EntryState::live};
    }
}

/** Inserts or replaces one handle without allocating. Caller owns g_lock exclusively. */
void retain(const Instance& instance) noexcept {
    std::size_t firstTombstone = kRegistryCapacity;
    for (std::size_t probe = 0; probe < kRegistryCapacity; ++probe) {
        const std::size_t index = (bucket(instance.handle) + probe) & kRegistryMask;
        RegistryEntry& entry = g_entries[index];
        if (entry.state == EntryState::live && entry.instance.handle == instance.handle) {
            if (identity_key(entry.instance) != identity_key(instance)) {
                adjust_identity(entry.instance, false);
                adjust_identity(instance, true);
            }
            entry.instance = instance;
            return;
        }
        if (entry.state == EntryState::tombstone && firstTombstone == kRegistryCapacity) {
            firstTombstone = index;
        }
        if (entry.state != EntryState::empty) {
            continue;
        }
        RegistryEntry& destination =
            g_entries[firstTombstone == kRegistryCapacity ? index : firstTombstone];
        destination.instance = instance;
        destination.state = EntryState::live;
        adjust_identity(instance, true);
        ++g_liveCount;
        return;
    }
    if (firstTombstone != kRegistryCapacity) {
        RegistryEntry& destination = g_entries[firstTombstone];
        destination.instance = instance;
        destination.state = EntryState::live;
        adjust_identity(instance, true);
        ++g_liveCount;
        return;
    }
    ++g_overflowCount;
}

/**
 * Returns a tombstone run to empty when the slot after it is already empty.
 * A probe stops only on empty, so a run that never becomes empty makes every later miss walk the
 * whole table. Nothing live can sit past an empty slot, so the run behind one is free to reclaim.
 * @param index Slot just tombstoned. Caller owns g_lock exclusively.
 */
void reclaim_tombstones(std::size_t index) noexcept {
    if (g_entries[(index + 1) & kRegistryMask].state != EntryState::empty) {
        return;
    }
    std::size_t slot = index;
    while (g_entries[slot].state == EntryState::tombstone) {
        g_entries[slot] = {};
        slot = (slot - 1) & kRegistryMask;
    }
}

/** Erases one handle before native teardown can recycle its generation. */
void erase(std::uint32_t handle) noexcept {
    for (std::size_t probe = 0; probe < kRegistryCapacity; ++probe) {
        const std::size_t index = (bucket(handle) + probe) & kRegistryMask;
        RegistryEntry& entry = g_entries[index];
        if (entry.state == EntryState::empty) {
            return;
        }
        if (entry.state == EntryState::live && entry.instance.handle == handle) {
            adjust_identity(entry.instance, false);
            entry.state = EntryState::tombstone;
            --g_liveCount;
            if (g_liveCount == 0) {
                clear_registry();
                return;
            }
            reclaim_tombstones(index);
            return;
        }
    }
}

/** Reads one scalar from the process without trusting a stale game-owned pointer. */
template <typename Value>
[[nodiscard]] bool read_value(const Value* source, Value& output) noexcept {
    return memory::read_current_process(
        nullptr,
        reinterpret_cast<std::uintptr_t>(source),
        std::span(reinterpret_cast<std::byte*>(&output), sizeof output));
}

/** Datum bytes through the object-list tuple, and through the retained placement identity. */
constexpr std::uint32_t kDatumTupleBytes = offsetof(DatumIdentity, placementIdentity);
constexpr std::uint32_t kDatumIdentityBytes = sizeof(DatumIdentity);

/**
 * Reads one object datum's identity block.
 * A stride that stops before the placement identity still yields the tuple, and leaves the
 * identity zero, so a layout surprise degrades to tuple-keyed counting instead of silence.
 */
[[nodiscard]] bool read_datum_identity(std::uint32_t handle, DatumIdentity& output) noexcept {
    if (g_datumBaseStorage == nullptr || g_datumStrideStorage == nullptr) {
        return false;
    }
    std::uintptr_t base = 0;
    std::uint32_t stride = 0;
    if (!read_value(g_datumBaseStorage, base) || !read_value(g_datumStrideStorage, stride)
        || base == 0 || stride < kDatumTupleBytes) {
        return false;
    }
    const std::size_t wanted =
        stride >= kDatumIdentityBytes ? kDatumIdentityBytes : kDatumTupleBytes;
    output = {};
    return memory::read_current_process(
        nullptr,
        base + static_cast<std::uintptr_t>(stride) * (handle & 0x1FFFU),
        std::span(reinterpret_cast<std::byte*>(&output), wanted));
}

/** Checks the native generation pair and the three datum identity fields. */
[[nodiscard]] bool validate(const Instance& instance) noexcept {
    if (g_validatePair == nullptr) {
        return false;
    }
    const HandlePair pair{instance.generation, instance.handle};
    std::int32_t resolved = -1;
    __try {
        g_validatePair(&pair, &resolved);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (static_cast<std::uint32_t>(resolved) != instance.handle) {
        return false;
    }

    DatumIdentity identity{};
    if (!read_datum_identity(instance.handle, identity)) {
        return false;
    }
    return identity.selfHandle == instance.handle
           && identity.objectListTag == instance.objectListTag
           && identity.entryIndex == instance.entryIndex;
}

/**
 * Reads the placed entry's authored world position, held at entry `+0x20`.
 * Two entries at one position under different object lists are the same authored prop placed
 * twice, which an identity-keyed count cannot see because each source carries its own `+0x70`.
 */
[[nodiscard]] bool read_entry_position(const void* entry, std::array<float, 3>& output) noexcept {
    if (entry == nullptr) {
        return false;
    }
    return memory::read_current_process(
        nullptr,
        reinterpret_cast<std::uintptr_t>(entry) + 0x20U,
        std::span(reinterpret_cast<std::byte*>(output.data()), sizeof(float) * output.size()));
}

/**
 * Reports one object built by a caller that named no placed entry.
 * Those callers pass {-1,-1}, so the registry cannot retain them and nothing else here sees them.
 * A second copy of authored content that the placed path builds once must come from here.
 */
void report_dynamic(std::uint32_t handle, const void* entry, std::uintptr_t caller) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    ++g_dynamicCount;
    const std::uint64_t ordinal = g_dynamicCount;
    const bool report = g_dynamicReportBudget > 0;
    if (report) {
        --g_dynamicReportBudget;
    }
    const std::size_t track = static_cast<std::size_t>(ordinal - 1) % kDynamicHandleCapacity;
    g_dynamicHandles[track] = handle;
    g_dynamicOrdinals[track] = ordinal;
    ReleaseSRWLockExclusive(&g_lock);
    if (!report) {
        return;
    }
    std::array<float, 3> position{};
    const bool positionRead = read_entry_position(entry, position);
    std::array<char, 224> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=world_object stage=placement result=dynamic "
        "handle=0x%08X ordinal=%llu pos=%.3f,%.3f,%.3f "
        "caller=+0x%llX",
        handle,
        static_cast<unsigned long long>(ordinal),
        positionRead ? static_cast<double>(position[0]) : 0.0,
        positionRead ? static_cast<double>(position[1]) : 0.0,
        positionRead ? static_cast<double>(position[2]) : 0.0,
        static_cast<unsigned long long>(caller >= g_moduleBase ? caller - g_moduleBase : caller));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Captures only placed-content calls; dynamic callers pass {-1,-1}. */
void observe_instance(std::uint32_t handle,
                      const void* entry,
                      std::int32_t objectListTag,
                      std::int32_t entryIndex) noexcept {
    if (handle == kNone || objectListTag == -1 || entryIndex == -1 || g_resolvePair == nullptr
        || !g_accepting.load(std::memory_order_acquire)) {
        return;
    }
    HandlePair pair{};
    __try {
        g_resolvePair(&pair, handle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
    if (pair.handle != handle || pair.generation == kNone) {
        return;
    }
    // Native init has already copied placed entry +0x70 into the datum at +0x90, so the identity
    // that survives a mirrored object list is readable here.
    DatumIdentity datum{};
    const bool datumRead = read_datum_identity(handle, datum) && datum.selfHandle == handle
                           && datum.objectListTag == static_cast<std::uint32_t>(objectListTag)
                           && datum.entryIndex == static_cast<std::uint32_t>(entryIndex);
    const Instance instance{datumRead ? datum.placementIdentity : 0,
                            static_cast<std::uint32_t>(objectListTag),
                            static_cast<std::uint32_t>(entryIndex),
                            handle,
                            pair.generation};
    AcquireSRWLockExclusive(&g_lock);
    retain(instance);
    const bool report = has_placement_identity(instance) && g_identityReportBudget > 0;
    if (report) {
        --g_identityReportBudget;
    }
    const std::size_t live = g_liveCount;
    ReleaseSRWLockExclusive(&g_lock);
    if (!report) {
        return;
    }
    std::array<float, 3> position{};
    const bool positionRead = read_entry_position(entry, position);
    std::array<char, 256> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=world_object stage=placement result=observed "
                                      "list=0x%08X entry=%u identity=0x%016llX handle=0x%08X "
                                      "pos=%.3f,%.3f,%.3f live=%zu",
                                      instance.objectListTag,
                                      instance.entryIndex,
                                      static_cast<unsigned long long>(instance.placementIdentity),
                                      instance.handle,
                                      positionRead ? static_cast<double>(position[0]) : 0.0,
                                      positionRead ? static_cast<double>(position[1]) : 0.0,
                                      positionRead ? static_cast<double>(position[2]) : 0.0,
                                      live);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Calls native construction first, then retains the successfully initialized identity. */
__declspec(noinline) std::uint32_t* __fastcall instantiate(std::uint32_t* output,
                                                           const void* entry,
                                                           std::int32_t objectListTag,
                                                           std::int32_t entryIndex) noexcept {
    ActiveCall active;
    const Instantiate original = g_instantiateOriginal.load(std::memory_order_acquire);
    t_inInstantiate = true;
    std::uint32_t* const result =
        original != nullptr ? original(output, entry, objectListTag, entryIndex) : output;
    t_inInstantiate = false;
    if (result != nullptr) {
        if (objectListTag == -1 || entryIndex == -1) {
            report_dynamic(*result, entry, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
        } else {
            observe_instance(*result, entry, objectListTag, entryIndex);
        }
    }
    return result;
}

/**
 * Reports one datum allocated by a path other than the instantiate hook above.
 * @param caller Return address, reported as an RVA so it names the creating function.
 */
/** @return The datum flag word at `+4`, or zero when it cannot be read. */
[[nodiscard]] std::uint32_t datum_flags(std::uint32_t handle) noexcept {
    if (g_datumBaseStorage == nullptr || g_datumStrideStorage == nullptr) {
        return 0;
    }
    const std::uintptr_t datum =
        *g_datumBaseStorage
        + static_cast<std::uintptr_t>(*g_datumStrideStorage) * (handle & 0x1FFFU);
    std::uint32_t flags = 0;
    if (!memory::read_current_process(
            nullptr, datum + 4U, std::span(reinterpret_cast<std::byte*>(&flags), sizeof flags))) {
        return 0;
    }
    return flags;
}

/** Associates an allocation with its native creator and any active entity identity. */
void report_allocation(std::uint32_t handle, std::uintptr_t caller) noexcept {
    // The allocation site alone does not say which subsystem asked. Unwind names the frames.
    std::array<void*, kFrameCount> frames{};
    const USHORT captured =
        RtlCaptureStackBackTrace(2, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    AcquireSRWLockExclusive(&g_lock);
    const bool report = g_allocateReportBudget > 0;
    if (report) {
        --g_allocateReportBudget;
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (!report) {
        return;
    }
    if (t_entityGlue != kNone) {
        std::array<char, 192> identity{};
        const int length = std::snprintf(
            identity.data(),
            identity.size(),
            "ev=world_object stage=entity_create handle=0x%08X glue=0x%08X network=0x%08X slot=%u",
            handle,
            t_entityGlue,
            t_entityNetwork,
            t_entityNetwork & kEntityIndexMask);
        if (length > 0)
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {identity.data(), static_cast<std::size_t>(length)});
    }
    std::array<char, 192> line{};
    int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=world_object stage=placement result=alloc handle=0x%08X flags=0x%08X caller=+0x%llX",
        handle,
        datum_flags(handle),
        static_cast<unsigned long long>(caller >= g_moduleBase ? caller - g_moduleBase : caller));
    for (USHORT index = 0; written > 0 && index < captured; ++index) {
        const auto frame = reinterpret_cast<std::uintptr_t>(frames[index]);
        const int appended = std::snprintf(
            line.data() + written,
            line.size() - static_cast<std::size_t>(written),
            " f%u=+0x%llX",
            static_cast<unsigned>(index),
            static_cast<unsigned long long>(frame >= g_moduleBase ? frame - g_moduleBase : frame));
        if (appended <= 0) {
            break;
        }
        written += appended;
    }
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Carries native entity identity into the allocator trace without changing creation. */
__declspec(noinline) bool __fastcall create_entity(void* definition,
                                                   const void* data,
                                                   std::uint32_t glue,
                                                   std::uint32_t parent) {
    ActiveCall active;
    const auto original = g_createEntityOriginal.load(std::memory_order_acquire);
    const auto savedGlue = t_entityGlue;
    const auto savedNetwork = t_entityNetwork;
    t_entityGlue = glue;
    t_entityNetwork = kNone;
    if (glue != kNone && g_glueBaseStorage != nullptr && g_glueStrideStorage != nullptr) {
        const auto row =
            *g_glueBaseStorage
            + static_cast<std::uintptr_t>(*g_glueStrideStorage) * (glue & kEntityIndexMask);
        static_cast<void>(memory::read_current_process(
            nullptr,
            row,
            std::span(reinterpret_cast<std::byte*>(&t_entityNetwork), sizeof(t_entityNetwork))));
    }
    const bool result = original != nullptr && original(definition, data, glue, parent);
    t_entityGlue = savedGlue;
    t_entityNetwork = savedNetwork;
    return result;
}

/** Reports native policy changes for the bounded glue slots under investigation. */
__declspec(noinline) std::uint32_t __fastcall entity_policy(void* definition, std::uint32_t glue) {
    ActiveCall active;
    const auto original = g_entityPolicyOriginal.load(std::memory_order_acquire);
    const std::uint32_t policy = original != nullptr ? original(definition, glue) : 0;
    if (!g_accepting.load(std::memory_order_acquire) || glue == kNone
        || (glue & kEntityIndexMask) >= kPurgeTraceCapacity || g_glueBaseStorage == nullptr
        || g_glueStrideStorage == nullptr)
        return policy;
    std::uint32_t token = kNone;
    const auto row =
        *g_glueBaseStorage
        + static_cast<std::uintptr_t>(*g_glueStrideStorage) * (glue & kEntityIndexMask);
    if (!memory::read_current_process(
            nullptr, row, std::span(reinterpret_cast<std::byte*>(&token), sizeof(token)))
        || token == kNone || (token & kEntityIndexMask) >= kPurgeTraceCapacity)
        return policy;
    AcquireSRWLockExclusive(&g_lock);
    PolicyTrace& previous = g_policyTrace[token & kEntityIndexMask];
    const bool changed = !previous.reported || previous.glue != glue || previous.policy != policy;
    previous = {glue, policy, true};
    ReleaseSRWLockExclusive(&g_lock);
    if (changed) {
        std::array<char, 160> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=world_object stage=entity_policy slot=%u token=0x%08X glue=0x%08X value=%u",
            token & kEntityIndexMask,
            token,
            glue,
            policy);
        if (length > 0)
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(length)});
    }
    return policy;
}

/** Logs unselected records without invoking native policy or mutating their state. */
void report_unselected_records(void* view,
                               const std::array<std::uint32_t, kEntityMaskWords>& mask,
                               std::uint8_t epoch) noexcept {
    for (std::uint32_t slot = 0; g_entityRecordBase != 0 && slot < kPurgeTraceCapacity; ++slot) {
        if ((mask[slot / 32U] & (1U << (slot % 32U))) != 0) continue;
        std::uint32_t occupied = 0;
        if (!memory::read_current_process(
                nullptr,
                reinterpret_cast<std::uintptr_t>(view) + kViewOccupiedOffset
                    + sizeof(occupied) * (slot / 32U),
                std::span(reinterpret_cast<std::byte*>(&occupied), sizeof(occupied)))
            || (occupied & (1U << (slot % 32U))) == 0)
            continue;
        std::int16_t ordinal = -1;
        if (!memory::read_current_process(
                nullptr,
                reinterpret_cast<std::uintptr_t>(view) + kViewMapOffset + kViewMapStride * slot,
                std::span(reinterpret_cast<std::byte*>(&ordinal), sizeof(ordinal)))
            || ordinal < 0 || static_cast<std::size_t>(ordinal) >= kEntityRecordCapacity)
            continue;
        EntityRecordPrefix record{};
        std::uint16_t flags = 0;
        const auto address =
            g_entityRecordBase + kEntityRecordStride * static_cast<std::size_t>(ordinal);
        if (!memory::read_current_process(
                nullptr, address, std::span(reinterpret_cast<std::byte*>(&record), sizeof(record)))
            || !memory::read_current_process(
                nullptr,
                address + kEntityFlagsOffset,
                std::span(reinterpret_cast<std::byte*>(&flags), sizeof(flags))))
            continue;
        std::array<char, 240> line{};
        const int length =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=world_object stage=entity_unselected epoch=%u slot=%u type=%u "
                          "lifecycle=0x%02X cell=%u flags=0x%04X parent=0x%08X glue=0x%08X",
                          static_cast<unsigned>(epoch),
                          slot,
                          static_cast<unsigned>(record.type),
                          static_cast<unsigned>(record.lifecycle),
                          static_cast<unsigned>(record.cell),
                          static_cast<unsigned>(flags),
                          record.parent,
                          record.glue);
        if (length > 0)
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Logs the mask the native purge actually consumes and preserves all seven arguments. */
__declspec(noinline) void __fastcall purge_entities(void* view,
                                                    std::int32_t reason,
                                                    const std::uint32_t* mask,
                                                    std::uint32_t* work0,
                                                    std::uint32_t* work1,
                                                    std::uint32_t* work2,
                                                    std::uint8_t epoch) {
    ActiveCall active;
    const auto original = g_purgeEntitiesOriginal.load(std::memory_order_acquire);
    std::array<std::uint32_t, kEntityMaskWords> words{};
    const bool readable = memory::read_current_process(
        nullptr, reinterpret_cast<std::uintptr_t>(mask), std::as_writable_bytes(std::span(words)));
    if (readable && g_accepting.load(std::memory_order_acquire))
        report_unselected_records(view, words, epoch);
    std::array<std::uint32_t, kPurgeTraceCapacity> selected{};
    std::array<std::int16_t, kPurgeTraceCapacity> mappedBefore{};
    std::size_t selectedCount = 0;
    for (std::uint32_t slot = 0;
         readable && slot <= kEntityIndexMask && selectedCount < selected.size();
         ++slot) {
        if ((words[slot / 32U] & (1U << (slot % 32U))) == 0) continue;
        selected[selectedCount] = slot;
        mappedBefore[selectedCount] = -1;
        static_cast<void>(memory::read_current_process(
            nullptr,
            reinterpret_cast<std::uintptr_t>(view) + kViewMapOffset + kViewMapStride * slot,
            std::span(reinterpret_cast<std::byte*>(&mappedBefore[selectedCount]),
                      sizeof(std::int16_t))));
        ++selectedCount;
    }
    std::uint8_t before = 0;
    static_cast<void>(memory::read_current_process(
        nullptr,
        reinterpret_cast<std::uintptr_t>(view) + kViewEpochOffset,
        std::span(reinterpret_cast<std::byte*>(&before), sizeof(before))));
    if (readable && g_accepting.load(std::memory_order_acquire)) {
        for (std::size_t word = 0; word < words.size(); ++word) {
            if (words[word] == 0) continue;
            std::array<char, 192> line{};
            const int length = std::snprintf(line.data(),
                                             line.size(),
                                             "ev=world_object stage=entity_purge epoch=%u prior=%u "
                                             "reason=%d word=%zu bits=0x%08X",
                                             static_cast<unsigned>(epoch),
                                             static_cast<unsigned>(before),
                                             reason,
                                             word,
                                             words[word]);
            if (length > 0)
                core::log::write(core::log::Channel::client,
                                 core::log::Level::debug,
                                 {line.data(), static_cast<std::size_t>(length)});
        }
    }
    if (original != nullptr) original(view, reason, mask, work0, work1, work2, epoch);
    for (std::size_t index = 0;
         index < selectedCount && g_accepting.load(std::memory_order_acquire);
         ++index) {
        std::int16_t mappedAfter = -1;
        static_cast<void>(memory::read_current_process(
            nullptr,
            reinterpret_cast<std::uintptr_t>(view) + kViewMapOffset
                + kViewMapStride * selected[index],
            std::span(reinterpret_cast<std::byte*>(&mappedAfter), sizeof(mappedAfter))));
        std::array<char, 192> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=world_object stage=entity_purge_slot epoch=%u slot=%u before=%d after=%d view=%p",
            static_cast<unsigned>(epoch),
            selected[index],
            static_cast<int>(mappedBefore[index]),
            static_cast<int>(mappedAfter),
            view);
        if (length > 0)
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(length)});
    }
    std::uint8_t after = before;
    static_cast<void>(memory::read_current_process(
        nullptr,
        reinterpret_cast<std::uintptr_t>(view) + kViewEpochOffset,
        std::span(reinterpret_cast<std::byte*>(&after), sizeof(after))));
    if (g_accepting.load(std::memory_order_acquire)) {
        std::array<char, 160> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=world_object stage=entity_purge result=returned epoch=%u current=%u readable=%u",
            static_cast<unsigned>(epoch),
            static_cast<unsigned>(after),
            static_cast<unsigned>(readable));
        if (length > 0)
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Calls native allocation first, then reports it when the instantiate hook did not ask. */
__declspec(noinline) std::uint32_t* __fastcall allocate(std::uint32_t* output,
                                                        const void* entry,
                                                        std::int32_t objectListTag,
                                                        std::int32_t entryIndex) noexcept {
    ActiveCall active;
    const Allocate original = g_allocateOriginal.load(std::memory_order_acquire);
    std::uint32_t* const result =
        original != nullptr ? original(output, entry, objectListTag, entryIndex) : output;
    if (!t_inInstantiate && result != nullptr && *result != kNone
        && g_accepting.load(std::memory_order_acquire)) {
        report_allocation(*result, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
    }
    return result;
}

/** Reports one logical destroy, the only teardown that releases the object's entity. */
__declspec(noinline) std::uintptr_t __fastcall logical_destroy(std::uint32_t handle) noexcept {
    ActiveCall active;
    const LogicalDestroy original = g_logicalDestroyOriginal.load(std::memory_order_acquire);
    AcquireSRWLockExclusive(&g_lock);
    const bool report = g_logicalDestroyReportBudget > 0;
    if (report) {
        --g_logicalDestroyReportBudget;
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (report && g_accepting.load(std::memory_order_acquire)) {
        std::array<char, 128> line{};
        const int written =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=world_object stage=placement result=released handle=0x%08X "
                          "caller=+0x%llX",
                          handle,
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(_ReturnAddress()) - g_moduleBase));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    return original != nullptr ? original(handle) : 0;
}

/** Reports the teardown of one object the dynamic path built, and forgets it. */
void report_dynamic_destroy(std::uint32_t handle) noexcept {
    std::uint64_t ordinal = 0;
    AcquireSRWLockExclusive(&g_lock);
    for (std::size_t index = 0; index < kDynamicHandleCapacity; ++index) {
        if (g_dynamicHandles[index] == handle && g_dynamicOrdinals[index] != 0) {
            ordinal = g_dynamicOrdinals[index];
            g_dynamicHandles[index] = 0;
            g_dynamicOrdinals[index] = 0;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (ordinal == 0) {
        return;
    }
    std::array<char, 128> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=world_object stage=placement result=dynamic_destroyed "
                                      "handle=0x%08X ordinal=%llu",
                                      handle,
                                      static_cast<unsigned long long>(ordinal));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Removes the identity while its datum and generation still belong to this handle. */
__declspec(noinline) std::uintptr_t __fastcall destroy(std::uint32_t handle) noexcept {
    ActiveCall active;
    if (g_accepting.load(std::memory_order_acquire)) {
        AcquireSRWLockExclusive(&g_lock);
        erase(handle);
        ReleaseSRWLockExclusive(&g_lock);
        report_dynamic_destroy(handle);
    }
    const Destroy original = g_destroyOriginal.load(std::memory_order_acquire);
    return original != nullptr ? original(handle) : 0;
}

/** @return True when no replacement still owns a trampoline call. */
[[nodiscard]] bool calls_idle() noexcept {
    return g_activeCalls.load(std::memory_order_acquire) == 0;
}

/** Reads flags only when the datum still names the observed full handle. */
bool trace_flags(std::uint32_t handle, std::uint32_t& flags) noexcept {
    std::uintptr_t base{};
    std::uint32_t stride{}, self{};
    if (handle == kNone || !read_value(g_datumBaseStorage, base)
        || !read_value(g_datumStrideStorage, stride) || !base || stride < 16)
        return false;
    const auto datum = base + static_cast<std::uintptr_t>(stride) * (handle & kEntityIndexMask);
    return read_value(reinterpret_cast<const std::uint32_t*>(datum + 12), self) && self == handle
           && read_value(reinterpret_cast<const std::uint32_t*>(datum + 4), flags);
}

/** Logs a bounded line without trusting the formatter's required buffer length. */
template <typename... Args> void trace_log(const char* format, Args... args) noexcept {
    std::array<char, 640> line{};
    const int length = std::snprintf(line.data(), line.size(), format, args...);
    if (length > 0)
        core::log::write(
            core::log::Channel::client,
            core::log::Level::debug,
            {line.data(), std::min(static_cast<std::size_t>(length), line.size() - 1)});
}

/** Flushes the results of actual native calls for one actor visited by the rebind pass. */
void flush_rebind_actor(RebindTrace& value) noexcept {
    if (value.association.actor == kNone) return;
    if (g_rebindRows.fetch_add(1) < kRebindRowBudget) {
        value.flagsAfterKnown = trace_flags(value.association.owner, value.flagsAfter);
        trace_log("ev=world_object stage=squad_rebind_actor pass=%u activity=%p bubble=%u "
                  "actor=0x%08X owner=0x%08X flags=0x%08X flags_known=%u after=0x%08X "
                  "after_known=%u source_result=%d source_known=%u key=0x%08X type=%u index=%u "
                  "resolved=%d predicate=%d bind_called=%u count_before=%d count_after=%d "
                  "binding_before_known=%u binding_after_known=%u before0=0x%016llX "
                  "before1=0x%016llX after0=0x%016llX after1=0x%016llX",
                  value.pass,
                  value.activity,
                  value.bubble,
                  value.association.actor,
                  value.association.owner,
                  value.flags,
                  value.flagsKnown,
                  value.flagsAfter,
                  value.flagsAfterKnown,
                  value.sourceResult,
                  value.sourceKnown,
                  value.source.key,
                  value.source.type,
                  value.source.index,
                  value.resolveResult,
                  value.predicate,
                  value.bindCalled,
                  value.countBefore,
                  value.countAfter,
                  value.bindingBeforeKnown,
                  value.bindingAfterKnown,
                  value.bindingBefore[0],
                  value.bindingBefore[1],
                  value.bindingAfter[0],
                  value.bindingAfter[1]);
    }
    value.association.actor = kNone;
}

/** Preserves the observer's original call and records the bubble used by its native gate. */
__declspec(noinline) std::uintptr_t __fastcall trace_observer(void* observer,
                                                              void* activity,
                                                              const std::uint8_t* bubble) {
    ActiveCall active;
    const auto original = g_observerOriginal.load(std::memory_order_acquire);
    ObserverTrace observerTrace{};
    trace::Scope<ObserverTrace> scope(t_observerTrace, observerTrace);
    std::uint8_t requested{0xFF};
    std::uint32_t current{kNone};
    const bool report = g_accepting.load() && g_observerReports.fetch_add(1) < kRebindPassBudget;
    if (report && read_value(bubble, requested)) {
        observerTrace.activity = activity;
        observerTrace.bubble = requested;
        if (g_sliceManager && g_currentBubble) g_currentBubble(g_sliceManager(), &current);
        trace_log("ev=world_object stage=squad_observer activity=%p bubble=%u current=%u",
                  activity,
                  requested,
                  current);
    }
    const auto result = original ? original(observer, activity, bubble) : 0;
    return result;
}

/** Nested calls restore their caller's diagnostic scope without changing native execution. */
__declspec(noinline) std::uintptr_t __fastcall trace_rebind() {
    ActiveCall active;
    const auto original = g_rebindOriginal.load(std::memory_order_acquire);
    RebindTrace value{};
    trace::Scope<RebindTrace> scope(t_rebindTrace, value);
    const auto pass = g_rebindPasses.fetch_add(1);
    value.association.active = g_accepting.load() && pass < kRebindPassBudget;
    value.activity = t_observerTrace ? t_observerTrace->activity : nullptr;
    value.bubble = t_observerTrace ? t_observerTrace->bubble : kNone;
    value.pass = pass;
    const auto result = original ? original() : 0;
    flush_rebind_actor(value);
    if (value.association.active)
        trace_log("ev=world_object stage=squad_rebind pass=%u activity=%p bubble=%u visited=%u "
                  "bind_calls=%u",
                  pass,
                  value.activity,
                  value.bubble,
                  value.visited,
                  value.bound);
    return result;
}

/** Captures only the rebind function's direct actor iterator call. */
__declspec(noinline) std::uintptr_t __fastcall trace_iterator(void* iterator,
                                                              std::uint32_t* output) {
    ActiveCall active;
    const auto original = g_iteratorOriginal.load(std::memory_order_acquire);
    const auto result = original ? original(iterator, output) : 0;
    auto* value = t_rebindTrace;
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    if (value && value->association.active && caller == g_rebindAddress + 0x5F
        && (value->association.iterator == 0
            || value->association.iterator == reinterpret_cast<std::uintptr_t>(iterator))) {
        flush_rebind_actor(*value);
        if (value->association.visit(
                caller, g_rebindAddress + 0x5F, reinterpret_cast<std::uintptr_t>(iterator))) {
            value->source = {};
            value->sourceResult = value->resolveResult = value->predicate = -1;
            value->countBefore = value->countAfter = -1;
            value->bindCalled = value->bindingBeforeKnown = value->bindingAfterKnown = false;
            value->bindingBefore = value->bindingAfter = {};
            value->flagsKnown = value->flagsAfterKnown = value->sourceKnown = false;
            value->flags = value->flagsAfter = 0;
            if (read_value(output, value->association.actor) && value->association.actor != kNone) {
                ++value->visited;
                if (g_actorOwner) g_actorOwner(&value->association.owner, value->association.actor);
                value->flagsKnown = trace_flags(value->association.owner, value->flags);
            }
        }
    }
    return result;
}

/** Associates the actual source lookup with the current iterator output. */
__declspec(noinline) std::uint8_t __fastcall trace_source(std::uint32_t owner, void* output) {
    ActiveCall active;
    const auto original = g_sourceOriginal.load(std::memory_order_acquire);
    const std::uint8_t result = original ? original(owner, output) : std::uint8_t{};
    auto* value = t_rebindTrace;
    if (value && value->association.active && value->association.actor != kNone
        && reinterpret_cast<std::uintptr_t>(_ReturnAddress()) == g_rebindAddress + 0x83) {
        value->association.owner = owner;
        value->sourceResult = result;
        value->flagsKnown = trace_flags(owner, value->flags);
        if (result)
            value->sourceKnown = read_value(static_cast<const ActorSource*>(output), value->source);
    }
    return result;
}

/** Records only the source resolver called directly by the current rebind pass. */
__declspec(noinline) std::uint8_t __fastcall trace_resolve(const void* source, void* output) {
    ActiveCall active;
    const auto original = g_resolveSourceOriginal.load(std::memory_order_acquire);
    const std::uint8_t result = original ? original(source, output) : std::uint8_t{};
    auto* value = t_rebindTrace;
    ActorSource actual{};
    if (value && value->association.active && value->sourceKnown
        && reinterpret_cast<std::uintptr_t>(_ReturnAddress()) == g_rebindAddress + 0xA5
        && read_value(static_cast<const ActorSource*>(source), actual)
        && actual.key == value->source.key && actual.type == value->source.type
        && actual.index == value->source.index)
        value->resolveResult = result;
    return result;
}

/** Records the native exclusion predicate without invoking it a second time. */
__declspec(noinline) std::uintptr_t __fastcall trace_predicate(std::uint32_t owner) {
    ActiveCall active;
    const auto original = g_predicateOriginal.load(std::memory_order_acquire);
    const auto result = original ? original(owner) : 0;
    auto* value = t_rebindTrace;
    if (value
        && value->association.matches(
            reinterpret_cast<std::uintptr_t>(_ReturnAddress()), g_rebindAddress + 0x103, owner))
        value->predicate = static_cast<std::uint8_t>(result);
    return result;
}

/** Reads a binding only for the actual generation-valid actor selected by native iteration. */
bool trace_actor_binding(std::uint32_t actor, std::array<std::uint64_t, 2>& output) noexcept {
    std::uintptr_t base{};
    std::uint32_t stride{};
    if (actor == kNone || !read_value(g_actorBaseStorage, base)
        || !read_value(g_actorStrideStorage, stride) || !base || stride < 0x48)
        return false;
    return read_value(
        reinterpret_cast<const std::array<std::uint64_t, 2>*>(
            base + static_cast<std::uintptr_t>(stride) * (actor & kEntityIndexMask) + 0x38),
        output);
}

/** Records collection counts and the actor's binding around the actual native insertion call. */
__declspec(noinline) void __fastcall trace_bind(void* squad, std::uint32_t actor) {
    ActiveCall active;
    const auto original = g_bindOriginal.load(std::memory_order_acquire);
    auto* value = t_rebindTrace;
    const bool selected =
        value && value->association.active && value->association.actor == actor
        && reinterpret_cast<std::uintptr_t>(_ReturnAddress()) == g_rebindAddress + 0x135;
    const auto count = reinterpret_cast<const std::int32_t*>(reinterpret_cast<std::uintptr_t>(squad)
                                                             + kSquadCountOffset);
    if (selected) {
        value->bindCalled = true;
        ++value->bound;
        static_cast<void>(read_value(count, value->countBefore));
        value->bindingBeforeKnown = trace_actor_binding(actor, value->bindingBefore);
    }
    if (original) original(squad, actor);
    if (selected) {
        static_cast<void>(read_value(count, value->countAfter));
        value->bindingAfterKnown = trace_actor_binding(actor, value->bindingAfter);
    }
}

/** Captures generation-valid member owners before native teardown and checks them afterward. */
__declspec(noinline) std::uintptr_t __fastcall trace_teardown(void* squad) {
    ActiveCall active;
    const auto original = g_teardownOriginal.load(std::memory_order_acquire);
    std::array<std::uint32_t, kSquadMembers> owners{}, flags{};
    std::array<bool, kSquadMembers> known{};
    std::int32_t count{-1};
    const auto base = reinterpret_cast<std::uintptr_t>(squad);
    const bool report =
        g_accepting.load() && g_rebindRows.load() < kRebindRowBudget
        && read_value(reinterpret_cast<const std::int32_t*>(base + kSquadCountOffset), count)
        && count >= 0 && count <= static_cast<std::int32_t>(kSquadMembers);
    if (report)
        for (std::int32_t index = 0; index < count; ++index) {
            HandlePair pair{};
            std::int32_t actor{-1};
            owners[index] = kNone;
            if (read_value(reinterpret_cast<const HandlePair*>(base + kSquadRefsOffset + 8 * index),
                           pair)
                && g_validatePair && g_actorOwner) {
                g_validatePair(&pair, &actor);
                if (actor != -1) g_actorOwner(&owners[index], static_cast<std::uint32_t>(actor));
                known[index] = trace_flags(owners[index], flags[index]);
            }
        }
    const auto result = original ? original(squad) : 0;
    if (report && g_rebindRows.fetch_add(1) < kRebindRowBudget) {
        std::int32_t after{-1};
        static_cast<void>(
            read_value(reinterpret_cast<const std::int32_t*>(base + kSquadCountOffset), after));
        trace_log("ev=world_object stage=squad_teardown squad=%p before=%d after=%d",
                  squad,
                  count,
                  after);
        for (std::int32_t index = 0; index < count; ++index) {
            if (g_rebindRows.fetch_add(1) >= kRebindRowBudget) break;
            std::uint32_t afterFlags{};
            const bool afterKnown = trace_flags(owners[index], afterFlags);
            trace_log("ev=world_object stage=squad_teardown_member squad=%p index=%d owner=0x%08X "
                      "before=0x%08X before_known=%u after=0x%08X after_known=%u",
                      squad,
                      index,
                      owners[index],
                      flags[index],
                      known[index],
                      afterFlags,
                      afterKnown);
        }
    }
    return result;
}

/** Private signatures select the verified native diagnostic ABI. */
constexpr std::string_view kObserverTraceText =
    "48 89 5C 24 08 57 48 83 EC 20 49 8B F8 48 8B DA E8 ? ? ? ? 48 8B C8 48 8D 54 24 38 E8 ? ? ? ? "
    "E8 ? ? ? ? 48 3B D8 75 13";
constexpr auto kObserverTracePattern =
    signature<signature_length(kObserverTraceText)>(kObserverTraceText);
constexpr std::string_view kRebindTraceText =
    "48 89 5C 24 10 48 89 7C 24 18 55 48 8D AC 24 30 FF FF FF 48 81 EC D0 01 00 00 48 8B 05 ? ? ? "
    "? 48 33 C4 48 89 85 C0 00 00 00 33 FF 48 8D 4C 24 40 33 D2 89 7C 24 70 E8 E3 47 59 00";
constexpr auto kRebindTracePattern =
    signature<signature_length(kRebindTraceText)>(kRebindTraceText);
constexpr std::string_view kIteratorTraceText =
    "40 53 48 83 EC 20 48 8B DA E8 82 7D FB FF 48 8B C3 48 83 C4 20 5B C3";
constexpr auto kIteratorTracePattern =
    signature<signature_length(kIteratorTraceText)>(kIteratorTraceText);
constexpr std::string_view kSourceTraceText =
    "48 89 5C 24 10 56 48 83 EC 20 48 8B F2 8B D9 83 F9 FF 0F 84 8C 00 00 00 48 89 7C 24 30";
constexpr auto kSourceTracePattern =
    signature<signature_length(kSourceTraceText)>(kSourceTraceText);
constexpr std::string_view kResolveSourceTraceText =
    "40 53 48 83 EC 20 48 0F BE 41 04 48 8B DA 83 F8 3C 77 17 48 BA 00 00 00 00 00 B0 01 18";
constexpr auto kResolveSourceTracePattern =
    signature<signature_length(kResolveSourceTraceText)>(kResolveSourceTraceText);
constexpr std::string_view kPredicateTraceText =
    "48 8B 05 ? ? ? ? 8B D1 48 8B C8 4C 8B 00 49 FF A0 08 01 00 00";
constexpr auto kPredicateTracePattern =
    signature<signature_length(kPredicateTraceText)>(kPredicateTraceText);
constexpr std::string_view kBindTraceText = "48 89 5C 24 08 57 48 83 EC 30 48 8B F9 8B DA 48 81 C1 "
                                            "F0 02 00 00 E8 ? ? ? ? 84 C0 0F 84 97 00 00 00";
constexpr auto kBindTracePattern = signature<signature_length(kBindTraceText)>(kBindTraceText);
constexpr std::string_view kTeardownTraceText =
    "40 56 48 83 EC 40 83 B9 FC 05 00 00 FF 48 8B F1 0F 84 27 01 00 00";
constexpr auto kTeardownTracePattern =
    signature<signature_length(kTeardownTraceText)>(kTeardownTraceText);
constexpr std::string_view kActorOwnerTraceText =
    "C7 01 FF FF FF FF 83 FA FF 74 1B 81 E2 FF 1F 00 00 0F AF 15 ? ? ? ? 8B C2 48 03 05 ? ? ? ? 8B "
    "50 4C 89 11 48 8B C1 C3";
constexpr auto kActorOwnerTracePattern =
    signature<signature_length(kActorOwnerTraceText)>(kActorOwnerTraceText);

struct Targets final {
    std::byte* instantiate{};
    std::byte* destroy{};
    std::byte* allocate{};
    std::byte* logicalDestroy{};
    std::byte* resolvePair{};
    std::byte* validatePair{};
    std::byte* datumLayout{};
    std::byte* createEntity{};
    std::byte* purgeEntities{};
    std::byte* glueMapping{};
    std::byte* entityPool{};
    std::byte* entityPolicy{};
    std::byte* observer{};
    std::byte* rebind{};
    std::byte* iterator{};
    std::byte* source{};
    std::byte* resolveSource{};
    std::byte* predicate{};
    std::byte* bind{};
    std::byte* teardown{};
    std::byte* actorOwner{};
};

/** @return The main module's base, or zero when it cannot be read. */
[[nodiscard]] std::uintptr_t main_module_base() noexcept {
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

/** Resolves all five optional targets in one image pass. */
[[nodiscard]] bool resolve_targets(Targets& output) noexcept {
    output = {};
    executable::ExecutableImage main{};
    if (!executable::inspect_main_module(main)) {
        return false;
    }
    std::array<patterns::ImageRange, executable::kPeSectionLimit> ranges{};
    for (std::size_t index = 0; index < main.count; ++index) {
        ranges[index] = patterns::ImageRange{main.sections[index]};
    }
    const std::array definitions{
        patterns::Pattern{"placed_object_instantiate", kInstantiateSignature},
        patterns::Pattern{"placed_object_destroy", kDestroySignature},
        patterns::Pattern{"object_datum_allocate", kAllocateSignature},
        patterns::Pattern{"object_logical_destroy", kLogicalDestroySignature},
        patterns::Pattern{"object_handle_pair", kResolvePairSignature},
        patterns::Pattern{"object_handle_validate", kValidatePairSignature},
        patterns::Pattern{"object_datum_layout", kDatumLayoutSignature},
        patterns::Pattern{"simulation_sobject_create", kCreateEntityPattern},
        patterns::Pattern{"simulation_entity_purge", kPurgeEntitiesPattern},
        patterns::Pattern{"simulation_glue_mapping", kGlueMappingPattern},
        patterns::Pattern{"simulation_entity_pool", kEntityPoolPattern},
        patterns::Pattern{"simulation_entity_policy", kEntityPolicyPattern},
        patterns::Pattern{"squad_trace_observer", kObserverTracePattern},
        patterns::Pattern{"squad_trace_rebind", kRebindTracePattern},
        patterns::Pattern{"squad_trace_iterator", kIteratorTracePattern},
        patterns::Pattern{"squad_trace_source", kSourceTracePattern},
        patterns::Pattern{"squad_trace_resolveSource", kResolveSourceTracePattern},
        patterns::Pattern{"squad_trace_predicate", kPredicateTracePattern},
        patterns::Pattern{"squad_trace_bind", kBindTracePattern},
        patterns::Pattern{"squad_trace_teardown", kTeardownTracePattern},
        patterns::Pattern{"squad_trace_actorOwner", kActorOwnerTracePattern},

    };
    std::array<patterns::Match, definitions.size()> matches{};
    if (!patterns::resolve_all(std::span(ranges.data(), main.count), definitions, matches)) {
        return false;
    }
    for (const patterns::Match& match : matches) {
        if (match.status != patterns::MatchStatus::unique) {
            return false;
        }
    }
    output = {matches[0].address,  matches[1].address,  matches[2].address,  matches[3].address,
              matches[4].address,  matches[5].address,  matches[6].address,  matches[7].address,
              matches[8].address,  matches[9].address,  matches[10].address, matches[11].address,
              matches[12].address, matches[13].address, matches[14].address, matches[15].address,
              matches[16].address, matches[17].address, matches[18].address, matches[19].address,
              matches[20].address};
    return true;
}

/** Binds the two datum globals encoded at fixed operands in the checked layout signature. */
[[nodiscard]] bool bind_datum_layout(std::byte* target) noexcept {
    if (target == nullptr) {
        return false;
    }
    g_datumStrideStorage = reinterpret_cast<const std::uint32_t*>(
        patterns::resolve_relative(target + 41, target + 45));
    g_datumBaseStorage = reinterpret_cast<const std::uintptr_t*>(
        patterns::resolve_relative(target + 57, target + 61));
    return g_datumStrideStorage != nullptr && g_datumBaseStorage != nullptr;
}

} // namespace

/** Installs the generation-checked placed-object lifetime capture. */
bool install() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_handles[0].attached && g_handles[1].attached && g_handles[2].attached
        && g_handles[3].attached && g_handles[4].attached && g_handles[5].attached
        && std::all_of(
            g_handles.begin() + 6, g_handles.end(), [](const auto& h) { return h.attached; })) {
        const bool accepting = g_accepting.load(std::memory_order_acquire);
        ReleaseSRWLockExclusive(&g_lock);
        return accepting;
    }
    if (g_handles[0].attached || g_handles[1].attached || g_handles[2].attached
        || g_handles[3].attached || g_handles[4].attached || g_handles[5].attached
        || std::any_of(
            g_handles.begin() + 6, g_handles.end(), [](const auto& h) { return h.attached; })) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    g_moduleBase = main_module_base();
    Targets targets{};
    if (!resolve_targets(targets) || !bind_datum_layout(targets.datumLayout)) {
        ReleaseSRWLockExclusive(&g_lock);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=world_objects stage=install result=fail reason=targets");
        return false;
    }
    g_resolvePair = reinterpret_cast<ResolvePair>(targets.resolvePair);
    g_glueStrideStorage = reinterpret_cast<const std::uint32_t*>(
        patterns::resolve_relative(targets.glueMapping + 9, targets.glueMapping + 13));
    g_glueBaseStorage = reinterpret_cast<const std::uintptr_t*>(
        patterns::resolve_relative(targets.glueMapping + 18, targets.glueMapping + 22));
    g_entityRecordBase = reinterpret_cast<std::uintptr_t>(
        patterns::resolve_relative(targets.entityPool + 20, targets.entityPool + 24));
    g_validatePair = reinterpret_cast<ValidatePair>(targets.validatePair);
    const std::array specs{
        hooking::detour::Spec{targets.instantiate, reinterpret_cast<void*>(&instantiate)},
        hooking::detour::Spec{targets.destroy, reinterpret_cast<void*>(&destroy)},
        hooking::detour::Spec{targets.allocate, reinterpret_cast<void*>(&allocate)},
        hooking::detour::Spec{targets.logicalDestroy, reinterpret_cast<void*>(&logical_destroy)},
        hooking::detour::Spec{targets.createEntity, reinterpret_cast<void*>(&create_entity)},
        hooking::detour::Spec{targets.purgeEntities, reinterpret_cast<void*>(&purge_entities)},
        hooking::detour::Spec{targets.entityPolicy, reinterpret_cast<void*>(&entity_policy)},
        hooking::detour::Spec{targets.observer, reinterpret_cast<void*>(&trace_observer)},
        hooking::detour::Spec{targets.rebind, reinterpret_cast<void*>(&trace_rebind)},
        hooking::detour::Spec{targets.iterator, reinterpret_cast<void*>(&trace_iterator)},
        hooking::detour::Spec{targets.source, reinterpret_cast<void*>(&trace_source)},
        hooking::detour::Spec{targets.resolveSource, reinterpret_cast<void*>(&trace_resolve)},
        hooking::detour::Spec{targets.predicate, reinterpret_cast<void*>(&trace_predicate)},
        hooking::detour::Spec{targets.bind, reinterpret_cast<void*>(&trace_bind)},
        hooking::detour::Spec{targets.teardown, reinterpret_cast<void*>(&trace_teardown)},

    };
    if (!hooking::detour::install(specs, g_handles)) {
        g_resolvePair = nullptr;
        g_validatePair = nullptr;
        g_datumBaseStorage = nullptr;
        g_datumStrideStorage = nullptr;
        ReleaseSRWLockExclusive(&g_lock);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=world_objects stage=install result=fail reason=detour");
        return false;
    }
    g_instantiateOriginal.store(reinterpret_cast<Instantiate>(g_handles[0].original),
                                std::memory_order_release);
    g_destroyOriginal.store(reinterpret_cast<Destroy>(g_handles[1].original),
                            std::memory_order_release);
    g_allocateOriginal.store(reinterpret_cast<Allocate>(g_handles[2].original),
                             std::memory_order_release);
    g_logicalDestroyOriginal.store(reinterpret_cast<LogicalDestroy>(g_handles[3].original),
                                   std::memory_order_release);
    g_createEntityOriginal.store(reinterpret_cast<CreateEntity>(g_handles[4].original),
                                 std::memory_order_release);
    g_purgeEntitiesOriginal.store(reinterpret_cast<PurgeEntities>(g_handles[5].original),
                                  std::memory_order_release);
    g_entityPolicyOriginal.store(reinterpret_cast<EntityPolicy>(g_handles[6].original),
                                 std::memory_order_release);

    g_observerOriginal.store(reinterpret_cast<Observer>(g_handles[7].original),
                             std::memory_order_release);
    g_rebindOriginal.store(reinterpret_cast<Rebind>(g_handles[8].original),
                           std::memory_order_release);
    g_iteratorOriginal.store(reinterpret_cast<IteratorValue>(g_handles[9].original),
                             std::memory_order_release);
    g_sourceOriginal.store(reinterpret_cast<SourceRef>(g_handles[10].original),
                           std::memory_order_release);
    g_resolveSourceOriginal.store(reinterpret_cast<ResolveSource>(g_handles[11].original),
                                  std::memory_order_release);
    g_predicateOriginal.store(reinterpret_cast<Predicate>(g_handles[12].original),
                              std::memory_order_release);
    g_bindOriginal.store(reinterpret_cast<BindActor>(g_handles[13].original),
                         std::memory_order_release);
    g_teardownOriginal.store(reinterpret_cast<Teardown>(g_handles[14].original),
                             std::memory_order_release);
    g_actorOwner = reinterpret_cast<ActorOwner>(targets.actorOwner);
    g_actorStrideStorage = reinterpret_cast<const std::uint32_t*>(
        patterns::resolve_relative(targets.actorOwner + 20, targets.actorOwner + 24));
    g_actorBaseStorage = reinterpret_cast<const std::uintptr_t*>(
        patterns::resolve_relative(targets.actorOwner + 29, targets.actorOwner + 33));
    g_rebindAddress = reinterpret_cast<std::uintptr_t>(targets.rebind);
    g_observerAddress = reinterpret_cast<std::uintptr_t>(targets.observer);
    g_sliceManager = reinterpret_cast<SliceManager>(
        patterns::resolve_relative(targets.observer + 17, targets.observer + 21));
    g_currentBubble = reinterpret_cast<CurrentBubble>(
        patterns::resolve_relative(targets.observer + 30, targets.observer + 34));
    g_rebindPasses.store(0);
    g_rebindRows.store(0);
    g_observerReports.store(0);
    g_accepting.store(true, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lock);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=world_objects stage=install result=ok");
    return true;
}

/** Removes both lifetime hooks only after native calls have left their trampolines. */
bool uninstall() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (!g_handles[0].attached && !g_handles[1].attached && !g_handles[2].attached
        && !g_handles[3].attached && !g_handles[4].attached && !g_handles[5].attached
        && std::none_of(
            g_handles.begin() + 6, g_handles.end(), [](const auto& h) { return h.attached; })) {
        clear_registry();
        ReleaseSRWLockExclusive(&g_lock);
        return true;
    }
    g_accepting.store(false, std::memory_order_release);
    const std::array<hooking::detour::ProtectedCodeEntry, 15> protectedEntries{
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&instantiate)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&destroy)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&allocate)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&logical_destroy)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&create_entity)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&purge_entities)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&entity_policy)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_observer)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_rebind)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_iterator)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_source)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_resolve)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_predicate)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_bind)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&trace_teardown)},

    };
    const hooking::detour::UninstallResult result =
        hooking::detour::uninstall(g_handles, protectedEntries, &calls_idle);
    if (result != hooking::detour::UninstallResult::removed) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    g_instantiateOriginal.store(nullptr, std::memory_order_release);
    g_destroyOriginal.store(nullptr, std::memory_order_release);
    g_allocateOriginal.store(nullptr, std::memory_order_release);
    g_logicalDestroyOriginal.store(nullptr, std::memory_order_release);
    g_createEntityOriginal.store(nullptr, std::memory_order_release);
    g_purgeEntitiesOriginal.store(nullptr, std::memory_order_release);
    g_entityPolicyOriginal.store(nullptr, std::memory_order_release);
    g_observerOriginal.store(nullptr, std::memory_order_release);
    g_rebindOriginal.store(nullptr, std::memory_order_release);
    g_iteratorOriginal.store(nullptr, std::memory_order_release);
    g_sourceOriginal.store(nullptr, std::memory_order_release);
    g_resolveSourceOriginal.store(nullptr, std::memory_order_release);
    g_predicateOriginal.store(nullptr, std::memory_order_release);
    g_bindOriginal.store(nullptr, std::memory_order_release);
    g_teardownOriginal.store(nullptr, std::memory_order_release);
    g_actorOwner = nullptr;
    g_actorBaseStorage = nullptr;
    g_actorStrideStorage = nullptr;
    g_sliceManager = nullptr;
    g_currentBubble = nullptr;
    g_rebindAddress = g_observerAddress = 0;
    g_entityRecordBase = 0;
    g_policyTrace = {};
    g_glueBaseStorage = nullptr;
    g_glueStrideStorage = nullptr;
    g_resolvePair = nullptr;
    g_validatePair = nullptr;
    g_datumBaseStorage = nullptr;
    g_datumStrideStorage = nullptr;
    clear_registry();
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

/** @return True while both hooks are attached and accepting observations. */
bool is_installed() noexcept {
    AcquireSRWLockShared(&g_lock);
    const bool installed =
        g_handles[0].attached && g_handles[1].attached && g_handles[2].attached
        && g_handles[3].attached && g_handles[4].attached && g_handles[5].attached
        && std::all_of(
            g_handles.begin() + 6, g_handles.end(), [](const auto& h) { return h.attached; })
        && g_accepting.load(std::memory_order_acquire);
    ReleaseSRWLockShared(&g_lock);
    return installed;
}

/** Finds exact live instances, pruning any generation or datum mismatch. */
std::size_t
find(std::uint32_t objectListTag, std::uint32_t entryIndex, std::span<Instance> output) noexcept {
    std::size_t found = 0;
    AcquireSRWLockExclusive(&g_lock);
    for (RegistryEntry& entry : g_entries) {
        if (entry.state != EntryState::live || entry.instance.objectListTag != objectListTag
            || entry.instance.entryIndex != entryIndex) {
            continue;
        }
        if (!validate(entry.instance)) {
            entry.state = EntryState::tombstone;
            --g_liveCount;
            continue;
        }
        if (found < output.size()) {
            output[found] = entry.instance;
        }
        ++found;
    }
    if (g_liveCount == 0) {
        clear_registry();
    }
    ReleaseSRWLockExclusive(&g_lock);
    return found;
}

/** @return Current bounded-registry counters. */
Diagnostics diagnostics() noexcept {
    AcquireSRWLockShared(&g_lock);
    const Diagnostics result{g_liveCount,
                             g_overflowCount,
                             g_handles[0].attached && g_handles[1].attached
                                 && g_accepting.load(std::memory_order_acquire)};
    ReleaseSRWLockShared(&g_lock);
    return result;
}

} // namespace sunrise::client::hooks::world_objects
