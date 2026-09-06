#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../client/network/consumer.h"
#include "../../middleware/bap/activity_message/activity_patch_epoch_parser.h"
#include "../../middleware/bap/activity_message/replicate_membership.h"
#include "../../middleware/bap/activity_message/sensor_auth_update.h"
#include "../../middleware/bap/frame.h"
#include "../../middleware/content/packages/tables/scenario_reader.h"
#include "../../state/activity/bubble_authority/definition.h"
#include "../../state/activity/definition.h"
#include "../../state/activity_sdk/runtime.h"
#include "../../state/build_data/scenarios/definition.h"
#include "../../state/gameplay/external/squad_entity_retirement.h"
#include "../../state/runtime/runtime.h"
#include "../activity/host_runtime.h"
#include "activity_authority_query_owner.h"
#include "activity_authority_reset_owner.h"
#include "encrypted/queuez/definition.h"
#include "runtime.h"

namespace sunrise::server::bap {

/** One session per transport peer slot, so a connection id indexes this array directly. */
inline constexpr std::size_t kSessionCount = client::network::kBapConnectionCount;
/**
 * A delivered activity frame defers the next silence-prevention write.
 * This is the host's own period. It is not the floor handed to the client, which is a separate
 * value, and no bulk body may be scheduled on it.
 */
inline constexpr std::uint64_t kActivityKeepaliveIntervalMs = 2'000;

/** Counts matching authenticated links while the caller already owns the BAP lock. */
[[nodiscard]] std::size_t
activity_link_count_locked(const state::activity::SessionBinding& binding) noexcept;

/** Fixed scratch storage owned by the lock, kept off the Client thread's stack. */
struct Scratch {
    std::array<std::byte, client::network::kBapFrameCapacity> plaintext{};
    std::array<std::byte, client::network::kBapFrameCapacity> responseBody{};
    std::array<std::byte, client::network::kBapFrameCapacity> responsePayload{};
    std::array<std::byte, client::network::kBapFrameCapacity> sealed{};
    std::array<std::byte, client::network::kBapFrameCapacity> framed{};
    /** Roster groups the outbound body's slot spans point into, top-level and per-bubble alike. */
    std::array<state::build_data::scenarios::RosterGroup,
               middleware::bap::activity_message::sensor_auth_update::kPublishedGroupCapacity>
        rosterGroups{};
    /** Exact typed auth bodies the outbound snapshot span points into. */
    std::array<middleware::bap::activity_message::sensor_auth_update::AuthOverride,
               middleware::bap::activity_message::sensor_auth_update::kAuthOverrideCapacity>
        rosterAuthOverrides{};
    std::array<middleware::bap::activity_message::sensor_auth_update::SenseOverride,
               middleware::bap::activity_message::sensor_auth_update::kAuthOverrideCapacity>
        rosterSenseOverrides{};
    /** SDK-authored scene inputs staged before their exact msg-5 targets are installed. */
    std::array<state::activity_sdk::AuthoredSceneSeed,
               middleware::bap::activity_message::sensor_auth_update::kAuthOverrideCapacity>
        rosterSceneSeeds{};
    /** Per-bubble sub-blocks the outbound body's field-1 span points into. */
    std::array<middleware::bap::activity_message::sensor_auth_update::BubbleSubBlock,
               state::build_data::scenarios::kBubbleCapacity>
        rosterSubBlocks{};
    /** Keys each sub-block carries, which its own span points into. */
    std::array<
        std::array<std::uint32_t,
                   middleware::bap::activity_message::sensor_auth_update::kBubbleKeyCapacity>,
        state::build_data::scenarios::kBubbleCapacity>
        rosterSubBlockKeys{};
};

/** One registry key and its package object tag copied from an exact msg-5 roster snapshot. */
struct RosterDecodeEntry final {
    std::uint32_t registryKey{};
    std::uint32_t objectTag{};
};

/** Complete msg-5 roster identity map retained for one exact ActivityClient generation. */
struct RosterDecodeMap final {
    std::array<RosterDecodeEntry,
               middleware::bap::activity_message::sensor_auth_update::kPublishedGroupCapacity>
        entries{};
    std::uint64_t bindingGeneration{};
    std::uint16_t count{};
    bool valid{};
};

/**
 * One published group's registration identity and the revision last sent beside its key.
 * The wire carries one revision byte per key. The client tears down and rebuilds a group's
 * objects only when that byte moves, so the byte stays put while the group's identity holds.
 */
struct RosterGroupLease {
    std::uint32_t key{};
    std::uint32_t identityFold{};
    std::uint8_t sequence{};
    bool used{};
};

/** Lease slots mirror the roster's published-group capacity. */
inline constexpr std::size_t kRosterGroupLeaseCapacity =
    middleware::bap::activity_message::sensor_auth_update::kPublishedGroupCapacity;

/**
 * What one staged roster body owes State, and the counters to put back if it is discarded.
 * A bubble is offered once, and each group revision may rebuild that registry key. Counters and
 * staged per-group revisions may move only once the frame reaches the caller.
 */
struct RosterPublication {
    state::activity::bubble_authority::Grant grant{};
    state::gameplay::squad_entity_retirement::RetirementPlan entityRetirement{};
    /** Epochs remain staged until both retirement and roster frames reach the caller. */
    std::uint8_t retirementPriorEpoch{}, retirementBaseEpoch{}, retirementEpoch{};
    bool priorRosterOwedForEpoch{};
    /** Exact decode identities carried by this staged complete roster snapshot. */
    RosterDecodeMap decodeMap{};
    /** Exact typed body carried by this staged roster, if any. */
    activity::host::PendingScriptableOverride scriptableOverride{};
    /** ActivityClient generation that staged this grant and its roster counters. */
    std::uint64_t bindingGeneration{};
    /** Group leases as they stood before this body, put back if it never reaches the caller. */
    std::array<RosterGroupLease, kRosterGroupLeaseCapacity> priorLeases{};
    std::uint8_t priorSends{};
    std::uint8_t priorState{};
    /** Region epoch and the bubble it was stamped for, put back with the leases above. */
    std::uint8_t priorRegionEpoch{};
    std::int32_t priorRegionBubble{-1};
    /** Generated squad-group revision carried by this staged body. */
    std::uint8_t squadStateSequence{};
    /** Activity Host state revision carried by this body. */
    std::uint64_t hostStateRevision{};
    /** SDK selected-state roster lease revision carried by this body. */
    std::uint64_t missionSeedRevision{};
    /** Type-17 lifetime state carried for that revision. */
    std::uint8_t hostLifetimeState{};
    /** Exact authored region that owns the staged state-local group. */
    std::int32_t stateLocalRegion{-1};
    /** Set when the staged body carried a bubble grant that State has not recorded yet. */
    bool hasGrant{};
    /** Set when this body carries a pending Activity Host state revision. */
    bool hasHostState{};
    /** Set when this body carries a not-yet-published SDK selected-state roster lease revision. */
    bool hasMissionSeedRevision{};
    /** Set when this body carries the pending typed body above. */
    bool hasScriptableOverride{};
    /** Set when the delivered body merges into this binding's retained squad Auth set. */
    bool activatesSquadOverride{};
    /** Set when the staged squad body carries its own per-group revision. */
    bool hasSquadStateSequence{};
    /** Set while a roster body is staged and its outcome is undecided. */
    bool staged{};
};

/** Compact retained squad body; shared target fields and the generated group live on its group. */
struct RetainedSquadAuth {
    std::array<std::byte, middleware::bap::activity_message::squad_auth::kMaximumByteCount> body{};
    std::uint32_t generation{};
    std::uint16_t rosterSlotOffset{};
    std::uint16_t slotIndex{};
    std::uint16_t bitCount{};
    std::uint16_t byteCount{};
    /** Dense retained-group index that owns this body. */
    std::uint8_t groupIndex{};
};

/** One generated registry key and the squad Auth bodies that target its slots. */
struct RetainedSquadGroup {
    /** Fields shared by this group's retained slots; only slot offset and index vary. */
    activity::host::ScriptableTarget scopeTarget{};
    /** Exact generated SDK group shared by this group's retained slots. */
    state::build_data::scenarios::RosterGroup stateLocalRosterGroup{};
    std::int32_t region{-1};
    std::uint16_t authCount{};
    /** Last delivered revision of the generated state-local roster group. */
    std::uint8_t stateSequence{};
    /** Region epoch the revision was armed under; a newer one re-arms the group. */
    std::uint8_t regionEpoch{};
};

/** All generated squad groups retained by one exact ActivityClient binding. */
struct SquadOverrideLease {
    std::array<RetainedSquadAuth,
               middleware::bap::activity_message::sensor_auth_update::kAuthOverrideCapacity>
        authBodies{};
    std::array<RetainedSquadGroup,
               middleware::bap::activity_message::sensor_auth_update::kPublishedGroupCapacity>
        groups{};
    std::uint64_t bindingGeneration{};
    std::uint16_t authCount{};
    std::uint16_t groupCount{};
    bool active{};
};

/** Off-by-default generated selected-state roster plan pinned to one exact ActivityClient
 * generation. */
struct MissionSeedLease {
    ActivityMissionSeedPlan plan{};
    std::uint64_t bindingGeneration{};
    std::uint64_t revision{};
    std::uint64_t publishedRevision{};
    /**
     * Every authored region this lease has selected, in selection order. The peer's registered set
     * only grows: a group is torn down by a changed state byte, never by being left out, and every
     * message must seed its sync records. So each publication carries the union of these regions.
     */
    std::array<std::uint32_t, middleware::content::packages::tables::kSliceSetIndexFactor>
        registeredRegions{};
    std::uint8_t registeredRegionCount{};
    bool configured{};
    /**
     * Set once the complete selected-state set has been published. It only ratchets: shrinking
     * the published set back to the transition subset would re-register the shared groups.
     */
    bool fullSetPublished{};
    /**
     * The plan the previous selection held, kept while a region change waits for the client to
     * arrive. Publications in that window answer this plan's region: the client is tearing its
     * old world down, and registering the new region's groups into it races the teardown.
     */
    ActivityMissionSeedPlan previousPlan{};
    /** True from a region-changing selection until the client's post-arrival solicited answer. */
    bool regionArrivalPending{};
    /** Set when a mission script selected the plan. An adopted default plan is not a selection. */
    bool scriptSelected{};
};

static_assert(middleware::bap::activity_message::sensor_auth_update::kAuthOverrideCapacity
              == state::build_data::scenarios::kRosterSlotCapacity);

/** ActivityClient role owned by one authenticated BAP link. */
enum class ActivityClientRole : std::uint8_t {
    none,
    privateCurrent,
    publicTarget,
};

/** Exact activity-session generations owned by one BAP link. */
struct ActivityClientBinding {
    /** Target/current session that every activity envelope on this link names. */
    state::activity::SessionBinding session{};
    /** Same as session for private links; advertised source for public targets. */
    state::activity::SessionBinding source{};
    std::uint64_t groupSessionId{};
    std::uint64_t hostGeneration{};
    /** Changes on every bind and rejoin, even when the session id stays the same. */
    std::uint64_t bindingGeneration{};
    /** Epoch this host authored in the accepted join result. */
    std::uint8_t replicationEpoch{};
    /** Private: last citizen region. Public: immutable region captured by the host binding. */
    std::int32_t advertisedRegion{-1};
    /** True when the last advertisement named a private region's own Bubble Host. */
    bool advertisedPrivate{};
    ActivityClientRole role{ActivityClientRole::none};
};

/** Patch epoch tied to the exact ActivityClient binding that received it. */
struct BoundPatchEpoch {
    middleware::bap::activity_message::patch_epoch::PatchEpoch value{};
    std::uint64_t bindingGeneration{};
    bool seen{};
};

/** Host rows one membership body's directory holds against replacement. */
struct AdvertisementRetains {
    std::array<std::uint64_t,
               middleware::bap::activity_message::replicate_membership::kCitizenCapacity>
        hostGenerations{};
    std::uint8_t count{};
};

/** Host-session retains staged by one membership body until its frame is published. */
struct AdvertisementPublication {
    AdvertisementRetains retains{};
    bool staged{};
};

/** One staged msg-19 host output, committed only after its complete frame reaches the caller. */
struct IncidentPublication {
    std::uint64_t bindingGeneration{};
    std::uint64_t revision{};
    bool staged{};
};

/** One generation-bound activity message 44 request. */
struct ReplicationEpochPublication {
    std::uint64_t bindingGeneration{};
    std::uint8_t generation{};
    bool pending{};
    bool staged{};
};

/** Compact world reward retained until an active Family-4 peer can publish it. */
enum class WorldRewardKind : std::uint8_t {
    item,
    profileItem,
};

struct WorldRewardRequest {
    std::int32_t quantity{};
    std::uint16_t itemDefinitionIndex{};
    WorldRewardKind kind{};
    std::uint8_t failures{};
};
static_assert(sizeof(WorldRewardRequest) == 8);

inline constexpr std::size_t kWorldRewardQueueCapacity = 64;

/** Mutable transport state owned by one BAP connection. */
struct Session {
    std::uint64_t abilityRefreshDueTick{};
    std::uint64_t accountGeneration{};
    std::uint64_t accountResyncGeneration{};
    std::uint64_t activityAdvertisementHostGeneration{};
    std::uint64_t activityCharacterSoid{};
    std::uint64_t activityClientIdentityPublishedGeneration{};
    std::uint64_t activityClientIdentitySeenGeneration{};
    std::uint64_t activityHostStateRevision{};
    std::uint64_t activityIncidentRetryDueTick{};
    std::uint64_t activityJoinGeneration{};
    std::uint64_t activityKeepaliveDueTick{};
    std::uint64_t activityMemberKey{};
    std::uint64_t activityMembershipSentGeneration{};
    std::uint64_t activityRosterDueTick{};
    std::uint64_t activityTransitionUntilTick{};
    std::uint64_t acquisitionPresentationUntilTick{};
    std::uint64_t artifactFamily4RefreshDueTick{};
    std::uint64_t bannerRepushDueTick{};
    std::uint64_t bannerRepushRoot{};
    std::uint64_t family4RepushDueTick{};
    std::uint64_t family4RepushRoot{};
    std::uint64_t socialRosterRepushDueTick{};
    std::uint64_t socialRosterRepushRoot{};

    std::uint32_t activityRosterGroups{};
    std::uint32_t id{};
    std::uint32_t pendingSeasonalExperienceMutationSerial{};
    std::int32_t activityRosterRegionBubble{-1};
    std::int32_t pendingSeasonalExperienceAmount{};
    
    std::uint8_t activityRosterReason{};
    std::uint8_t activityRosterRegionEpoch{};
    std::uint8_t activityRosterSends{};
    std::uint8_t activityRosterState{};
    std::uint8_t acquisitionPresentationRowCount{};
    std::uint8_t pendingSeasonalExperienceFailures{};

    ActivityClientBinding activity{};
    AdvertisementPublication activityAdvertisementStaged{};
    AdvertisementRetains activityAdvertisementHeld{};
    BoundPatchEpoch activityPatchEpoch{};
    IncidentPublication activityIncidentStaged{};
    MissionSeedLease activityMissionSeed{};
    ReplicationEpochPublication activityReplicationEpoch{};
    RosterDecodeMap activityRosterDecode{};
    RosterPublication activityRosterStaged{};
    SquadOverrideLease activitySquadOverride{};

    authority_query::Owner activityAuthorityQuery{};
    authority_reset::Owner activityAuthorityReset{};
    state::ArtifactResetResult artifactResetRefresh{};
    state::matchmaking::ContextHandle matchmakingContext{};
    encrypted::queuez::SessionState queuez{};

    bool abilityRefreshArmed{};
    bool accountMutationPublished{};
    bool accountResyncArmed{};
    bool activityJoinMembershipStaged{};
    bool activityRosterOwedForEpoch{};
    bool artifactFamily4RefreshArmed{};
    bool artifactRefreshArmed{};
    bool authenticated{};
    bool bannerRepushArmed{};
    bool cinematicHeld{};
    bool family4RepushArmed{};
    bool socialRosterRepushArmed{};
    
    std::size_t artifactResetRefreshCursor{};
    std::array<std::byte, state::kBapNonceSize> sendNonce{};
    std::array<std::byte, state::kBapNonceSize> receiveNonce{};
    std::array<std::byte, state::kAesKeySize> sessionKey{};
    std::array<RosterGroupLease, kRosterGroupLeaseCapacity> activityRosterGroupLeases{};
    std::array<encrypted::queuez::AcquisitionPresentationRow,
               encrypted::queuez::kAcquisitionPresentationRowCapacity>
        acquisitionPresentationRows{};
};

/** Arms every other Family-4 peer after the origin publishes a complete account mutation. */
void arm_account_resync_elsewhere(Session& origin) noexcept;

/** Arms every Family-4 peer, including the origin, for a full account resync. */
void arm_account_resync_everywhere() noexcept;

/** Holds this peer's full Family-4 refreshes until its acquisition flyout has finished. */
void arm_acquisition_presentation_hold(Session& session) noexcept;

/** Queues one character item for normal acquisition feedback. */
[[nodiscard]] bool arm_world_item_acquisition(std::uint16_t itemDefinitionIndex) noexcept;

/** Queues one profile material for normal acquisition feedback. */
[[nodiscard]] bool arm_world_profile_item_acquisition(std::uint16_t itemDefinitionIndex,
                                                      std::int32_t quantity) noexcept;

/** Reads the oldest queued world reward without removing it. */
[[nodiscard]] bool current_world_reward(WorldRewardRequest& request) noexcept;

/** Removes the world reward returned by current_world_reward. */
void complete_world_reward() noexcept;

/** Records one failed publication and settles a repeatedly failing reward. */
void fail_world_reward_attempt() noexcept;

/** Queues one transient XP item update so the native HUD presents a seasonal XP gain. */
[[nodiscard]] bool arm_seasonal_experience_presentation(std::int32_t amount) noexcept;

/**
 * Finds one unambiguous registry identity in a committed connection-local roster map.
 * @param map Last complete msg-5 map delivered on one BAP connection.
 * @param expectedBindingGeneration Exact ActivityClient generation routing the client message.
 * @param registryKey Client-reported registry key from that roster.
 * @return The unique entry, or null for an invalid/stale map, absent key, or duplicate key.
 */
[[nodiscard]] const RosterDecodeEntry*
find_roster_decode_entry(const RosterDecodeMap& map,
                         std::uint64_t expectedBindingGeneration,
                         std::uint32_t registryKey) noexcept;

namespace plaintext {

/**
 * Handles plaintext bootstrap services, arms encryption after service 25, and routes the rest.
 * @param session Auth and nonce state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param outer Parsed outer frame carrying the service id and its body.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded response size in bytes.
 * @return True when the service owes no reply, or its response is encoded.
 */
[[nodiscard]] bool consume(Session& session,
                           Scratch& scratch,
                           const middleware::bap::OuterFrame& outer,
                           std::span<std::byte> response,
                           std::size_t& written) noexcept;

} // namespace plaintext

namespace encrypted {

/**
 * Authenticates and routes one encrypted post-bootstrap service frame.
 * @param session Auth and nonce state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param outer Validated encrypted outer frame.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded response size in bytes.
 * @return True when routing works, any response fits, State commits and the nonce is published.
 */
[[nodiscard]] bool consume(Session& session,
                           Scratch& scratch,
                           const middleware::bap::OuterFrame& outer,
                           std::span<std::byte> response,
                           std::size_t& written) noexcept;

/**
 * Sends the owed Family-4 re-push once its delay has passed.
 * @param session Auth, nonce and queuez state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded notification size in bytes.
 * @param touchesScratch Set before any scratch buffer is used.
 * @return True when a whole Family-4 notification is published.
 */
[[nodiscard]] bool consume_deferred(Session& session,
                                    Scratch& scratch,
                                    std::span<std::byte> response,
                                    std::size_t& written,
                                    bool& touchesScratch) noexcept;

} // namespace encrypted

} // namespace sunrise::server::bap
