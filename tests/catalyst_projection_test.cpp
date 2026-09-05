#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <fstream>
#include "state/progression/seasonal_experience.h"
#include "state/build_data/cache/records/codec.h"
#include "state/build_data/items/catalysts/exotic_catalyst_catalog.h"
#include "state/unlocks/definition.h"
#include "middleware/encoding/bit_reader.h"
#include "middleware/web_service/messages/opcode503.h"
#include "middleware/web_service/messages/opcode205.h"

namespace st = sunrise::state;
namespace cat = st::build_data::items::catalysts;
namespace ws = sunrise::middleware::web_service;
using sunrise::middleware::encoding::bits::Reader;

static std::uint64_t read(Reader& r, std::uint8_t bits) {
    std::uint64_t v{};
    assert(r.read(bits,v));
    return v;
}

static void decode_family(Reader& r,const st::Family5State& family) {
    assert(read(r,1)==1 && read(r,64)==family.objectSoid);
    assert(read(r,1)==1 && read(r,64)==123);
    assert(read(r,1)==0 && read(r,1)==0);
    assert(read(r,1)==1 && read(r,7)==family.flagCount);
    for(std::size_t i=0;i<family.flagCount;++i) {
        assert(read(r,1)==1 && read(r,16)==family.flags[i].slot+0x8000U);
        assert(read(r,1)==1 && read(r,2)==family.flags[i].value+1U);
    }
    assert(read(r,1)==1 && read(r,7)==family.valueCount);
    for(std::size_t i=0;i<family.valueCount;++i) {
        assert(read(r,1)==1 && read(r,16)==family.values[i].slot+0x8000U);
        assert(read(r,1)==1 && read(r,32)==static_cast<std::uint32_t>(family.values[i].value)+0x80000000U);
    }
    assert(read(r,1)==0);
    assert(read(r,1)==1 && read(r,32)==1); // content-gate arm
    assert(read(r,1)==0 && read(r,1)==0 && read(r,2)==0);
    assert(r.remaining_bits()<8);
}

int main(int argc, char** argv) {
    assert(argc == 2);
    static_assert(st::kUnlockOverrideCapacity == 100);
    namespace artifact = st::progression::seasonal_experience;
    std::array<cat::Definition, 45> rows{};
    std::ifstream fixture(argv[1]);
    assert(fixture);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        auto& row = rows[i];
        row.itemDefinitionHash = static_cast<std::uint32_t>(i + 1);
        row.itemDefinitionIndex = static_cast<std::uint16_t>(i);
        row.completedPlugDefinitionIndex = row.effectDefinitionIndex = 100;
        row.progressPlugDefinitionIndex = 0xFFFF;
        row.availability = cat::Availability::released;
        unsigned count;
        fixture >> row.acquisitionDefinitionIndex >> count;
        assert(count <= row.completion.flags.size());
        row.completion.flagCount = static_cast<std::uint8_t>(count);
        for (std::size_t j = 0; j < count; ++j)
            fixture >> row.completion.flags[j] >> row.completionAccountFlagIndices[j];
        fixture >> count;
        assert(count <= row.completion.values.size());
        row.completion.valueCount = static_cast<std::uint8_t>(count);
        for (std::size_t j = 0; j < count; ++j)
            fixture >> row.completion.values[j].index >> row.completion.values[j].minimum;
        assert(fixture);
    }
    // Shipped authored flags, before the artifact/catalyst projections.
    const std::array<st::UnlockFlagOverride, 43> defaults{{
        {2003, 2},
        {2260, 2},
        {3698, 2},
        {4661, 2},
        {5901, 2},
        {7188, 2},
        {9144, 2},
        {9150, 2},
        {9162, 2},
        {9164, 2},
        {9169, 2},
        {9171, 2},
        {9176, 2},
        {9178, 2},
        {9180, 2},
        {9183, 2},
        {9186, 2},
        {9279, 2},
        {9355, 2},
        {9567, 2},
        {11554, 2},
        {11558, 2},
        {15034, 2},
        {16840, 2},
        {16843, 2},
        {16846, 2},
        {16849, 2},
        {16852, 2},
        {16854, 2},
        {16856, 2},
        {16857, 2},
        {16860, 2},
        {16862, 2},
        {16865, 2},
        {16868, 2},
        {16871, 2},
        {16873, 2},
        {16875, 2},
        {16878, 2},
        {16884, 2},
        {16887, 2},
        {16889, 2},
        {16892, 2},
    }};
    st::Family5State initial{};
    for (const auto row : defaults) initial.flags[initial.flagCount++] = row;
    auto unmapped = rows;
    for (auto& row : unmapped) row.completionAccountFlagIndices.fill(0xFFFF);
    assert(cat::replace(unmapped));
    auto family = initial;
    assert(!cat::append_investment_overrides(family)); // 105 flags even without artifact duplication
    assert(family.flagCount == initial.flagCount && family.valueCount == 0);
    for (std::size_t i = 0; i < family.flags.size(); ++i)
        assert(family.flags[i].slot == initial.flags[i].slot && family.flags[i].value == initial.flags[i].value);

    assert(cat::replace(rows));
    assert(artifact::apply_artifact_state(family));
    assert(family.flagCount == 43 && family.valueCount == 3);
    assert(cat::append_investment_overrides(family));
    assert(family.flagCount == 90 && family.valueCount == 34);
    for (std::size_t i = 0; i < defaults.size(); ++i)
        assert(family.flags[i].slot == defaults[i].slot && family.flags[i].value == defaults[i].value);
    std::array<std::uint8_t, st::unlocks::kAccountFlagCapacity> flags{};
    flags[10] = 1;
    assert(cat::append_account_completions(flags));
    std::size_t mappedCount = 0;
    std::uint16_t highest = 0;
    for (const auto& row : rows) for (auto mapped : row.completionAccountFlagIndices) {
        if (mapped == 0xFFFF) continue;
        ++mappedCount;
        assert(flags[mapped] == 2);
        highest = (std::max)(highest, mapped);
    }
    assert(mappedCount == 15 && flags[10] == 1);
    flags.fill(0);
    assert(!cat::append_account_completions(std::span(flags).first(highest)));
    for (auto v : flags) assert(v == 0); // no partial writes
    cat::set_completion_enabled(false);
    assert(cat::append_account_completions(flags));
    family = initial;
    assert(cat::append_investment_overrides(family) && family.flagCount == 43);
    for (auto v : flags) assert(v == 0);
    cat::set_completion_enabled(true);
    auto bad = rows;
    bad[0].completionAccountFlagIndices[0] = st::unlocks::kAccountFlagCapacity;
    assert(!cat::replace(bad));
    bad = rows;
    for (auto& row : bad) row.availability = cat::Availability::placeholder;
    assert(cat::replace(bad));
    assert(cat::append_account_completions(flags));
    for (auto v : flags) assert(v == 0);
    // Row zero is a valid mapped bank index; unavailable is exclusively 0xFFFF.
    auto single = rows.back();
    single.completionAccountFlagIndices[0] = 0;
    assert(single.completion.flagCount > 0 && cat::replace(std::span(&single, 1)));
    assert(cat::append_account_completions(flags) && flags[0] == 2);
    family = {};
    family.flags[family.flagCount++] = {single.completion.flags[0], 0};
    assert(cat::append_investment_overrides(family));
    assert(family.flags[0].value == 2); // authored false must not mask the native completion

    // Artifact purchase and reset still update the existing native character bank.
    std::array<std::byte, st::unlocks::kCharacterObjectFlagCapacity> characterFlags{};
    std::array<std::int32_t, st::unlocks::kCharacterObjectValueCapacity> characterValues{};
    assert(artifact::apply_artifact_character_state(1, characterFlags, characterValues));
    assert(characterFlags[164] == std::byte{2} && characterValues[38] == 1);
    assert(artifact::apply_artifact_character_state(0, characterFlags, characterValues));
    assert(characterFlags[164] == std::byte{0} && characterValues[38] == 0);
    family = initial;
    family.flags[family.flagCount++] = {1428, 2};
    family.flags[family.flagCount++] = {1388, 0};
    assert(artifact::apply_artifact_state(family) && family.flagCount == initial.flagCount);
    family = initial;
    family.valueCount = family.values.size();
    for (std::size_t i = 0; i < family.valueCount; ++i)
        family.values[i] = {static_cast<std::uint16_t>(i), 0};
    assert(!artifact::apply_artifact_state(family) && family.flagCount == initial.flagCount);

    namespace cache=st::build_data::cache::records;
    cache::ExoticCatalystRecord disk{};
    cat::Definition decoded{};
    assert(cache::encode(rows.back(),disk) && cache::decode(disk,decoded) && decoded==rows.back());

    st::InvestmentState investment{};
    investment.family5.objectSoid=42;
    investment.family5.contentGateArm=true;
    investment.family5.flagCount=investment.family5.valueCount=100;
    for(std::size_t i=0;i<100;++i) {
        investment.family5.flags[i]={static_cast<std::uint16_t>(7000+i),2};
        investment.family5.values[i]={static_cast<std::uint16_t>(8000+i),static_cast<std::int32_t>(i)};
    }
    std::array<std::byte,1200> output{};
    std::size_t written=0;
    ws::Message request{503,7,{}};
    assert(ws::messages::opcode503::encode_response(request,{42,true},investment,123,output,written));
    Reader bootstrap(std::span<const std::byte>(output).subspan(6,written-6));
    assert(read(bootstrap,5)==1 && read(bootstrap,32)==0x7FFFFFFFU);
    assert(read(bootstrap,64)==42 && read(bootstrap,32)==0 && read(bootstrap,32)==0);
    decode_family(bootstrap,investment.family5);
    request.opcode=205;
    assert(ws::messages::opcode205::encode_response(request,investment,123,output,written));
    Reader snapshot(std::span<const std::byte>(output).subspan(6,written-6));
    assert(read(snapshot,5)==1);
    decode_family(snapshot,investment.family5);
    investment.family5.flagCount=101;
    assert(!ws::messages::opcode205::encode_response(request,investment,123,output,written) && written==0);
    request.opcode=503;
    assert(!ws::messages::opcode503::encode_response(request,{42,true},investment,123,output,written) && written==0);
    std::cout<<"Catalyst account projection, atomic failures, cache row, and 100-row bootstrap/snapshot contracts passed\n";
}
