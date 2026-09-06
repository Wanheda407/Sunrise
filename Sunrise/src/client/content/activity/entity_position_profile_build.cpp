#include "entity_position_profile_build.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

#include "../../../core/logging/log.h"
#include "../../../middleware/content/packages/named_tags.h"
#include "../../../middleware/content/packages/tables/entity_position_profile_extractor.h"
#include "../../../state/build_data/runtime.h"
#include "../../../state/content_manifest/content_manifest_state_runtime.h"
#include "../../../state/gameplay/external/entity_position_profiles.h"
#include "entity_object_type_build.h"

namespace sunrise::client::content::activity::entity_position_profiles {
namespace {
namespace profiles = state::gameplay::entity_position_profiles;
namespace extractor = middleware::content::packages::position_profiles;
namespace named = middleware::content::packages::named_tags;
namespace reader = middleware::content::packages::reader;
using Blob = std::vector<std::byte>;
struct Name final {
    extractor::NamedTag value;
    std::uint32_t patch{};
    bool conflict{};
};
struct Names final {
    std::map<std::string, Name> rows;
    bool base{};
    std::uint32_t patch{};
};
struct Context final {
    const reader::Source& source;
    reader::Scratch& scratch;
};
/** The manifest identity includes the installed package builds. */
bool fingerprint(void* opaque, const state::content_manifest::View& view) noexcept {
    std::copy(view.buildFingerprint.begin(),
              view.buildFingerprint.end(),
              static_cast<profiles::Fingerprint*>(opaque)->begin());
    return true;
}
/** Same-patch name conflicts cannot select an arbitrary package. */
bool collect_name(void* opaque, const named::Entry& entry) noexcept {
    try {
        auto& names = *static_cast<Names*>(opaque);
        if (entry.classId != 0x808091DE && entry.classId != 0x80809994) return true;
        const std::string name(entry.name.data(), entry.nameLength);
        auto found = names.rows.find(name);
        if (found == names.rows.end() || found->second.patch < names.patch)
            names.rows[name] = {{name, entry.tag, entry.classId, names.base}, names.patch, false};
        else if (found->second.patch == names.patch
                 && (found->second.value.tag != entry.tag
                     || found->second.value.classId != entry.classId))
            found->second.conflict = true;
        return true;
    } catch (...) {
        return false;
    }
}
template <class T> T value(const Blob& bytes, std::size_t offset) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) throw 0;
    T result{};
    std::memcpy(&result, bytes.data() + offset, sizeof result);
    return result;
}
/** Metadata references merge patches within a family before cross-family conflict checks. */
bool inventory(std::wstring_view directory,
               std::vector<extractor::NamedTag>& names,
               std::vector<extractor::KeyTag>& keys) {
    struct File final {
        std::filesystem::path path;
        std::wstring family;
        std::uint32_t patch{};
    };
    std::vector<File> files;
    for (const auto& file : std::filesystem::directory_iterator(directory)) {
        if (!file.is_regular_file() || file.path().extension() != L".pkg") continue;
        const auto stem = file.path().stem().wstring();
        const auto separator = stem.rfind(L'_');
        if (separator == std::wstring::npos) return false;
        std::size_t consumed{};
        const auto patch = std::stoul(stem.substr(separator + 1), &consumed);
        if (consumed != stem.size() - separator - 1 || patch > UINT32_MAX) return false;
        files.push_back(
            {file.path(), stem.substr(0, separator), static_cast<std::uint32_t>(patch)});
    }
    if (files.empty()) return false;
    std::sort(files.begin(), files.end(), [](const File& a, const File& b) {
        return a.family < b.family || (a.family == b.family && a.patch < b.patch);
    });
    Names collected;
    std::map<std::wstring, std::map<std::uint64_t, std::pair<std::uint32_t, std::uint32_t>>>
        families;
    for (const auto& file : files) {
        collected.base = file.family.find(L"_activities_") == std::wstring::npos;
        collected.patch = file.patch;
        named::Result result{};
        if (!named::extract_file(file.path.c_str(), &collect_name, &collected, result))
            return false;
        std::ifstream stream(file.path, std::ios::binary | std::ios::ate);
        const auto length = stream.tellg();
        Blob header(0x180);
        stream.seekg(0);
        if (!stream.read(reinterpret_cast<char*>(header.data()), header.size())
            || value<std::uint16_t>(header, 0) != 38)
            return false;
        /** Beta metadata has no hash64 reference directory at offset 48. */
        if (value<std::uint8_t>(header, 0x1A) == 0) continue;
        if (value<std::uint8_t>(header, 0x1A) != 1) return false;
        const auto offset = value<std::uint32_t>(header, 0xF0),
                   size = value<std::uint32_t>(header, 0xF4);
        if (size == 0) continue;
        if (size > 64 * 1024 * 1024
            || static_cast<std::uint64_t>(offset) + size > static_cast<std::uint64_t>(length))
            return false;
        Blob metadata(size);
        stream.seekg(offset);
        if (!stream.read(reinterpret_cast<char*>(metadata.data()), size)) return false;
        if (metadata.size() < 64) continue;
        std::vector<std::size_t> offsets;
        if (!extractor::array(metadata, 48, 16, 0x80809D02, offsets)) return false;
        auto& rows = families[file.family];
        for (auto member : offsets)
            rows[value<std::uint64_t>(metadata, member)] = {
                value<std::uint32_t>(metadata, member + 8),
                value<std::uint32_t>(metadata, member + 12)};
    }
    std::map<std::uint64_t, std::set<std::pair<std::uint32_t, std::uint32_t>>> merged;
    for (const auto& family : families)
        for (const auto& row : family.second)
            merged[row.first].insert(row.second);
    for (const auto& row : merged)
        if (row.second.size() == 1)
            keys.push_back({row.first, row.second.begin()->first, row.second.begin()->second});
    for (const auto& row : collected.rows)
        if (!row.second.conflict) names.push_back(row.second.value);
    return true;
}
/** Class checks apply to every live tag reached by the extraction. */
bool read(void* opaque, std::uint32_t tag, std::uint32_t expected, Blob& bytes) noexcept {
    auto& context = *static_cast<Context*>(opaque);
    std::uint32_t actual{};
    return reader::read_tag(context.source, context.scratch, tag, bytes, actual)
           && actual == expected;
}
} // namespace
bool ready() noexcept {
    profiles::Fingerprint identity{};
    if (!state::content_manifest::visit_snapshot(&fingerprint, &identity)) return false;
    const bool positions = profiles::confirm(identity);
    const bool objects = state::gameplay::entity_object_types::confirm(identity);
    return positions && objects;
}
/** The package pass confirms shared-cache rows or publishes a complete extraction. */
bool build(const reader::Source& source, reader::Scratch& scratch) noexcept {
    try {
        profiles::Fingerprint identity{};
        if (!state::content_manifest::visit_snapshot(&fingerprint, &identity)) return false;
        const bool positions = profiles::confirm(identity);
        const bool objects = state::gameplay::entity_object_types::confirm(identity);
        if (positions && objects) return true;
        if (!objects && !entity_object_types::build(source, scratch, identity)) return false;
        if (positions) {
            state::build_data::invalidate_cache();
            return true;
        }
        profiles::reset();
        std::vector<extractor::NamedTag> names;
        std::vector<extractor::KeyTag> keys;
        profiles::Rows rows;
        Context context{source, scratch};
        if (!inventory(source.directory, names, keys)
            || !extractor::extract(names, keys, &read, &context, rows))
            return false;
        const auto count = rows.size();
        const bool published = profiles::publish(std::move(rows), identity);
        if (published) state::build_data::invalidate_cache();
        char line[160]{};
        (void)std::snprintf(
            line, sizeof line, "entity_position_profiles source=packages rows=%zu", count);
        core::log::write(core::log::Channel::client, core::log::Level::info, line);
        return published;
    } catch (...) {
        return false;
    }
}
} // namespace sunrise::client::content::activity::entity_position_profiles
