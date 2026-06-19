#include <demida/imports.hpp>

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <limits>
#include <optional>
#include <string_view>
#include <unordered_set>

namespace demida {
namespace {

constexpr auto max_thunk_depth = 16u;
constexpr auto max_thunk_decode_bytes = 16u;
constexpr auto max_v3_iat_pointers = 100u;

status make_error(const status_code code, std::wstring message) {
    return status{code, std::move(message)};
}

DEMIDA_FORCE_INLINE bool valid_pointer_size(const std::uint32_t pointer_size) noexcept {
    return pointer_size == 4u || pointer_size == 8u;
}

DEMIDA_FORCE_INLINE bool ascii_wide_iequals(
    const std::wstring_view left,
    const std::string_view right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }

    for (std::size_t index = 0; index != left.size(); ++index) {
        const auto wide = static_cast<wchar_t>(std::towlower(left[index]));
        const auto narrow = static_cast<wchar_t>(std::tolower(static_cast<unsigned char>(right[index])));
        if (wide != narrow) {
            return false;
        }
    }

    return true;
}

struct ordinal_import_entry {
    std::string_view name;
    std::uint16_t ordinal = 0;
};

constexpr std::array<ordinal_import_entry, 7> oleaut32_ordinal_imports = {{
    {"SysAllocString", 2u},
    {"SysFreeString", 6u},
    {"VariantInit", 8u},
    {"VariantClear", 9u},
    {"SafeArrayGetUBound", 19u},
    {"SafeArrayGetLBound", 20u},
    {"SafeArrayGetElement", 25u},
}};

result<std::uint32_t> pointer_size_for_arch(const arch architecture) {
    switch (architecture) {
    case arch::x86:
        return 4u;
    case arch::x64:
        return 8u;
    default:
        return make_error(status_code::invalid_argument, L"unsupported architecture");
    }
}

DEMIDA_FORCE_INLINE std::uint32_t read_u32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(bytes[offset + 0]) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16u) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24u);
}

DEMIDA_FORCE_INLINE std::int32_t read_i32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::int32_t>(read_u32(bytes, offset));
}

DEMIDA_FORCE_INLINE void write_u32(
    std::vector<std::uint8_t>& bytes,
    const std::size_t offset,
    const std::uint32_t value) {
    bytes[offset + 0] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8u);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 16u);
    bytes[offset + 3] = static_cast<std::uint8_t>(value >> 24u);
}

DEMIDA_FORCE_INLINE std::uint64_t add_i32(const std::uint64_t base, const std::int32_t displacement) noexcept {
    if (displacement >= 0) {
        return base + static_cast<std::uint32_t>(displacement);
    }

    const auto magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
    return base - magnitude;
}

DEMIDA_FORCE_INLINE bool is_pad_byte(const std::uint8_t value) noexcept {
    return value == 0x90u || value == 0xCCu;
}

DEMIDA_FORCE_INLINE bool is_any_executable_protect(const std::uint32_t protect) noexcept {
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
        return false;
    }

    switch (protect & 0xFFu) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

DEMIDA_FORCE_INLINE bool is_read_execute_protect(const std::uint32_t protect) noexcept {
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
        return false;
    }

    switch (protect & 0xFFu) {
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

std::optional<std::uint64_t> read_pointer_value(
    const read_memory_fn& read_memory,
    const std::uint64_t address,
    const std::uint32_t pointer_size) {
    const auto memory = read_memory(address, pointer_size);
    if (memory.is_error() || memory.value().size() < pointer_size) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (auto index = 0u; index != pointer_size; ++index) {
        value |= static_cast<std::uint64_t>(memory.value()[index]) << (index * 8u);
    }

    return value;
}

std::optional<std::uint64_t> read_pointer_from_span(
    const std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::uint32_t pointer_size) {
    if (!valid_pointer_size(pointer_size) || offset + pointer_size > bytes.size()) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (auto index = 0u; index != pointer_size; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8u);
    }

    return value;
}

std::optional<std::uint64_t> unwrap_data_pointer(
    const std::uint64_t value,
    const std::span<const std::uint8_t> data,
    const std::uint64_t data_va,
    const std::uint32_t pointer_size) {
    if (value < data_va) {
        return std::nullopt;
    }

    const auto offset64 = value - data_va;
    if (offset64 > static_cast<std::uint64_t>(data.size())) {
        return std::nullopt;
    }

    const auto offset = static_cast<std::size_t>(offset64);
    return read_pointer_from_span(data, offset, pointer_size);
}

struct resolver_context {
    arch architecture = arch::unknown;
    std::uint32_t pointer_size = 0;
    const std::unordered_map<std::uint64_t, export_symbol>* exports = nullptr;
    const read_memory_fn* read_memory = nullptr;
    const query_protect_fn* query_protect = nullptr;
};

std::optional<std::uint64_t> resolve_target(
    const resolver_context& context,
    std::uint64_t target_va,
    std::unordered_set<std::uint64_t>& visited,
    std::uint32_t depth);

std::optional<std::uint64_t> resolve_decoded_instruction(
    const resolver_context& context,
    const decoded_import_instruction& decoded,
    std::unordered_set<std::uint64_t>& visited,
    const std::uint32_t depth) {
    if (decoded.has_destination) {
        return resolve_target(context, decoded.destination_va, visited, depth + 1u);
    }

    if (!decoded.has_pointer_slot) {
        return std::nullopt;
    }

    const auto pointer_value = read_pointer_value(*context.read_memory, decoded.pointer_slot_va, context.pointer_size);
    if (!pointer_value.has_value() || *pointer_value == 0u) {
        return std::nullopt;
    }

    return resolve_target(context, *pointer_value, visited, depth + 1u);
}

std::optional<std::uint64_t> resolve_target(
    const resolver_context& context,
    const std::uint64_t target_va,
    std::unordered_set<std::uint64_t>& visited,
    const std::uint32_t depth) {
    if (target_va == 0u) {
        return std::nullopt;
    }

    if (context.exports->find(target_va) != context.exports->end()) {
        return target_va;
    }

    if (depth >= max_thunk_depth) {
        return std::nullopt;
    }

    if (!visited.insert(target_va).second) {
        return std::nullopt;
    }

    const auto protection = (*context.query_protect)(target_va);
    if (protection.is_error() || !is_any_executable_protect(protection.value())) {
        return std::nullopt;
    }

    const auto memory = (*context.read_memory)(target_va, max_thunk_decode_bytes);
    if (memory.is_error() || memory.value().empty()) {
        return std::nullopt;
    }

    const auto decoded = decode_import_instruction(context.architecture, target_va, memory.value());
    if (decoded.is_error() || decoded.value().kind == import_instruction_kind::none) {
        return std::nullopt;
    }

    return resolve_decoded_instruction(context, decoded.value(), visited, depth);
}

std::optional<std::uint64_t> resolve_call_site(
    const resolver_context& context,
    const decoded_import_instruction& decoded) {
    std::unordered_set<std::uint64_t> visited;
    return resolve_decoded_instruction(context, decoded, visited, 0u);
}

} // namespace

bool should_encode_import_by_ordinal(
    const std::wstring_view module_name,
    const std::string_view name,
    const std::uint16_t ordinal) noexcept {
    if (!ascii_wide_iequals(module_name, "oleaut32.dll")) {
        return false;
    }

    for (const auto& entry : oleaut32_ordinal_imports) {
        if (entry.ordinal == ordinal && entry.name == name) {
            return true;
        }
    }

    return false;
}

std::uint64_t encode_ordinal_import_thunk(const std::uint16_t ordinal, const std::uint32_t pointer_size) noexcept {
    const auto flag = pointer_size == 8u ? IMAGE_ORDINAL_FLAG64 : static_cast<std::uint64_t>(IMAGE_ORDINAL_FLAG32);
    return flag | ordinal;
}

result<decoded_import_instruction> decode_import_instruction(
    const arch architecture,
    const std::uint64_t instruction_va,
    const std::span<const std::uint8_t> bytes) {
    if (architecture != arch::x86 && architecture != arch::x64) {
        return make_error(status_code::invalid_argument, L"unsupported architecture");
    }

    decoded_import_instruction decoded;
    if (bytes.empty()) {
        return decoded;
    }

    if (bytes.size() >= 6u && bytes[0] == 0x90u && (bytes[1] == 0xE8u || bytes[1] == 0xE9u)) {
        const auto opcode_va = instruction_va + 1u;
        decoded.kind = bytes[1] == 0xE8u ? import_instruction_kind::direct_call : import_instruction_kind::direct_jump;
        decoded.size = 6u;
        decoded.destination_va = add_i32(opcode_va + 5u, read_i32(bytes, 2u));
        decoded.has_destination = true;
        decoded.patch_as_jmp = bytes[1] == 0xE9u;
        return decoded;
    }

    if (bytes.size() >= 5u && (bytes[0] == 0xE8u || bytes[0] == 0xE9u)) {
        decoded.kind = bytes[0] == 0xE8u ? import_instruction_kind::direct_call : import_instruction_kind::direct_jump;
        decoded.size = bytes.size() >= 6u && is_pad_byte(bytes[5]) ? 6u : 5u;
        decoded.destination_va = add_i32(instruction_va + 5u, read_i32(bytes, 1u));
        decoded.has_destination = true;
        decoded.patch_as_jmp = bytes[0] == 0xE9u;
        return decoded;
    }

    if (bytes.size() >= 6u && bytes[0] == 0xFFu && (bytes[1] == 0x15u || bytes[1] == 0x25u)) {
        decoded.kind = bytes[1] == 0x15u ? import_instruction_kind::indirect_call : import_instruction_kind::indirect_jump;
        decoded.size = 6u;
        decoded.has_pointer_slot = true;
        decoded.patch_as_jmp = bytes[1] == 0x25u;

        if (architecture == arch::x86) {
            decoded.pointer_slot_va = read_u32(bytes, 2u);
        } else {
            decoded.pointer_slot_va = add_i32(instruction_va + 6u, read_i32(bytes, 2u));
        }

        return decoded;
    }

    return decoded;
}

result<import_fix_plan> recover_v2_imports(
    const arch architecture,
    const std::uint64_t text_va,
    const std::span<const std::uint8_t> text_bytes,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const read_memory_fn& read_memory,
    const query_protect_fn& query_protect) {
    const auto pointer_size = pointer_size_for_arch(architecture);
    if (pointer_size.is_error()) {
        return pointer_size.error();
    }

    if (!read_memory || !query_protect) {
        return make_error(status_code::invalid_argument, L"memory callbacks are required");
    }

    import_fix_plan plan;
    std::unordered_set<std::uint64_t> seen_apis;

    const resolver_context context{
        architecture,
        pointer_size.value(),
        &exports,
        &read_memory,
        &query_protect,
    };

    for (std::size_t offset = 0; offset < text_bytes.size(); ++offset) {
        const auto instruction_va = text_va + offset;
        const auto decoded = decode_import_instruction(architecture, instruction_va, text_bytes.subspan(offset));
        if (decoded.is_error()) {
            return decoded.error();
        }

        const auto& instruction = decoded.value();
        if (instruction.kind == import_instruction_kind::none || instruction.size != 6u) {
            continue;
        }

        const auto api_va = resolve_call_site(context, instruction);
        if (!api_va.has_value()) {
            continue;
        }

        if (seen_apis.insert(*api_va).second) {
            plan.iat_entries.push_back(*api_va);
        }

        plan.calls_by_api.push_back({
            *api_va,
            import_call_site{
                instruction_va,
                instruction.size,
                instruction.patch_as_jmp,
            },
        });

        offset += instruction.size - 1u;
    }

    return plan;
}

result<std::vector<std::uint8_t>> build_iat_blob(const import_fix_plan& plan, const std::uint32_t pointer_size) {
    if (!valid_pointer_size(pointer_size)) {
        return make_error(status_code::invalid_argument, L"pointer size must be 4 or 8");
    }

    std::vector<std::uint8_t> blob;
    blob.reserve(plan.iat_entries.size() * pointer_size);

    for (const auto entry : plan.iat_entries) {
        if (pointer_size == 4u && entry > std::numeric_limits<std::uint32_t>::max()) {
            return make_error(status_code::invalid_argument, L"32-bit IAT entry does not fit");
        }

        for (auto index = 0u; index != pointer_size; ++index) {
            blob.push_back(static_cast<std::uint8_t>(entry >> (index * 8u)));
        }
    }

    return blob;
}

result<std::vector<patch_record>> build_call_site_patches(
    const import_fix_plan& plan,
    const std::uint64_t iat_va,
    const std::uint32_t pointer_size,
    const arch architecture) {
    const auto expected_pointer_size = pointer_size_for_arch(architecture);
    if (expected_pointer_size.is_error()) {
        return expected_pointer_size.error();
    }

    if (expected_pointer_size.value() != pointer_size) {
        return make_error(status_code::invalid_argument, L"pointer size does not match architecture");
    }

    std::unordered_map<std::uint64_t, std::size_t> iat_index_by_api;
    for (std::size_t index = 0; index != plan.iat_entries.size(); ++index) {
        iat_index_by_api.emplace(plan.iat_entries[index], index);
    }

    std::vector<patch_record> patches;
    patches.reserve(plan.calls_by_api.size());

    for (const auto& [api_va, site] : plan.calls_by_api) {
        const auto iat_index = iat_index_by_api.find(api_va);
        if (iat_index == iat_index_by_api.end()) {
            return make_error(status_code::invalid_argument, L"call site references API missing from IAT entries");
        }

        if (site.instruction_size != 6u) {
            return make_error(status_code::invalid_argument, L"call site does not have a 6-byte patch slot");
        }

        const auto slot_va = iat_va + (static_cast<std::uint64_t>(iat_index->second) * pointer_size);
        patch_record patch;
        patch.address = site.instruction_va;
        patch.bytes = {0xFFu, site.patch_as_jmp ? 0x25u : 0x15u, 0u, 0u, 0u, 0u};

        if (architecture == arch::x86) {
            if (slot_va > std::numeric_limits<std::uint32_t>::max()) {
                return make_error(status_code::invalid_argument, L"x86 IAT slot address does not fit");
            }

            write_u32(patch.bytes, 2u, static_cast<std::uint32_t>(slot_va));
        } else {
            const auto next_instruction_va = site.instruction_va + 6u;
            const auto displacement =
                static_cast<std::int64_t>(slot_va) - static_cast<std::int64_t>(next_instruction_va);
            if (displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max()) {
                return make_error(status_code::invalid_argument, L"x64 IAT slot is outside rel32 range");
            }

            write_u32(patch.bytes, 2u, static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement)));
        }

        patches.push_back(std::move(patch));
    }

    return patches;
}

result<std::pair<std::uint64_t, std::uint32_t>> find_v3_iat_candidate(
    const std::span<const std::uint8_t> data,
    const std::uint64_t data_va,
    const std::uint32_t pointer_size,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const query_protect_fn& query_protect) {
    if (!valid_pointer_size(pointer_size)) {
        return make_error(status_code::invalid_argument, L"pointer size must be 4 or 8");
    }

    if (!query_protect) {
        return make_error(status_code::invalid_argument, L"query protection callback is required");
    }

    const auto pointer_count = static_cast<std::uint32_t>(data.size() / pointer_size);
    if (pointer_count == 0u) {
        return make_error(status_code::invalid_argument, L"data range does not contain pointers");
    }

    for (auto start_index = 0u; start_index != pointer_count; ++start_index) {
        const auto slots_left = pointer_count - start_index;
        const auto slot_count = (std::min)(slots_left, max_v3_iat_pointers);
        auto non_null = 0u;
        auto export_count = 0u;
        auto rx_count = 0u;

        for (auto slot_index = 0u; slot_index != slot_count; ++slot_index) {
            const auto pointer_offset = static_cast<std::size_t>((start_index + slot_index) * pointer_size);
            auto value = read_pointer_from_span(data, pointer_offset, pointer_size).value_or(0u);
            if (value == 0u) {
                continue;
            }

            if (const auto unwrapped = unwrap_data_pointer(value, data, data_va, pointer_size);
                unwrapped.has_value() && *unwrapped != 0u) {
                value = *unwrapped;
            }

            ++non_null;

            if (exports.find(value) != exports.end()) {
                ++export_count;
            }

            const auto protection = query_protect(value);
            if (protection.is_success() && is_read_execute_protect(protection.value())) {
                ++rx_count;
            }
        }

        if (non_null == 0u) {
            continue;
        }

        const auto required_exports = 1u + ((non_null * 2u) / 100u);
        const auto required_rx = 1u + ((non_null * 75u) / 100u);
        if (export_count >= required_exports && rx_count >= required_rx) {
            const auto start_offset = static_cast<std::uint32_t>(start_index * pointer_size);
            return std::pair<std::uint64_t, std::uint32_t>{
                data_va + start_offset,
                static_cast<std::uint32_t>(data.size()) - start_offset,
            };
        }
    }

    return make_error(status_code::invalid_argument, L"no v3 IAT candidate matched thresholds");
}

} // namespace demida
