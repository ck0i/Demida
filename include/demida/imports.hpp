#pragma once

#include <demida/common.hpp>

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace demida {

struct export_symbol {
    std::uint64_t address = 0;
    std::wstring module_name;
    std::string name;
    std::uint16_t ordinal = 0;
    bool has_ordinal = false;
};

struct import_call_site {
    std::uint64_t instruction_va = 0;
    std::uint8_t instruction_size = 0;
    bool patch_as_jmp = false;
};

struct import_fix_plan {
    std::vector<std::uint64_t> iat_entries;
    std::vector<std::pair<std::uint64_t, import_call_site>> calls_by_api;
};

struct patch_record {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> bytes;
};

enum class import_instruction_kind : std::uint8_t {
    none = 0,
    direct_call = 1,
    direct_jump = 2,
    indirect_call = 3,
    indirect_jump = 4,
};

struct decoded_import_instruction {
    import_instruction_kind kind = import_instruction_kind::none;
    std::uint8_t size = 0;
    std::uint64_t destination_va = 0;
    std::uint64_t pointer_slot_va = 0;
    bool has_destination = false;
    bool has_pointer_slot = false;
    bool patch_as_jmp = false;
};

using read_memory_fn = std::function<result<std::vector<std::uint8_t>>(std::uint64_t, std::size_t)>;
using query_protect_fn = std::function<result<std::uint32_t>(std::uint64_t)>;

result<decoded_import_instruction> decode_import_instruction(
    arch architecture,
    std::uint64_t instruction_va,
    std::span<const std::uint8_t> bytes);

result<import_fix_plan> recover_v2_imports(
    arch architecture,
    std::uint64_t text_va,
    std::span<const std::uint8_t> text_bytes,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const read_memory_fn& read_memory,
    const query_protect_fn& query_protect);

result<std::vector<std::uint8_t>> build_iat_blob(const import_fix_plan& plan, std::uint32_t pointer_size);

result<std::vector<patch_record>> build_call_site_patches(
    const import_fix_plan& plan,
    std::uint64_t iat_va,
    std::uint32_t pointer_size,
    arch architecture);

result<std::pair<std::uint64_t, std::uint32_t>> find_v3_iat_candidate(
    std::span<const std::uint8_t> data,
    std::uint64_t data_va,
    std::uint32_t pointer_size,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const query_protect_fn& query_protect);

bool should_encode_import_by_ordinal(
    std::wstring_view module_name,
    std::string_view name,
    std::uint16_t ordinal) noexcept;
std::uint64_t encode_ordinal_import_thunk(std::uint16_t ordinal, std::uint32_t pointer_size) noexcept;

} // namespace demida
