#include <demida/unpacker.hpp>

#include <demida/imports.hpp>
#include <demida/pe_image.hpp>
#include <demida/process.hpp>

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace demida {
namespace {

constexpr auto max_v3_resolve_depth = 16u;

struct import_function {
    std::uint64_t api_va = 0;
    std::wstring module_name;
    std::string name;
    std::uint16_t ordinal = 0;
    bool import_by_ordinal = false;
};

struct import_run {
    std::wstring module_name;
    std::vector<import_function> functions;
    std::uint32_t first_thunk_rva = 0;
    bool owns_iat = false;
};

struct import_section_result {
    std::unordered_map<std::uint64_t, std::uint64_t> iat_va_by_api;
    std::uint32_t import_directory_rva = 0;
    std::uint32_t import_directory_size = 0;
    std::uint32_t iat_directory_rva = 0;
    std::uint32_t iat_directory_size = 0;
};

status make_error(const status_code code, std::wstring message) {
    return status{code, std::move(message)};
}

bool range_fits(const std::size_t size, const std::size_t offset, const std::size_t length) noexcept {
    return offset <= size && length <= (size - offset);
}

std::uint64_t range_end(const std::uint64_t base, const std::uint64_t size) noexcept {
    if (size > (std::numeric_limits<std::uint64_t>::max)() - base) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }

    return base + size;
}

std::uint32_t remaining_iat_size(const std::uint64_t address, const std::uint64_t end) noexcept {
    if (address >= end) {
        return 0u;
    }

    const auto remaining = end - address;
    return static_cast<std::uint32_t>(
        (std::min)(remaining, static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));
}

std::uint32_t align_up_u32(const std::uint32_t value, const std::uint32_t alignment) noexcept {
    if (alignment == 0) {
        return value;
    }

    const auto mask = alignment - 1u;
    return (value + mask) & ~mask;
}

std::size_t align_up_size(const std::size_t value, const std::size_t alignment) noexcept {
    if (alignment == 0) {
        return value;
    }

    const auto mask = alignment - 1u;
    return (value + mask) & ~mask;
}

template <typename value_type>
bool write_object(std::vector<std::uint8_t>& bytes, const std::size_t offset, const value_type& value) noexcept {
    if (!range_fits(bytes.size(), offset, sizeof(value_type))) {
        return false;
    }

    std::memcpy(bytes.data() + offset, &value, sizeof(value_type));
    return true;
}

template <typename value_type>
std::optional<value_type> read_object(const std::vector<std::uint8_t>& bytes, const std::size_t offset) noexcept {
    if (!range_fits(bytes.size(), offset, sizeof(value_type))) {
        return std::nullopt;
    }

    value_type value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value_type));
    return value;
}

void write_pointer(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint64_t value, const std::uint32_t pointer_size) {
    for (auto index = 0u; index != pointer_size; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8u));
    }
}

std::uint64_t read_pointer(std::span<const std::uint8_t> bytes, const std::size_t offset, const std::uint32_t pointer_size) {
    std::uint64_t value = 0;
    for (auto index = 0u; index != pointer_size; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8u);
    }
    return value;
}

std::wstring lower_copy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::string lower_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    return value;
}

std::wstring module_basename(std::wstring value) {
    const auto slash = value.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        value.erase(0u, slash + 1u);
    }

    return value;
}

std::wstring normalized_module_name(std::wstring value) {
    value = lower_copy(module_basename(std::move(value)));
    if (value.find(L'.') == std::wstring::npos) {
        value += L".dll";
    }

    return value;
}

std::uint32_t export_module_preference_rank(const std::wstring& module_name) {
    const auto normalized = normalized_module_name(module_name);
    if (normalized == L"kernel32.dll" || normalized == L"user32.dll" || normalized == L"ole32.dll") {
        return 0u;
    }

    if (normalized == L"kernelbase.dll" || normalized == L"combase.dll") {
        return 2u;
    }

    if (normalized == L"ntdll.dll") {
        return 3u;
    }

    if (normalized.rfind(L"api-", 0u) == 0u || normalized.rfind(L"ext-", 0u) == 0u) {
        return 4u;
    }

    return 1u;
}

bool should_prefer_export_symbol(const export_symbol& candidate, const export_symbol& current) {
    const auto candidate_rank = export_module_preference_rank(candidate.module_name);
    const auto current_rank = export_module_preference_rank(current.module_name);
    if (candidate_rank != current_rank) {
        return candidate_rank < current_rank;
    }

    const auto candidate_module = normalized_module_name(candidate.module_name);
    const auto current_module = normalized_module_name(current.module_name);
    if (candidate_module != current_module) {
        return candidate_module < current_module;
    }

    return lower_ascii(candidate.name) < lower_ascii(current.name);
}

std::string narrow_ascii(const std::wstring& value) {
    std::string out;
    out.reserve(value.size());
    for (const auto ch : value) {
        out.push_back(ch >= 0 && ch <= 0x7f ? static_cast<char>(ch) : '?');
    }
    return out;
}

std::wstring default_output_path(const std::wstring& target_path) {
    const std::filesystem::path target(target_path);
    const auto name = L"unpacked_" + target.filename().wstring();
    return (std::filesystem::current_path() / name).wstring();
}

std::optional<std::size_t> rva_to_output_offset(const pe_file& pe, const std::vector<std::uint8_t>& output, const std::uint32_t rva) {
    if (rva < pe.info().headers_size && range_fits(output.size(), rva, 1)) {
        return rva;
    }

    const auto file_header = read_object<IMAGE_FILE_HEADER>(
        output,
        static_cast<std::size_t>(pe.nt_headers_offset()) + sizeof(DWORD));
    if (!file_header.has_value()) {
        return std::nullopt;
    }

    for (auto index = 0u; index != file_header->NumberOfSections; ++index) {
        const auto section = read_object<IMAGE_SECTION_HEADER>(
            output,
            static_cast<std::size_t>(pe.section_headers_offset()) + (index * sizeof(IMAGE_SECTION_HEADER)));
        if (!section.has_value()) {
            return std::nullopt;
        }

        const auto begin = static_cast<std::uint64_t>(section->VirtualAddress);
        const auto span = std::max<std::uint64_t>(section->Misc.VirtualSize, section->SizeOfRawData);
        const auto value = static_cast<std::uint64_t>(rva);
        if (value < begin || value >= begin + span) {
            continue;
        }

        const auto delta = value - begin;
        if (delta >= section->SizeOfRawData) {
            return std::nullopt;
        }

        const auto offset = static_cast<std::uint64_t>(section->PointerToRawData) + delta;
        if (offset > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }

        const auto file_offset = static_cast<std::size_t>(offset);
        if (!range_fits(output.size(), file_offset, 1)) {
            return std::nullopt;
        }

        return file_offset;
    }

    return std::nullopt;
}

std::uint32_t next_section_rva(const pe_file& pe) {
    auto high = pe.info().image_size;
    for (const auto& section : pe.info().sections) {
        const auto end = section.virtual_address + align_up_u32(
            std::max(section.virtual_size, section.raw_data_size),
            pe.info().section_alignment);
        high = std::max(high, end);
    }

    return align_up_u32(high, pe.info().section_alignment);
}

bool section_name_equals(const pe_section& section, const std::string_view expected) {
    return lower_ascii(section.name) == lower_ascii(std::string(expected));
}

bool is_themida_marker_section(const pe_section& section) {
    return section_name_equals(section, ".themida") ||
           section_name_equals(section, ".winlice") ||
           section_name_equals(section, ".boot");
}

bool is_themida_pre_marker_directory_section(const pe_section& section) {
    return section_name_equals(section, ".edata") ||
           section_name_equals(section, ".idata") ||
           section_name_equals(section, ".tls") ||
           section_name_equals(section, ".rsrc");
}

std::optional<std::uint32_t> recycled_import_section_rva(const pe_file& pe) {
    auto marker_index = std::optional<std::size_t>{};
    for (std::size_t index = 0; index != pe.info().sections.size(); ++index) {
        if (is_themida_marker_section(pe.info().sections[index])) {
            marker_index = index;
            break;
        }
    }

    if (!marker_index.has_value()) {
        return std::nullopt;
    }

    auto recycled_index = *marker_index;
    while (recycled_index != 0u && is_themida_pre_marker_directory_section(pe.info().sections[recycled_index - 1u])) {
        --recycled_index;
    }

    if (recycled_index == *marker_index) {
        return std::nullopt;
    }

    return pe.info().sections[recycled_index].virtual_address;
}

bool patch_number_of_sections(std::vector<std::uint8_t>& output, const pe_file& pe, const std::uint16_t number_of_sections) {
    const auto offset = static_cast<std::size_t>(pe.nt_headers_offset()) + sizeof(DWORD) +
                        offsetof(IMAGE_FILE_HEADER, NumberOfSections);
    return write_object(output, offset, number_of_sections);
}

bool patch_size_of_image(std::vector<std::uint8_t>& output, const pe_file& pe, const std::uint32_t size_of_image) {
    const auto optional = static_cast<std::size_t>(pe.optional_header_offset());
    const auto offset = pe.is_64()
        ? optional + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage)
        : optional + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage);
    return write_object(output, offset, size_of_image);
}

bool patch_data_directory(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const std::uint32_t entry,
    const std::uint32_t rva,
    const std::uint32_t size) {
    const auto optional = static_cast<std::size_t>(pe.optional_header_offset());
    const auto directory_offset = pe.is_64()
        ? optional + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
        : optional + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);

    IMAGE_DATA_DIRECTORY directory{};
    directory.VirtualAddress = rva;
    directory.Size = size;
    return write_object(
        output,
        directory_offset + (entry * sizeof(IMAGE_DATA_DIRECTORY)),
        directory);
}

bool patch_import_directory(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const std::uint32_t rva,
    const std::uint32_t size) {
    return patch_data_directory(output, pe, IMAGE_DIRECTORY_ENTRY_IMPORT, rva, size);
}

bool patch_iat_directory(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const std::uint32_t rva,
    const std::uint32_t size) {
    return patch_data_directory(output, pe, IMAGE_DIRECTORY_ENTRY_IAT, rva, size);
}

result<std::pair<std::uint32_t, std::uint32_t>> compute_iat_directory_span(
    const std::vector<import_run>& runs,
    const std::uint32_t pointer_size) {
    struct thunk_span {
        std::uint32_t begin = 0;
        std::uint32_t end = 0;
        std::uint32_t entries = 0;
    };

    std::vector<thunk_span> spans;
    spans.reserve(runs.size());
    for (const auto& run : runs) {
        if (run.functions.empty() || run.first_thunk_rva == 0u) {
            continue;
        }

        const auto span_size = static_cast<std::uint64_t>(run.functions.size()) * pointer_size;
        const auto end = static_cast<std::uint64_t>(run.first_thunk_rva) + span_size;
        if (span_size > std::numeric_limits<std::uint32_t>::max() ||
            end > std::numeric_limits<std::uint32_t>::max()) {
            return make_error(status_code::invalid_argument, L"IAT directory span does not fit");
        }

        spans.push_back(thunk_span{
            .begin = run.first_thunk_rva,
            .end = static_cast<std::uint32_t>(end),
            .entries = static_cast<std::uint32_t>(run.functions.size()),
        });
    }

    if (spans.empty()) {
        return std::pair<std::uint32_t, std::uint32_t>{0u, 0u};
    }

    std::sort(spans.begin(), spans.end(), [](const thunk_span& left, const thunk_span& right) {
        if (left.begin != right.begin) {
            return left.begin < right.begin;
        }

        return left.end < right.end;
    });

    constexpr auto max_iat_island_gap = 0x40u;
    auto best_begin = spans.front().begin;
    auto best_end = spans.front().end;
    auto best_entries = spans.front().entries;

    auto current_begin = best_begin;
    auto current_end = best_end;
    auto current_entries = best_entries;

    const auto accept_current = [&]() {
        const auto best_size = best_end - best_begin;
        const auto current_size = current_end - current_begin;
        if (current_entries > best_entries ||
            (current_entries == best_entries &&
             (current_size > best_size || (current_size == best_size && current_begin < best_begin)))) {
            best_begin = current_begin;
            best_end = current_end;
            best_entries = current_entries;
        }
    };

    for (std::size_t index = 1; index < spans.size(); ++index) {
        const auto& span = spans[index];
        const auto gap = span.begin > current_end ? span.begin - current_end : 0u;
        if (gap > max_iat_island_gap) {
            accept_current();
            current_begin = span.begin;
            current_end = span.end;
            current_entries = span.entries;
            continue;
        }

        current_end = std::max(current_end, span.end);
        current_entries += span.entries;
    }

    accept_current();
    return std::pair<std::uint32_t, std::uint32_t>{best_begin, best_end - best_begin};
}

status append_section(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const char* name,
    const std::uint32_t virtual_address,
    const std::uint32_t virtual_size,
    const std::vector<std::uint8_t>& raw_data,
    const std::uint32_t characteristics) {
    const auto section_index = pe.info().sections.size();
    const auto header_offset = static_cast<std::size_t>(pe.section_headers_offset()) +
                               (section_index * sizeof(IMAGE_SECTION_HEADER));
    if (!range_fits(output.size(), header_offset, sizeof(IMAGE_SECTION_HEADER)) ||
        header_offset + sizeof(IMAGE_SECTION_HEADER) > pe.info().headers_size) {
        return make_error(status_code::invalid_argument, L"PE headers do not have room for a new section header");
    }

    const auto file_alignment = std::max(pe.info().file_alignment, 1u);
    const auto raw_offset = static_cast<std::uint32_t>(align_up_size(output.size(), file_alignment));
    const auto raw_size = align_up_u32(static_cast<std::uint32_t>(raw_data.size()), file_alignment);

    output.resize(raw_offset + raw_size);
    if (!raw_data.empty()) {
        std::memcpy(output.data() + raw_offset, raw_data.data(), raw_data.size());
    }

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, name, std::min<std::size_t>(std::strlen(name), IMAGE_SIZEOF_SHORT_NAME));
    section.Misc.VirtualSize = virtual_size;
    section.VirtualAddress = virtual_address;
    section.SizeOfRawData = raw_size;
    section.PointerToRawData = raw_offset;
    section.Characteristics = characteristics;

    const auto section_count = static_cast<std::uint16_t>(pe.info().sections.size() + 1u);
    const auto size_of_image = align_up_u32(virtual_address + std::max(virtual_size, raw_size), pe.info().section_alignment);
    if (!write_object(output, header_offset, section) ||
        !patch_number_of_sections(output, pe, section_count) ||
        !patch_size_of_image(output, pe, size_of_image)) {
        return make_error(status_code::invalid_argument, L"failed to patch new section metadata");
    }

    return {};
}

void append_zeroes(std::vector<std::uint8_t>& bytes, const std::size_t count) {
    bytes.insert(bytes.end(), count, 0);
}

std::size_t align_section_bytes(std::vector<std::uint8_t>& bytes, const std::size_t alignment) {
    const auto aligned = align_up_size(bytes.size(), alignment);
    append_zeroes(bytes, aligned - bytes.size());
    return aligned;
}

result<import_section_result> append_import_section(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const std::uint64_t image_base,
    const std::uint32_t pointer_size,
    std::vector<import_run> runs) {
    if (runs.empty()) {
        return import_section_result{};
    }

    if (pointer_size != 4 && pointer_size != 8) {
        return make_error(status_code::invalid_argument, L"invalid import pointer size");
    }

    const auto section_rva = recycled_import_section_rva(pe).value_or(next_section_rva(pe));
    std::vector<std::uint8_t> section_bytes;
    const auto descriptor_count = runs.size();
    append_zeroes(section_bytes, (descriptor_count + 1u) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    struct layout_run {
        std::size_t int_offset = 0;
        std::size_t iat_offset = 0;
        std::size_t dll_name_offset = 0;
        std::vector<std::size_t> hint_name_offsets;
    };

    std::vector<layout_run> layouts(runs.size());
    import_section_result result;
    result.import_directory_rva = section_rva;
    result.import_directory_size = static_cast<std::uint32_t>((descriptor_count + 1u) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    for (std::size_t run_index = 0; run_index < runs.size(); ++run_index) {
        auto& run = runs[run_index];
        auto& layout = layouts[run_index];

        layout.int_offset = align_section_bytes(section_bytes, pointer_size);
        append_zeroes(section_bytes, (run.functions.size() + 1u) * pointer_size);

        if (run.owns_iat) {
            layout.iat_offset = align_section_bytes(section_bytes, pointer_size);
            append_zeroes(section_bytes, (run.functions.size() + 1u) * pointer_size);
            run.first_thunk_rva = section_rva + static_cast<std::uint32_t>(layout.iat_offset);
        }
    }

    for (std::size_t run_index = 0; run_index < runs.size(); ++run_index) {
        auto& run = runs[run_index];
        auto& layout = layouts[run_index];

        layout.hint_name_offsets.reserve(run.functions.size());
        for (const auto& function : run.functions) {
            if (function.import_by_ordinal) {
                layout.hint_name_offsets.push_back(0u);
                continue;
            }

            const auto hint_name_offset = align_section_bytes(section_bytes, 2u);
            layout.hint_name_offsets.push_back(hint_name_offset);
            append_zeroes(section_bytes, sizeof(WORD));
            section_bytes.insert(section_bytes.end(), function.name.begin(), function.name.end());
            section_bytes.push_back(0);
        }

        layout.dll_name_offset = section_bytes.size();
        const auto dll_name = narrow_ascii(run.module_name);
        section_bytes.insert(section_bytes.end(), dll_name.begin(), dll_name.end());
        section_bytes.push_back(0);
    }

    for (std::size_t run_index = 0; run_index < runs.size(); ++run_index) {
        const auto& run = runs[run_index];
        const auto& layout = layouts[run_index];

        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.OriginalFirstThunk = section_rva + static_cast<std::uint32_t>(layout.int_offset);
        descriptor.Name = section_rva + static_cast<std::uint32_t>(layout.dll_name_offset);
        descriptor.FirstThunk = run.first_thunk_rva;
        if (!write_object(section_bytes, run_index * sizeof(IMAGE_IMPORT_DESCRIPTOR), descriptor)) {
            return make_error(status_code::invalid_argument, L"failed to write import descriptor");
        }

        for (std::size_t function_index = 0; function_index < run.functions.size(); ++function_index) {
            const auto& function = run.functions[function_index];
            const auto thunk_value = function.import_by_ordinal
                ? encode_ordinal_import_thunk(function.ordinal, pointer_size)
                : section_rva + static_cast<std::uint32_t>(layout.hint_name_offsets[function_index]);
            write_pointer(section_bytes, layout.int_offset + (function_index * pointer_size), thunk_value, pointer_size);

            if (run.owns_iat) {
                write_pointer(section_bytes, layout.iat_offset + (function_index * pointer_size), thunk_value, pointer_size);
                result.iat_va_by_api[function.api_va] =
                    image_base + run.first_thunk_rva + (function_index * pointer_size);
            }
        }
    }

    auto iat_span = compute_iat_directory_span(runs, pointer_size);
    if (iat_span.is_error()) {
        return iat_span.error();
    }

    result.iat_directory_rva = iat_span.value().first;
    result.iat_directory_size = iat_span.value().second;

    const auto append_status = append_section(
        output,
        pe,
        ".idata",
        section_rva,
        static_cast<std::uint32_t>(section_bytes.size()),
        section_bytes,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    if (append_status.is_error()) {
        return append_status;
    }

    if (!patch_import_directory(output, pe, result.import_directory_rva, result.import_directory_size)) {
        return make_error(status_code::invalid_argument, L"failed to patch import data directory");
    }

    if (!patch_iat_directory(output, pe, result.iat_directory_rva, result.iat_directory_size)) {
        return make_error(status_code::invalid_argument, L"failed to patch IAT data directory");
    }

    return result;
}

std::vector<import_run> build_owned_import_runs(
    const import_fix_plan& plan,
    const std::unordered_map<std::uint64_t, export_symbol>& exports) {
    std::map<std::wstring, import_run> by_module;
    for (const auto api_va : plan.iat_entries) {
        const auto found = exports.find(api_va);
        if (found == exports.end()) {
            continue;
        }

        auto& run = by_module[lower_copy(found->second.module_name)];
        if (run.module_name.empty()) {
            run.module_name = found->second.module_name;
            run.owns_iat = true;
        }

        run.functions.push_back(import_function{
            .api_va = api_va,
            .module_name = found->second.module_name,
            .name = found->second.name,
            .ordinal = found->second.ordinal,
            .import_by_ordinal = found->second.has_ordinal &&
                should_encode_import_by_ordinal(found->second.module_name, found->second.name, found->second.ordinal),
        });
    }

    std::vector<import_run> runs;
    runs.reserve(by_module.size());
    for (auto& [_, run] : by_module) {
        runs.push_back(std::move(run));
    }
    return runs;
}

status patch_call_sites(
    std::vector<std::uint8_t>& output,
    const pe_file& pe,
    const std::uint64_t image_base,
    const arch architecture,
    const import_fix_plan& plan,
    const std::unordered_map<std::uint64_t, std::uint64_t>& iat_va_by_api) {
    for (const auto& [api_va, site] : plan.calls_by_api) {
        const auto slot = iat_va_by_api.find(api_va);
        if (slot == iat_va_by_api.end()) {
            continue;
        }

        if (site.instruction_va < image_base || site.instruction_size != 6u) {
            return make_error(status_code::invalid_argument, L"invalid import call-site patch address");
        }

        const auto rva64 = site.instruction_va - image_base;
        if (rva64 > std::numeric_limits<std::uint32_t>::max()) {
            return make_error(status_code::invalid_argument, L"call-site RVA does not fit");
        }

        const auto offset = rva_to_output_offset(pe, output, static_cast<std::uint32_t>(rva64));
        if (!offset.has_value() || !range_fits(output.size(), *offset, 6u)) {
            return make_error(status_code::invalid_argument, L"call-site patch is outside the dumped image");
        }

        std::uint8_t patch[6] = {0xFFu, site.patch_as_jmp ? 0x25u : 0x15u, 0u, 0u, 0u, 0u};
        if (architecture == arch::x86) {
            if (slot->second > std::numeric_limits<std::uint32_t>::max()) {
                return make_error(status_code::invalid_argument, L"x86 IAT slot VA does not fit");
            }

            const auto value = static_cast<std::uint32_t>(slot->second);
            std::memcpy(patch + 2, &value, sizeof(value));
        } else {
            const auto displacement =
                static_cast<std::int64_t>(slot->second) - static_cast<std::int64_t>(site.instruction_va + 6u);
            if (displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max()) {
                return make_error(status_code::invalid_argument, L"x64 IAT slot is outside rel32 range");
            }

            const auto value = static_cast<std::int32_t>(displacement);
            std::memcpy(patch + 2, &value, sizeof(value));
        }

        std::memcpy(output.data() + *offset, patch, sizeof(patch));
    }

    return {};
}

std::unordered_map<std::uint64_t, export_symbol> make_export_map(const std::vector<module_export>& exports) {
    std::unordered_map<std::uint64_t, export_symbol> out;
    out.reserve(exports.size());
    for (const auto& symbol : exports) {
        const export_symbol export_entry{
            .address = symbol.address,
            .module_name = symbol.module_name,
            .name = symbol.name,
            .ordinal = symbol.ordinal,
            .has_ordinal = symbol.has_ordinal,
        };

        auto existing = out.find(symbol.address);
        if (existing == out.end() || should_prefer_export_symbol(export_entry, existing->second)) {
            out[symbol.address] = export_entry;
        }
    }
    return out;
}

bool is_executable_protect(const std::uint32_t protect) noexcept {
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
        return false;
    }

    switch (protect & 0xffu) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

std::optional<std::uint64_t> resolve_import_target(
    const arch architecture,
    const std::uint32_t pointer_size,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const read_memory_fn& read_memory,
    const query_protect_fn& query_protect,
    const std::uint64_t target,
    std::unordered_set<std::uint64_t>& visited,
    const std::uint32_t depth) {
    if (target == 0 || depth >= max_v3_resolve_depth) {
        return std::nullopt;
    }

    if (exports.find(target) != exports.end()) {
        return target;
    }

    if (!visited.insert(target).second) {
        return std::nullopt;
    }

    const auto protect = query_protect(target);
    if (protect.is_error() || !is_executable_protect(protect.value())) {
        return std::nullopt;
    }

    const auto bytes = read_memory(target, 16u);
    if (bytes.is_error() || bytes.value().empty()) {
        return std::nullopt;
    }

    const auto decoded = decode_import_instruction(architecture, target, bytes.value());
    if (decoded.is_error() || decoded.value().kind == import_instruction_kind::none) {
        return std::nullopt;
    }

    if (decoded.value().has_destination) {
        return resolve_import_target(
            architecture,
            pointer_size,
            exports,
            read_memory,
            query_protect,
            decoded.value().destination_va,
            visited,
            depth + 1u);
    }

    if (!decoded.value().has_pointer_slot) {
        return std::nullopt;
    }

    const auto pointer_bytes = read_memory(decoded.value().pointer_slot_va, pointer_size);
    if (pointer_bytes.is_error() || pointer_bytes.value().size() < pointer_size) {
        return std::nullopt;
    }

    return resolve_import_target(
        architecture,
        pointer_size,
        exports,
        read_memory,
        query_protect,
        read_pointer(pointer_bytes.value(), 0, pointer_size),
        visited,
        depth + 1u);
}

std::optional<std::uint64_t> resolve_import_target(
    const arch architecture,
    const std::uint32_t pointer_size,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const read_memory_fn& read_memory,
    const query_protect_fn& query_protect,
    const std::uint64_t target) {
    std::unordered_set<std::uint64_t> visited;
    return resolve_import_target(architecture, pointer_size, exports, read_memory, query_protect, target, visited, 0u);
}

result<std::pair<std::uint64_t, std::uint32_t>> find_v3_iat(
    const pe_file& original,
    const debugged_process& process,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const query_protect_fn& query_protect) {
    const auto page_size = process.page_size();
    for (const auto& section : section_ranges(original)) {
        if (section.size == 0) {
            continue;
        }

        const auto va = process.image_base() + section.base;
        const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(section.size, page_size));
        auto bytes = process.read_memory(va, size);
        if (bytes.is_error()) {
            continue;
        }

        auto candidate = find_v3_iat_candidate(bytes.value(), va, process.pointer_size(), exports, query_protect);
        if (candidate.is_success()) {
            return std::pair<std::uint64_t, std::uint32_t>{
                candidate.value().first,
                remaining_iat_size(candidate.value().first, range_end(va, section.size)),
            };
        }
    }

    auto cursor = process.image_base();
    const auto image_end = process.image_base() + original.info().image_size;
    while (cursor < image_end) {
        auto region = process.query_memory(cursor);
        if (region.is_error() || region.value().size == 0) {
            break;
        }

        for (auto page = 0u; page != 4u; ++page) {
            const auto page_va = region.value().base + (static_cast<std::uint64_t>(page) * page_size);
            if (page_va >= region.value().base + region.value().size || page_va >= image_end) {
                break;
            }

            const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(page_size, image_end - page_va));
            auto bytes = process.read_memory(page_va, size);
            if (bytes.is_error()) {
                continue;
            }

            auto candidate = find_v3_iat_candidate(bytes.value(), page_va, process.pointer_size(), exports, query_protect);
            if (candidate.is_success()) {
                return std::pair<std::uint64_t, std::uint32_t>{
                    candidate.value().first,
                    remaining_iat_size(
                        candidate.value().first,
                        (std::min)(range_end(region.value().base, region.value().size), image_end)),
                };
            }
        }

        cursor = region.value().base + region.value().size;
    }

    return make_error(status_code::invalid_argument, L"v3 IAT was not found");
}

result<std::vector<import_run>> recover_v3_import_runs(
    const pe_file& original,
    debugged_process& process,
    std::span<const module_export> remote_exports,
    const std::unordered_map<std::uint64_t, export_symbol>& exports,
    const read_memory_fn& read_memory,
    const query_protect_fn& query_protect,
    std::uint32_t& import_count,
    const bool verbose) {
    auto iat = find_v3_iat(original, process, exports, query_protect);
    if (iat.is_error()) {
        return iat.error();
    }

    auto bytes = process.read_memory(iat.value().first, iat.value().second);
    if (bytes.is_error()) {
        return bytes.error();
    }

    std::vector<import_run> runs;
    import_run current;
    import_count = 0;

    const auto pointer_size = process.pointer_size();
    const auto pointer_count = bytes.value().size() / pointer_size;

    std::vector<std::uint64_t> wrapper_entries;
    wrapper_entries.reserve(pointer_count);
    for (std::size_t index = 0; index < pointer_count; ++index) {
        const auto value = read_pointer(bytes.value(), index * pointer_size, pointer_size);
        if (value >= process.image_base() && value < process.image_base() + original.info().image_size &&
            exports.find(value) == exports.end()) {
            wrapper_entries.push_back(value);
        }
    }

    auto wrapper_resolutions = process.resolve_wrapped_import_targets(wrapper_entries, remote_exports, verbose);
    if (wrapper_resolutions.is_error()) {
        return wrapper_resolutions.error();
    }

    if (verbose) {
        std::wcerr << L"trace: v3 iat=0x" << std::hex << iat.value().first << L" size=0x" << iat.value().second
                   << std::dec << L" wrappers=" << wrapper_entries.size() << L" resolved_wrappers="
                   << wrapper_resolutions.value().size() << L"\n";
    }

    for (std::size_t index = 0; index < pointer_count; ++index) {
        const auto slot_va = iat.value().first + (index * pointer_size);
        const auto value = read_pointer(bytes.value(), index * pointer_size, pointer_size);

        auto resolved = std::optional<std::uint64_t>{};
        if (exports.find(value) != exports.end()) {
            resolved = value;
        } else if (value >= process.image_base() && value < process.image_base() + original.info().image_size) {
            const auto runtime_resolved = wrapper_resolutions.value().find(value);
            if (runtime_resolved != wrapper_resolutions.value().end()) {
                resolved = runtime_resolved->second;
            } else {
                resolved = resolve_import_target(
                    process.architecture(),
                    pointer_size,
                    exports,
                    read_memory,
                    query_protect,
                    value);
            }
        }

        if (!resolved.has_value()) {
            if (!current.functions.empty()) {
                runs.push_back(std::move(current));
                current = {};
            }
            continue;
        }

        const auto found = exports.find(*resolved);
        if (found == exports.end()) {
            if (!current.functions.empty()) {
                runs.push_back(std::move(current));
                current = {};
            }
            continue;
        }

        if (current.functions.empty() || lower_copy(current.module_name) != lower_copy(found->second.module_name) ||
            current.first_thunk_rva + (current.functions.size() * pointer_size) != slot_va - process.image_base()) {
            if (!current.functions.empty()) {
                runs.push_back(std::move(current));
            }

            current = import_run{
                .module_name = found->second.module_name,
                .first_thunk_rva = static_cast<std::uint32_t>(slot_va - process.image_base()),
                .owns_iat = false,
            };
        }

        current.functions.push_back(import_function{
            .api_va = *resolved,
            .module_name = found->second.module_name,
            .name = found->second.name,
            .ordinal = found->second.ordinal,
            .import_by_ordinal = found->second.has_ordinal &&
                should_encode_import_by_ordinal(found->second.module_name, found->second.name, found->second.ordinal),
        });
        ++import_count;
    }

    if (!current.functions.empty()) {
        runs.push_back(std::move(current));
    }

    if (runs.empty()) {
        return make_error(status_code::invalid_argument, L"v3 IAT candidate did not resolve any imports");
    }

    auto iat_span = compute_iat_directory_span(runs, pointer_size);
    if (iat_span.is_error()) {
        return iat_span.error();
    }

    const auto iat_begin = iat_span.value().first;
    const auto iat_end = iat_begin + iat_span.value().second;
    std::erase_if(runs, [pointer_size, iat_begin, iat_end](const import_run& run) {
        const auto begin = run.first_thunk_rva;
        const auto end = begin + static_cast<std::uint32_t>(run.functions.size() * pointer_size);
        return begin < iat_begin || end > iat_end;
    });

    import_count = 0u;
    for (const auto& run : runs) {
        import_count += static_cast<std::uint32_t>(run.functions.size());
    }

    if (runs.empty()) {
        return make_error(status_code::invalid_argument, L"v3 IAT island did not keep any resolved imports");
    }

    return runs;
}

memory_range pick_oep_text_range(std::span<const memory_range> ranges, const std::uint64_t image_base, const std::uint64_t oep_va) {
    const auto oep_rva = oep_va >= image_base ? oep_va - image_base : oep_va;
    for (const auto& range : ranges) {
        if (range.contains(oep_rva)) {
            return range;
        }
    }

    return ranges.front();
}

} // namespace

result<unpack_result> run_unpacker(const cli_options& options) {
    auto original = load_pe_file(options.target_path);
    if (original.is_error()) {
        return original.error();
    }

    auto target_version = options.target_version.value_or(0u);
    if (target_version == 0u) {
        auto detected = detect_packer_version(original.value());
        if (detected.is_error()) {
            return detected.error();
        }
        target_version = detected.value();
    }

    if (target_version != 2u && target_version != 3u) {
        return make_error(status_code::unsupported_version, L"failed to detect a supported Themida/WinLicense version");
    }

    auto text_ranges = probe_text_sections(original.value());
    if (text_ranges.is_error()) {
        return text_ranges.error();
    }

    if (text_ranges.value().empty()) {
        return make_error(status_code::invalid_argument, L"failed to locate an executable original text section");
    }

    debugged_process process;
    auto traced = trace_oep(oep_trace_options{
        .target_path = options.target_path,
        .expected_text_ranges = text_ranges.value(),
        .timeout_seconds = options.timeout_seconds,
        .pause_on_oep = options.pause_on_oep,
        .verbose = options.verbose,
    }, &process);
    if (traced.is_error()) {
        return traced.error();
    }

    if (options.pause_on_oep) {
        std::wcerr << L"OEP reached. Press ENTER to dump.";
        std::wstring ignored;
        std::getline(std::wcin, ignored);
    }

    auto effective_oep_va = traced.value().oep_va;
    if (options.force_oep.has_value()) {
        effective_oep_va = traced.value().image_base + *options.force_oep;
    }

    const auto output_path = options.output_path.empty() ? default_output_path(options.target_path) : options.output_path;
    const auto read_memory = read_memory_fn([&](const std::uint64_t address, const std::size_t size) {
        return process.read_memory(address, size);
    });
    const auto query_protect = query_protect_fn([&](const std::uint64_t address) {
        auto range = process.query_memory(address);
        if (range.is_error()) {
            return result<std::uint32_t>(range.error());
        }
        return result<std::uint32_t>(range.value().protect);
    });

    auto mapped_image = process.read_memory(traced.value().image_base, original.value().info().image_size);
    if (mapped_image.is_error()) {
        process.terminate();
        return mapped_image.error();
    }

    auto output = build_dump_image(
        original.value(),
        mapped_image.value(),
        traced.value().image_base,
        traced.value().is_dotnet ? traced.value().image_base : effective_oep_va,
        0,
        0,
        false);
    if (output.is_error()) {
        process.terminate();
        return output.error();
    }

    auto import_count = 0u;
    std::optional<status> import_failure;
    const auto note_import_failure = [&](status failure) {
        if (options.verbose) {
            std::wcerr << L"trace: import recovery failed, continuing with raw dump: " << failure.message << L"\n";
        }

        import_failure = std::move(failure);
    };

    if (!traced.value().is_dotnet && !options.no_imports) {
        auto remote_exports = process.enumerate_exports(traced.value().main_module_name);
        if (remote_exports.is_error()) {
            if (options.strict_imports) {
                process.terminate();
                return remote_exports.error();
            }

            note_import_failure(remote_exports.error());
        } else {
            auto exports = make_export_map(remote_exports.value());
            if (target_version == 2u) {
                const auto text_range = pick_oep_text_range(text_ranges.value(), traced.value().image_base, effective_oep_va);
                auto text_bytes = process.read_memory(
                    traced.value().image_base + text_range.base,
                    static_cast<std::size_t>(text_range.size));
                if (text_bytes.is_error()) {
                    if (options.strict_imports) {
                        process.terminate();
                        return text_bytes.error();
                    }

                    note_import_failure(text_bytes.error());
                } else {
                    auto plan = recover_v2_imports(
                        traced.value().architecture,
                        traced.value().image_base + text_range.base,
                        text_bytes.value(),
                        exports,
                        read_memory,
                        query_protect);
                    if (plan.is_error()) {
                        if (options.strict_imports) {
                            process.terminate();
                            return plan.error();
                        }

                        note_import_failure(plan.error());
                    } else {
                        auto import_output = output.value();
                        auto import_section = append_import_section(
                            import_output,
                            original.value(),
                            traced.value().image_base,
                            traced.value().pointer_size,
                            build_owned_import_runs(plan.value(), exports));
                        if (import_section.is_error()) {
                            if (options.strict_imports) {
                                process.terminate();
                                return import_section.error();
                            }

                            note_import_failure(import_section.error());
                        } else {
                            const auto patch_status = patch_call_sites(
                                import_output,
                                original.value(),
                                traced.value().image_base,
                                traced.value().architecture,
                                plan.value(),
                                import_section.value().iat_va_by_api);
                            if (patch_status.is_error()) {
                                if (options.strict_imports) {
                                    process.terminate();
                                    return patch_status;
                                }

                                note_import_failure(patch_status);
                            } else {
                                import_count = static_cast<std::uint32_t>(plan.value().iat_entries.size());
                                output.value() = std::move(import_output);
                            }
                        }
                    }
                }
            } else {
                auto runs = recover_v3_import_runs(
                    original.value(),
                    process,
                    remote_exports.value(),
                    exports,
                    read_memory,
                    query_protect,
                    import_count,
                    options.verbose);
                if (runs.is_error()) {
                    if (options.strict_imports) {
                        process.terminate();
                        return runs.error();
                    }

                    import_count = 0;
                    note_import_failure(runs.error());
                } else {
                    auto import_output = output.value();
                    auto import_section = append_import_section(
                        import_output,
                        original.value(),
                        traced.value().image_base,
                        traced.value().pointer_size,
                        std::move(runs.value()));
                    if (import_section.is_error()) {
                        if (options.strict_imports) {
                            process.terminate();
                            return import_section.error();
                        }

                        import_count = 0;
                        note_import_failure(import_section.error());
                    } else {
                        output.value() = std::move(import_output);
                    }
                }
            }
        }
    }

    const auto scrub_status = scrub_themida_sections(output.value(), original.value());
    if (scrub_status.is_error()) {
        process.terminate();
        return scrub_status;
    }

    const auto write_status = write_file_bytes(output_path, output.value());
    if (write_status.is_error()) {
        process.terminate();
        return write_status;
    }

    process.terminate();
    return unpack_result{
        .output_path = output_path,
        .target_version = target_version,
        .image_base = traced.value().image_base,
        .oep_va = effective_oep_va,
        .import_count = import_count,
        .is_dotnet = traced.value().is_dotnet,
        .import_recovery_failed = import_failure.has_value(),
        .import_error_message = import_failure.has_value() ? import_failure->message : std::wstring{},
    };
}

} // namespace demida
