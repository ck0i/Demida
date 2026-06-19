#include <demida/pe_image.hpp>

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace demida {
namespace {

status make_error(const status_code code, std::wstring message) {
    return status{code, std::move(message)};
}

status make_last_error(std::wstring message, const DWORD error_code = GetLastError()) {
    message += L" (win32=";
    message += std::to_wstring(error_code);
    message += L")";
    return make_error(status_code::system_error, std::move(message));
}

bool range_fits(const std::size_t size, const std::size_t offset, const std::size_t length) noexcept {
    return offset <= size && length <= (size - offset);
}

std::uint32_t align_up_u32(const std::uint32_t value, const std::uint32_t alignment) noexcept {
    if (alignment == 0u) {
        return value;
    }

    const auto remainder = value % alignment;
    if (remainder == 0u) {
        return value;
    }

    return value + (alignment - remainder);
}

std::size_t align_up_size(const std::size_t value, const std::uint32_t alignment) noexcept {
    if (alignment == 0u) {
        return value;
    }

    const auto size_alignment = static_cast<std::size_t>(alignment);
    const auto remainder = value % size_alignment;
    if (remainder == 0u) {
        return value;
    }

    return value + (size_alignment - remainder);
}

template <typename value_type>
bool read_object(const std::vector<std::uint8_t>& bytes, const std::size_t offset, value_type& value) noexcept {
    if (!range_fits(bytes.size(), offset, sizeof(value_type))) {
        return false;
    }

    std::memcpy(&value, bytes.data() + offset, sizeof(value_type));
    return true;
}

template <typename value_type>
bool write_object(std::vector<std::uint8_t>& bytes, const std::size_t offset, const value_type& value) noexcept {
    if (!range_fits(bytes.size(), offset, sizeof(value_type))) {
        return false;
    }

    std::memcpy(bytes.data() + offset, &value, sizeof(value_type));
    return true;
}

std::string section_name(const BYTE name[IMAGE_SIZEOF_SHORT_NAME]) {
    auto length = std::size_t{0};
    while (length < IMAGE_SIZEOF_SHORT_NAME && name[length] != 0u) {
        ++length;
    }

    return std::string(reinterpret_cast<const char*>(name), length);
}

char lower_ascii(const char ch) noexcept {
    if (ch >= 'A' && ch <= 'Z') {
        return static_cast<char>((ch - 'A') + 'a');
    }

    return ch;
}

std::string lower_ascii(std::string value) {
    for (auto& ch : value) {
        ch = lower_ascii(ch);
    }

    return value;
}

bool equals_no_case(const std::string& left, const std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index) {
        if (lower_ascii(left[index]) != lower_ascii(right[index])) {
            return false;
        }
    }

    return true;
}

bool is_anonymous_section_name(const std::string& name) {
    return std::all_of(name.begin(), name.end(), [](const char ch) {
        return ch == '\0' || ch == ' ';
    });
}

bool is_zero_import_descriptor(const IMAGE_IMPORT_DESCRIPTOR& descriptor) noexcept {
    return descriptor.OriginalFirstThunk == 0u && descriptor.TimeDateStamp == 0u && descriptor.ForwarderChain == 0u &&
           descriptor.Name == 0u && descriptor.FirstThunk == 0u;
}

std::uint64_t section_virtual_span(const pe_section& section) noexcept {
    if (section.virtual_size != 0u) {
        return section.virtual_size;
    }

    return section.raw_data_size;
}

std::optional<std::size_t> rva_to_file_offset(
    const pe_file& pe,
    const std::uint32_t rva,
    const std::size_t length = 1u) {
    const auto& bytes = pe.bytes();
    const auto& info = pe.info();

    if (rva < info.headers_size) {
        const auto offset = static_cast<std::size_t>(rva);
        if (range_fits(bytes.size(), offset, length)) {
            return offset;
        }
    }

    for (const auto& section : info.sections) {
        const auto begin = static_cast<std::uint64_t>(section.virtual_address);
        const auto span = std::max<std::uint64_t>(section_virtual_span(section), section.raw_data_size);
        const auto end = begin + span;
        const auto value = static_cast<std::uint64_t>(rva);

        if (value < begin || value >= end) {
            continue;
        }

        const auto delta = value - begin;
        if (delta > section.raw_data_size) {
            return std::nullopt;
        }

        const auto raw_offset = static_cast<std::uint64_t>(section.raw_data_offset) + delta;
        if (raw_offset > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }

        const auto offset = static_cast<std::size_t>(raw_offset);
        if (!range_fits(bytes.size(), offset, length)) {
            return std::nullopt;
        }

        return offset;
    }

    return std::nullopt;
}

std::optional<std::size_t> rva_to_output_offset(
    const pe_file& original,
    const std::vector<std::uint8_t>& bytes,
    const std::uint32_t rva,
    const std::size_t length = 1u) {
    if (rva < original.info().headers_size) {
        const auto offset = static_cast<std::size_t>(rva);
        if (range_fits(bytes.size(), offset, length)) {
            return offset;
        }
    }

    const auto file_header_offset = static_cast<std::size_t>(original.nt_headers_offset()) + sizeof(DWORD);
    IMAGE_FILE_HEADER file_header{};
    if (!read_object(bytes, file_header_offset, file_header)) {
        return std::nullopt;
    }

    const auto section_headers_offset = static_cast<std::size_t>(original.section_headers_offset());
    for (auto index = 0u; index != file_header.NumberOfSections; ++index) {
        const auto header_offset = section_headers_offset + (index * sizeof(IMAGE_SECTION_HEADER));
        IMAGE_SECTION_HEADER section{};
        if (!read_object(bytes, header_offset, section)) {
            return std::nullopt;
        }

        const auto begin = static_cast<std::uint64_t>(section.VirtualAddress);
        const auto span = std::max<std::uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        const auto value = static_cast<std::uint64_t>(rva);
        if (span == 0u || value < begin || value >= begin + span) {
            continue;
        }

        const auto delta = value - begin;
        if (delta > section.SizeOfRawData || length > section.SizeOfRawData - delta) {
            return std::nullopt;
        }

        const auto raw_offset = static_cast<std::uint64_t>(section.PointerToRawData) + delta;
        if (raw_offset > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }

        const auto offset = static_cast<std::size_t>(raw_offset);
        if (range_fits(bytes.size(), offset, length)) {
            return offset;
        }
    }

    return std::nullopt;
}

std::optional<std::string> read_c_string_rva(
    const pe_file& pe,
    const std::uint32_t rva,
    const std::size_t max_length = 4096u) {
    const auto offset = rva_to_file_offset(pe, rva);
    if (!offset.has_value()) {
        return std::nullopt;
    }

    const auto& bytes = pe.bytes();
    std::string text;
    text.reserve(32u);

    for (auto index = *offset; index < bytes.size() && text.size() < max_length; ++index) {
        const auto ch = static_cast<char>(bytes[index]);
        if (ch == '\0') {
            return text;
        }

        text.push_back(ch);
    }

    return std::nullopt;
}

std::vector<std::string> read_import_names(const pe_file& pe, const IMAGE_IMPORT_DESCRIPTOR& descriptor) {
    std::vector<std::string> names;

    const auto thunk_rva = descriptor.OriginalFirstThunk != 0u ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
    if (thunk_rva == 0u) {
        return names;
    }

    constexpr auto max_imports_per_descriptor = 512u;
    const auto thunk_size = pe.is_64() ? sizeof(std::uint64_t) : sizeof(std::uint32_t);

    for (auto index = 0u; index < max_imports_per_descriptor; ++index) {
        const auto entry_rva = thunk_rva + (index * static_cast<std::uint32_t>(thunk_size));
        const auto entry_offset = rva_to_file_offset(pe, entry_rva, thunk_size);
        if (!entry_offset.has_value()) {
            break;
        }

        std::uint64_t thunk = 0;
        if (pe.is_64()) {
            if (!read_object(pe.bytes(), *entry_offset, thunk)) {
                break;
            }

            if (thunk == 0u) {
                break;
            }

            if ((thunk & IMAGE_ORDINAL_FLAG64) != 0u) {
                continue;
            }
        } else {
            std::uint32_t thunk32 = 0;
            if (!read_object(pe.bytes(), *entry_offset, thunk32)) {
                break;
            }

            if (thunk32 == 0u) {
                break;
            }

            if ((thunk32 & IMAGE_ORDINAL_FLAG32) != 0u) {
                continue;
            }

            thunk = thunk32;
        }

        if (thunk > std::numeric_limits<std::uint32_t>::max() - sizeof(WORD)) {
            continue;
        }

        auto name = read_c_string_rva(pe, static_cast<std::uint32_t>(thunk + sizeof(WORD)));
        if (!name.has_value()) {
            continue;
        }

        names.push_back(lower_ascii(std::move(*name)));
    }

    return names;
}

bool has_function_named(const std::vector<std::string>& names, const std::string_view wanted) {
    return std::any_of(names.begin(), names.end(), [&](const std::string& name) {
        return name == wanted;
    });
}

bool has_function_prefix(const std::vector<std::string>& names, const std::string_view wanted_prefix) {
    return std::any_of(names.begin(), names.end(), [&](const std::string& name) {
        return name.starts_with(wanted_prefix);
    });
}

bool has_themida2_import_signature(const pe_file& pe) {
    const auto& info = pe.info();
    if (info.import_table_rva == 0u) {
        return false;
    }

    auto kernel32_lstrcpy = false;
    auto comctl32_init_common_controls = false;
    auto descriptor_count = 0u;

    constexpr auto max_descriptors = 32u;
    for (; descriptor_count < max_descriptors; ++descriptor_count) {
        const auto descriptor_rva =
            info.import_table_rva + (descriptor_count * static_cast<std::uint32_t>(sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        const auto descriptor_offset = rva_to_file_offset(pe, descriptor_rva, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!descriptor_offset.has_value()) {
            return false;
        }

        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!read_object(pe.bytes(), *descriptor_offset, descriptor)) {
            return false;
        }

        if (is_zero_import_descriptor(descriptor)) {
            break;
        }

        const auto dll_name = read_c_string_rva(pe, descriptor.Name);
        if (!dll_name.has_value()) {
            return false;
        }

        const auto lower_dll = lower_ascii(*dll_name);
        const auto function_names = read_import_names(pe, descriptor);

        if (lower_dll == "kernel32.dll" && has_function_prefix(function_names, "lstrcpy")) {
            kernel32_lstrcpy = true;
        } else if (lower_dll == "comctl32.dll" && has_function_named(function_names, "initcommoncontrols")) {
            comctl32_init_common_controls = true;
        }
    }

    return descriptor_count == 2u && kernel32_lstrcpy && comctl32_init_common_controls;
}

bool section_starts_with(
    const pe_file& pe,
    const pe_section& section,
    const std::uint8_t* const pattern,
    const std::size_t pattern_size) {
    if (section.raw_data_size < pattern_size) {
        return false;
    }

    const auto offset = static_cast<std::size_t>(section.raw_data_offset);
    if (!range_fits(pe.bytes().size(), offset, pattern_size)) {
        return false;
    }

    return std::memcmp(pe.bytes().data() + offset, pattern, pattern_size) == 0;
}

bool has_themida2_section_pattern(const pe_file& pe) {
    static constexpr std::uint8_t pattern_a[] = {0x56u, 0x50u, 0x53u, 0xe8u, 0x01u, 0x00u, 0x00u, 0x00u, 0xccu, 0x58u};
    static constexpr std::uint8_t pattern_b[] = {
        0x83u,
        0xecu,
        0x04u,
        0x50u,
        0x53u,
        0xe8u,
        0x01u,
        0x00u,
        0x00u,
        0x00u,
        0xccu,
        0x58u};

    for (const auto& section : pe.info().sections) {
        if (section_starts_with(pe, section, pattern_a, std::size(pattern_a)) ||
            section_starts_with(pe, section, pattern_b, std::size(pattern_b))) {
            return true;
        }
    }

    return false;
}

} // namespace

result<pe_file> parse_pe_file_from_bytes(std::vector<std::uint8_t> bytes) {
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        return make_error(status_code::invalid_argument, L"file is smaller than an MZ header");
    }

    IMAGE_DOS_HEADER dos{};
    if (!read_object(bytes, 0u, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return make_error(status_code::invalid_argument, L"file does not have an MZ header");
    }

    if (dos.e_lfanew <= 0) {
        return make_error(status_code::invalid_argument, L"PE header offset is invalid");
    }

    const auto nt_offset = static_cast<std::size_t>(dos.e_lfanew);
    if (!range_fits(bytes.size(), nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        return make_error(status_code::invalid_argument, L"PE header is truncated");
    }

    DWORD signature = 0;
    if (!read_object(bytes, nt_offset, signature) || signature != IMAGE_NT_SIGNATURE) {
        return make_error(status_code::invalid_argument, L"file does not have a PE signature");
    }

    IMAGE_FILE_HEADER file_header{};
    const auto file_header_offset = nt_offset + sizeof(DWORD);
    if (!read_object(bytes, file_header_offset, file_header)) {
        return make_error(status_code::invalid_argument, L"PE file header is truncated");
    }

    const auto optional_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    if (!range_fits(bytes.size(), optional_offset, file_header.SizeOfOptionalHeader)) {
        return make_error(status_code::invalid_argument, L"PE optional header is truncated");
    }

    WORD magic = 0;
    if (!read_object(bytes, optional_offset, magic)) {
        return make_error(status_code::invalid_argument, L"PE optional header magic is missing");
    }

    pe_file pe;
    pe.bytes_ = std::move(bytes);
    pe.nt_headers_offset_ = static_cast<std::uint32_t>(nt_offset);
    pe.optional_header_offset_ = static_cast<std::uint32_t>(optional_offset);
    pe.section_headers_offset_ = static_cast<std::uint32_t>(optional_offset + file_header.SizeOfOptionalHeader);
    pe.size_of_optional_header_ = file_header.SizeOfOptionalHeader;
    pe.info_.characteristics = file_header.Characteristics;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            return make_error(status_code::invalid_argument, L"PE32 optional header is too small");
        }

        IMAGE_OPTIONAL_HEADER32 optional{};
        if (!read_object(pe.bytes_, optional_offset, optional)) {
            return make_error(status_code::invalid_argument, L"PE32 optional header is truncated");
        }

        pe.info_.architecture = arch::x86;
        pe.info_.is_64 = false;
        pe.info_.image_base = optional.ImageBase;
        pe.info_.image_size = optional.SizeOfImage;
        pe.info_.headers_size = optional.SizeOfHeaders;
        pe.info_.entry_point_rva = optional.AddressOfEntryPoint;
        pe.info_.section_alignment = optional.SectionAlignment;
        pe.info_.file_alignment = optional.FileAlignment;
        pe.info_.dll_characteristics = optional.DllCharacteristics;

        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            pe.info_.import_table_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            pe.info_.import_table_size = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            pe.info_.resource_table_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            pe.info_.resource_table_size = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            return make_error(status_code::invalid_argument, L"PE32+ optional header is too small");
        }

        IMAGE_OPTIONAL_HEADER64 optional{};
        if (!read_object(pe.bytes_, optional_offset, optional)) {
            return make_error(status_code::invalid_argument, L"PE32+ optional header is truncated");
        }

        pe.info_.architecture = arch::x64;
        pe.info_.is_64 = true;
        pe.info_.image_base = optional.ImageBase;
        pe.info_.image_size = optional.SizeOfImage;
        pe.info_.headers_size = optional.SizeOfHeaders;
        pe.info_.entry_point_rva = optional.AddressOfEntryPoint;
        pe.info_.section_alignment = optional.SectionAlignment;
        pe.info_.file_alignment = optional.FileAlignment;
        pe.info_.dll_characteristics = optional.DllCharacteristics;

        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            pe.info_.import_table_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            pe.info_.import_table_size = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            pe.info_.resource_table_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            pe.info_.resource_table_size = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
    } else {
        return make_error(status_code::unsupported_version, L"PE optional header magic is not PE32 or PE32+");
    }

    const auto section_table_size =
        static_cast<std::size_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (!range_fits(pe.bytes_.size(), pe.section_headers_offset_, section_table_size)) {
        return make_error(status_code::invalid_argument, L"PE section table is truncated");
    }

    pe.info_.sections.reserve(file_header.NumberOfSections);
    for (auto index = 0u; index < file_header.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER header{};
        const auto section_offset = pe.section_headers_offset_ + (index * sizeof(IMAGE_SECTION_HEADER));
        if (!read_object(pe.bytes_, section_offset, header)) {
            return make_error(status_code::invalid_argument, L"PE section header is truncated");
        }

        pe_section section;
        section.name = section_name(header.Name);
        section.virtual_address = header.VirtualAddress;
        section.virtual_size = header.Misc.VirtualSize;
        section.raw_data_offset = header.PointerToRawData;
        section.raw_data_size = header.SizeOfRawData;
        section.characteristics = header.Characteristics;
        pe.info_.sections.push_back(std::move(section));
    }

    return pe;
}

namespace {

std::optional<std::size_t> find_section_index_containing_rva(const pe_file& pe, const std::uint32_t rva) {
    const auto& sections = pe.info().sections;
    for (std::size_t index = 0; index < sections.size(); ++index) {
        const auto& section = sections[index];
        const memory_range range{
            section.virtual_address,
            section_virtual_span(section),
            section.characteristics,
        };

        if (range.contains(rva)) {
            return index;
        }
    }

    return std::nullopt;
}

bool section_has_characteristic(const pe_section& section, const std::uint32_t characteristic) noexcept {
    return (section.characteristics & characteristic) != 0u;
}

std::uint64_t section_end_rva(const pe_section& section) noexcept {
    return static_cast<std::uint64_t>(section.virtual_address) + section_virtual_span(section);
}

bool rva_in_section(const pe_section& section, const std::uint32_t rva, const std::uint32_t size = 1u) noexcept {
    const auto begin = static_cast<std::uint64_t>(section.virtual_address);
    const auto end = section_end_rva(section);
    const auto value = static_cast<std::uint64_t>(rva);
    return value >= begin && size <= end - value;
}

bool rva_in_any_section(
    const pe_file& pe,
    const std::uint32_t rva,
    const std::uint32_t size = 1u,
    const std::uint32_t required_characteristic = 0u) noexcept {
    for (const auto& section : pe.info().sections) {
        if (required_characteristic != 0u && !section_has_characteristic(section, required_characteristic)) {
            continue;
        }

        if (rva_in_section(section, rva, size)) {
            return true;
        }
    }

    return false;
}

bool va_to_rva(
    const std::uint64_t image_base,
    const std::uint64_t va,
    std::uint32_t& rva) noexcept {
    if (va < image_base) {
        return false;
    }

    const auto delta = va - image_base;
    if (delta > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    rva = static_cast<std::uint32_t>(delta);
    return true;
}

bool patch_data_directory(
    std::vector<std::uint8_t>& bytes,
    const pe_file& original,
    const std::uint32_t entry,
    const IMAGE_DATA_DIRECTORY& directory) {
    const auto optional_offset = static_cast<std::size_t>(original.optional_header_offset());
    const auto directory_offset = original.is_64()
        ? optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
        : optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);

    return write_object(bytes, directory_offset + (entry * sizeof(IMAGE_DATA_DIRECTORY)), directory);
}

bool read_mapped_c_string(
    const std::vector<std::uint8_t>& mapped_image,
    const pe_file& original,
    const std::uint32_t rva,
    std::string& value,
    const std::size_t max_length = 260u) {
    if (!rva_in_any_section(original, rva)) {
        return false;
    }

    value.clear();
    for (std::size_t index = 0; index != max_length; ++index) {
        const auto offset = static_cast<std::size_t>(rva) + index;
        if (!range_fits(mapped_image.size(), offset, 1u)) {
            return false;
        }

        const auto ch = static_cast<char>(mapped_image[offset]);
        if (ch == '\0') {
            return !value.empty();
        }

        if (static_cast<unsigned char>(ch) < 0x20u || static_cast<unsigned char>(ch) > 0x7eu) {
            return false;
        }

        value.push_back(ch);
    }

    return false;
}

std::optional<IMAGE_DATA_DIRECTORY> find_export_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image) {
    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto section_offset = static_cast<std::size_t>(section.virtual_address);
        if (!range_fits(mapped_image.size(), section_offset, static_cast<std::size_t>(span))) {
            continue;
        }

        for (std::uint64_t cursor = 0; cursor + sizeof(IMAGE_EXPORT_DIRECTORY) <= span; cursor += sizeof(DWORD)) {
            const auto candidate_rva = section.virtual_address + static_cast<DWORD>(cursor);
            IMAGE_EXPORT_DIRECTORY exports{};
            if (!read_object(mapped_image, section_offset + static_cast<std::size_t>(cursor), exports)) {
                continue;
            }

            if (exports.NumberOfFunctions == 0u ||
                exports.NumberOfNames == 0u ||
                exports.NumberOfNames > exports.NumberOfFunctions ||
                exports.NumberOfFunctions > 0x400u ||
                exports.Base == 0u ||
                exports.Base > 0x10000u ||
                !rva_in_any_section(original, exports.AddressOfFunctions, exports.NumberOfFunctions * sizeof(DWORD)) ||
                !rva_in_any_section(original, exports.AddressOfNames, exports.NumberOfNames * sizeof(DWORD)) ||
                !rva_in_any_section(original, exports.AddressOfNameOrdinals, exports.NumberOfNames * sizeof(WORD))) {
                continue;
            }

            std::string module_name;
            if (!read_mapped_c_string(mapped_image, original, exports.Name, module_name) ||
                module_name.find('.') == std::string::npos) {
                continue;
            }

            auto valid = true;
            auto highest_rva = candidate_rva + static_cast<DWORD>(sizeof(IMAGE_EXPORT_DIRECTORY));
            highest_rva = std::max<DWORD>(highest_rva, exports.Name + static_cast<DWORD>(module_name.size() + 1u));
            highest_rva = std::max<DWORD>(highest_rva, exports.AddressOfFunctions + (exports.NumberOfFunctions * sizeof(DWORD)));
            highest_rva = std::max<DWORD>(highest_rva, exports.AddressOfNames + (exports.NumberOfNames * sizeof(DWORD)));
            highest_rva = std::max<DWORD>(highest_rva, exports.AddressOfNameOrdinals + (exports.NumberOfNames * sizeof(WORD)));

            for (DWORD index = 0; index != exports.NumberOfFunctions; ++index) {
                DWORD function_rva = 0;
                if (!read_object(
                        mapped_image,
                        static_cast<std::size_t>(exports.AddressOfFunctions) + (index * sizeof(DWORD)),
                        function_rva)) {
                    valid = false;
                    break;
                }

                if (function_rva != 0u &&
                    !rva_in_any_section(original, function_rva, 1u, IMAGE_SCN_MEM_EXECUTE) &&
                    !rva_in_section(section, function_rva)) {
                    valid = false;
                    break;
                }
            }

            for (DWORD index = 0; index != exports.NumberOfNames; ++index) {
                DWORD name_rva = 0;
                WORD ordinal = 0;
                if (!read_object(
                        mapped_image,
                        static_cast<std::size_t>(exports.AddressOfNames) + (index * sizeof(DWORD)),
                        name_rva) ||
                    !read_object(
                        mapped_image,
                        static_cast<std::size_t>(exports.AddressOfNameOrdinals) + (index * sizeof(WORD)),
                        ordinal) ||
                    ordinal >= exports.NumberOfFunctions) {
                    valid = false;
                    break;
                }

                std::string export_name;
                if (!read_mapped_c_string(mapped_image, original, name_rva, export_name)) {
                    valid = false;
                    break;
                }

                highest_rva = std::max<DWORD>(highest_rva, name_rva + static_cast<DWORD>(export_name.size() + 1u));
            }

            if (!valid || highest_rva <= candidate_rva || !rva_in_section(section, highest_rva - 1u)) {
                continue;
            }

            const IMAGE_DATA_DIRECTORY candidate{
                .VirtualAddress = candidate_rva,
                .Size = align_up_u32(highest_rva - candidate_rva, sizeof(DWORD)),
            };

            if (!best.has_value() || candidate.Size > best->Size ||
                (candidate.Size == best->Size && candidate.VirtualAddress < best->VirtualAddress)) {
                best = candidate;
            }
        }
    }

    return best;
}

std::optional<IMAGE_DATA_DIRECTORY> find_resource_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image) {
    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(IMAGE_RESOURCE_DIRECTORY) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto rva = section.virtual_address;
        const auto offset = static_cast<std::size_t>(rva);
        IMAGE_RESOURCE_DIRECTORY root{};
        if (!range_fits(mapped_image.size(), offset, sizeof(root)) ||
            !read_object(mapped_image, offset, root)) {
            continue;
        }

        const auto entry_count =
            static_cast<std::uint32_t>(root.NumberOfNamedEntries) + root.NumberOfIdEntries;
        const auto entries_size = static_cast<std::uint64_t>(entry_count) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        if (entry_count == 0u || entry_count > 0x400u ||
            sizeof(IMAGE_RESOURCE_DIRECTORY) + entries_size > span) {
            continue;
        }

        auto valid_entries = true;
        for (std::uint32_t index = 0; index != entry_count; ++index) {
            IMAGE_RESOURCE_DIRECTORY_ENTRY entry{};
            const auto entry_offset = offset + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                                      (index * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            if (!read_object(mapped_image, entry_offset, entry)) {
                valid_entries = false;
                break;
            }

            const auto target_offset = entry.OffsetToData & 0x7fffffffu;
            if (target_offset >= span) {
                valid_entries = false;
                break;
            }
        }

        if (!valid_entries) {
            continue;
        }

        const IMAGE_DATA_DIRECTORY candidate{
            .VirtualAddress = rva,
            .Size = static_cast<DWORD>(std::min<std::uint64_t>(span, std::numeric_limits<DWORD>::max())),
        };

        if (!best.has_value() || candidate.Size > best->Size) {
            best = candidate;
        }
    }

    return best;
}

std::optional<IMAGE_DATA_DIRECTORY> find_exception_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const std::uint32_t oep_rva) {
    if (!original.is_64()) {
        return std::nullopt;
    }

    const auto entry_section_index = find_section_index_containing_rva(original, oep_rva);
    if (!entry_section_index.has_value()) {
        return std::nullopt;
    }

    const auto& entry_section = original.info().sections[*entry_section_index];
    if (!section_has_characteristic(entry_section, IMAGE_SCN_MEM_EXECUTE)) {
        return std::nullopt;
    }

    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};
    auto best_count = 0u;

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto offset = static_cast<std::size_t>(section.virtual_address);
        if (!range_fits(mapped_image.size(), offset, static_cast<std::size_t>(span))) {
            continue;
        }

        auto count = 0u;
        auto last_begin = 0u;
        for (std::uint64_t cursor = 0; cursor + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) <= span;
             cursor += sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
            IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
            if (!read_object(mapped_image, offset + static_cast<std::size_t>(cursor), entry)) {
                break;
            }

            if (entry.BeginAddress == 0u && entry.EndAddress == 0u && entry.UnwindInfoAddress == 0u) {
                break;
            }

            if (entry.BeginAddress < last_begin ||
                !rva_in_section(entry_section, entry.BeginAddress) ||
                !rva_in_section(entry_section, entry.EndAddress == 0u ? 0u : entry.EndAddress - 1u) ||
                entry.BeginAddress >= entry.EndAddress ||
                !rva_in_any_section(original, entry.UnwindInfoAddress)) {
                break;
            }

            last_begin = entry.BeginAddress;
            ++count;
        }

        if (count > best_count) {
            best_count = count;
            best = IMAGE_DATA_DIRECTORY{
                .VirtualAddress = section.virtual_address,
                .Size = static_cast<DWORD>(count * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)),
            };
        }
    }

    if (best_count < 4u) {
        return std::nullopt;
    }

    return best;
}

std::optional<IMAGE_DATA_DIRECTORY> find_tls_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const std::uint64_t image_base) {
    if (!original.is_64()) {
        return std::nullopt;
    }

    const auto image_size = original.info().image_size;
    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(IMAGE_TLS_DIRECTORY64) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto section_offset = static_cast<std::size_t>(section.virtual_address);
        if (!range_fits(mapped_image.size(), section_offset, static_cast<std::size_t>(span))) {
            continue;
        }

        for (std::uint64_t cursor = 0; cursor + sizeof(IMAGE_TLS_DIRECTORY64) <= span; cursor += sizeof(std::uint64_t)) {
            IMAGE_TLS_DIRECTORY64 tls{};
            const auto candidate_rva = section.virtual_address + static_cast<std::uint32_t>(cursor);
            if (!read_object(mapped_image, section_offset + static_cast<std::size_t>(cursor), tls)) {
                continue;
            }

            if (tls.StartAddressOfRawData == 0u ||
                tls.EndAddressOfRawData < tls.StartAddressOfRawData ||
                tls.SizeOfZeroFill > 0x10000u) {
                continue;
            }

            std::uint32_t start_rva = 0;
            std::uint32_t end_rva = 0;
            std::uint32_t index_rva = 0;
            std::uint32_t callbacks_rva = 0;
            if (!va_to_rva(image_base, tls.StartAddressOfRawData, start_rva) ||
                !va_to_rva(image_base, tls.EndAddressOfRawData, end_rva) ||
                !va_to_rva(image_base, tls.AddressOfIndex, index_rva) ||
                !va_to_rva(image_base, tls.AddressOfCallBacks, callbacks_rva) ||
                start_rva >= image_size || end_rva > image_size || index_rva >= image_size ||
                callbacks_rva >= image_size) {
                continue;
            }

            if (!rva_in_any_section(original, start_rva) ||
                !rva_in_any_section(original, end_rva == 0u ? 0u : end_rva - 1u) ||
                !rva_in_any_section(original, index_rva, sizeof(std::uint32_t), IMAGE_SCN_MEM_WRITE) ||
                !rva_in_any_section(original, callbacks_rva, sizeof(std::uint64_t))) {
                continue;
            }

            auto found_callback = false;
            auto found_terminator = false;
            for (auto index = 0u; index != 8u; ++index) {
                std::uint64_t callback_va = 0;
                const auto callback_offset = static_cast<std::size_t>(callbacks_rva) + (index * sizeof(callback_va));
                if (!read_object(mapped_image, callback_offset, callback_va)) {
                    break;
                }

                if (callback_va == 0u) {
                    found_terminator = true;
                    break;
                }

                std::uint32_t callback_rva = 0;
                if (!va_to_rva(image_base, callback_va, callback_rva) ||
                    !rva_in_any_section(original, callback_rva, 1u, IMAGE_SCN_MEM_EXECUTE)) {
                    found_callback = false;
                    break;
                }

                found_callback = true;
            }

            if (!found_callback || !found_terminator) {
                continue;
            }

            const IMAGE_DATA_DIRECTORY candidate{
                .VirtualAddress = candidate_rva,
                .Size = sizeof(IMAGE_TLS_DIRECTORY64),
            };

            if (!best.has_value() || candidate.VirtualAddress < best->VirtualAddress) {
                best = candidate;
            }
        }
    }

    return best;
}

std::optional<IMAGE_DATA_DIRECTORY> find_load_config_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const std::uint64_t image_base) {
    if (!original.is_64()) {
        return std::nullopt;
    }

    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(DWORD) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto section_offset = static_cast<std::size_t>(section.virtual_address);
        if (!range_fits(mapped_image.size(), section_offset, static_cast<std::size_t>(span))) {
            continue;
        }

        for (std::uint64_t cursor = 0; cursor + sizeof(DWORD) <= span; cursor += sizeof(std::uint64_t)) {
            std::uint32_t size = 0;
            if (!read_object(mapped_image, section_offset + static_cast<std::size_t>(cursor), size)) {
                continue;
            }

            if (size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(std::uint64_t) ||
                size > sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) ||
                cursor + size > span) {
                continue;
            }

            IMAGE_LOAD_CONFIG_DIRECTORY64 load_config{};
            if (!read_object(mapped_image, section_offset + static_cast<std::size_t>(cursor), load_config) ||
                load_config.Size != size ||
                load_config.SecurityCookie == 0u) {
                continue;
            }

            std::uint32_t security_cookie_rva = 0;
            if (!va_to_rva(image_base, load_config.SecurityCookie, security_cookie_rva) ||
                !rva_in_any_section(original, security_cookie_rva, sizeof(std::uint64_t), IMAGE_SCN_MEM_WRITE)) {
                continue;
            }

            const IMAGE_DATA_DIRECTORY candidate{
                .VirtualAddress = section.virtual_address + static_cast<DWORD>(cursor),
                .Size = size,
            };

            if (!best.has_value() || candidate.Size > best->Size ||
                (candidate.Size == best->Size && candidate.VirtualAddress < best->VirtualAddress)) {
                best = candidate;
            }
        }
    }

    return best;
}

bool is_supported_debug_type(const DWORD type) noexcept {
    switch (type) {
    case IMAGE_DEBUG_TYPE_COFF:
    case IMAGE_DEBUG_TYPE_CODEVIEW:
    case IMAGE_DEBUG_TYPE_FPO:
    case IMAGE_DEBUG_TYPE_MISC:
    case IMAGE_DEBUG_TYPE_EXCEPTION:
    case IMAGE_DEBUG_TYPE_FIXUP:
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
    case IMAGE_DEBUG_TYPE_BORLAND:
    case IMAGE_DEBUG_TYPE_CLSID:
    case IMAGE_DEBUG_TYPE_VC_FEATURE:
    case IMAGE_DEBUG_TYPE_POGO:
    case IMAGE_DEBUG_TYPE_ILTCG:
    case IMAGE_DEBUG_TYPE_MPX:
    case IMAGE_DEBUG_TYPE_REPRO:
        return true;
    default:
        return false;
    }
}

bool is_valid_debug_directory_entry(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const pe_section& section,
    const IMAGE_DEBUG_DIRECTORY& entry) noexcept {
    if (entry.Characteristics != 0u ||
        entry.Type == IMAGE_DEBUG_TYPE_UNKNOWN ||
        !is_supported_debug_type(entry.Type) ||
        entry.SizeOfData == 0u ||
        entry.SizeOfData > 0x1000000u ||
        entry.AddressOfRawData == 0u ||
        !rva_in_section(section, entry.AddressOfRawData, entry.SizeOfData) ||
        !rva_in_any_section(original, entry.AddressOfRawData, entry.SizeOfData)) {
        return false;
    }

    return range_fits(mapped_image.size(), entry.AddressOfRawData, entry.SizeOfData);
}

std::optional<IMAGE_DATA_DIRECTORY> find_debug_directory_candidate(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image) {
    auto best = std::optional<IMAGE_DATA_DIRECTORY>{};
    auto best_count = 0u;

    for (const auto& section : original.info().sections) {
        const auto span = section_virtual_span(section);
        if (span < sizeof(IMAGE_DEBUG_DIRECTORY) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        const auto section_offset = static_cast<std::size_t>(section.virtual_address);
        if (!range_fits(mapped_image.size(), section_offset, static_cast<std::size_t>(span))) {
            continue;
        }

        for (std::uint64_t cursor = 0; cursor + sizeof(IMAGE_DEBUG_DIRECTORY) <= span; cursor += sizeof(DWORD)) {
            auto count = 0u;

            for (std::uint64_t entry_cursor = cursor; entry_cursor + sizeof(IMAGE_DEBUG_DIRECTORY) <= span;
                 entry_cursor += sizeof(IMAGE_DEBUG_DIRECTORY)) {
                IMAGE_DEBUG_DIRECTORY entry{};
                if (!read_object(mapped_image, section_offset + static_cast<std::size_t>(entry_cursor), entry) ||
                    !is_valid_debug_directory_entry(original, mapped_image, section, entry)) {
                    break;
                }

                ++count;
            }

            if (count == 0u) {
                continue;
            }

            const IMAGE_DATA_DIRECTORY candidate{
                .VirtualAddress = section.virtual_address + static_cast<DWORD>(cursor),
                .Size = count * static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY)),
            };

            if (!best.has_value() || candidate.VirtualAddress < best->VirtualAddress ||
                (candidate.VirtualAddress == best->VirtualAddress && count > best_count)) {
                best = candidate;
                best_count = count;
            }
        }
    }

    return best;
}

bool patch_debug_directory_entries(
    std::vector<std::uint8_t>& bytes,
    const pe_file& original,
    const IMAGE_DATA_DIRECTORY& directory) {
    if (directory.VirtualAddress == 0u ||
        directory.Size == 0u ||
        (directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0u) {
        return false;
    }

    const auto entry_count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (auto index = 0u; index != entry_count; ++index) {
        const auto entry_rva = directory.VirtualAddress + (index * static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY)));
        const auto entry_offset = rva_to_output_offset(original, bytes, entry_rva, sizeof(IMAGE_DEBUG_DIRECTORY));
        if (!entry_offset.has_value()) {
            return false;
        }

        IMAGE_DEBUG_DIRECTORY entry{};
        if (!read_object(bytes, *entry_offset, entry)) {
            return false;
        }

        if (entry.SizeOfData != 0u) {
            const auto payload_offset = rva_to_output_offset(original, bytes, entry.AddressOfRawData, entry.SizeOfData);
            if (!payload_offset.has_value() || *payload_offset > std::numeric_limits<DWORD>::max()) {
                return false;
            }

            entry.PointerToRawData = static_cast<DWORD>(*payload_offset);
        } else {
            entry.PointerToRawData = 0u;
        }

        if (!write_object(bytes, *entry_offset, entry)) {
            return false;
        }
    }

    return true;
}

bool patch_recovered_runtime_directories(
    std::vector<std::uint8_t>& bytes,
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const std::uint64_t image_base,
    const std::uint32_t oep_rva) {
    if (const auto exports = find_export_directory_candidate(original, mapped_image); exports.has_value()) {
        if (!patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_EXPORT, *exports)) {
            return false;
        }
    }

    if (const auto resource = find_resource_directory_candidate(original, mapped_image); resource.has_value()) {
        if (!patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_RESOURCE, *resource)) {
            return false;
        }
    }

    if (const auto exception = find_exception_directory_candidate(original, mapped_image, oep_rva);
        exception.has_value()) {
        if (!patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_EXCEPTION, *exception)) {
            return false;
        }
    }

    if (const auto tls = find_tls_directory_candidate(original, mapped_image, image_base); tls.has_value()) {
        if (!patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_TLS, *tls)) {
            return false;
        }
    }

    if (const auto load_config = find_load_config_directory_candidate(original, mapped_image, image_base);
        load_config.has_value()) {
        if (!patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, *load_config)) {
            return false;
        }
    }

    if (const auto debug = find_debug_directory_candidate(original, mapped_image); debug.has_value()) {
        if (patch_debug_directory_entries(bytes, original, *debug) &&
            !patch_data_directory(bytes, original, IMAGE_DIRECTORY_ENTRY_DEBUG, *debug)) {
            return false;
        }
    }

    return true;
}

bool write_section_name(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t section_headers_offset,
    const std::size_t index,
    const std::string_view name) {
    const auto offset = static_cast<std::size_t>(section_headers_offset) + (index * sizeof(IMAGE_SECTION_HEADER)) +
                        offsetof(IMAGE_SECTION_HEADER, Name);
    if (!range_fits(bytes.size(), offset, IMAGE_SIZEOF_SHORT_NAME)) {
        return false;
    }

    std::array<std::uint8_t, IMAGE_SIZEOF_SHORT_NAME> cleaned_name{};
    const auto copy_length = std::min<std::size_t>(cleaned_name.size(), name.size());
    std::memcpy(cleaned_name.data(), name.data(), copy_length);
    std::memcpy(bytes.data() + offset, cleaned_name.data(), cleaned_name.size());
    return true;
}

bool output_section_has_anonymous_name(
    const std::vector<std::uint8_t>& bytes,
    const std::uint32_t section_headers_offset,
    const std::size_t index) {
    const auto offset = static_cast<std::size_t>(section_headers_offset) + (index * sizeof(IMAGE_SECTION_HEADER));
    IMAGE_SECTION_HEADER section{};
    if (!read_object(bytes, offset, section)) {
        return false;
    }

    return is_anonymous_section_name(section_name(section.Name));
}

bool write_section_name_if_anonymous(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t section_headers_offset,
    const std::size_t index,
    const std::string_view name) {
    if (!output_section_has_anonymous_name(bytes, section_headers_offset, index)) {
        return true;
    }

    return write_section_name(bytes, section_headers_offset, index, name);
}

bool rename_runtime_data_section(
    std::vector<std::uint8_t>& bytes,
    const pe_file& original,
    const IMAGE_DATA_DIRECTORY& directory) {
    if (directory.VirtualAddress == 0u) {
        return true;
    }

    const auto section_index = find_section_index_containing_rva(original, directory.VirtualAddress);
    if (!section_index.has_value()) {
        return true;
    }

    const auto& section = original.info().sections[*section_index];
    if (section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
        section_has_characteristic(section, IMAGE_SCN_MEM_WRITE) ||
        !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
        return true;
    }

    return write_section_name_if_anonymous(bytes, original.section_headers_offset(), *section_index, ".rdata");
}

bool rename_common_data_sections(std::vector<std::uint8_t>& bytes, const pe_file& original) {
    auto data_index = std::optional<std::size_t>{};
    auto data_span = std::uint64_t{0};

    for (std::size_t index = 0; index != original.info().sections.size(); ++index) {
        const auto& section = original.info().sections[index];
        if (section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_WRITE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_DISCARDABLE)) {
            continue;
        }

        const auto span = section_virtual_span(section);
        if (span > data_span) {
            data_index = index;
            data_span = span;
        }
    }

    if (data_index.has_value() &&
        !write_section_name_if_anonymous(bytes, original.section_headers_offset(), *data_index, ".data")) {
        return false;
    }

    const auto fptable_limit = std::max<std::uint32_t>(original.info().section_alignment, 0x1000u);
    for (std::size_t index = 0; index != original.info().sections.size(); ++index) {
        if (data_index.has_value() && index == *data_index) {
            continue;
        }

        const auto& section = original.info().sections[index];
        if (section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_WRITE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_DISCARDABLE) ||
            section_virtual_span(section) > fptable_limit) {
            continue;
        }

        if (!write_section_name_if_anonymous(bytes, original.section_headers_offset(), index, ".fptable")) {
            return false;
        }
    }

    for (std::size_t index = 0; index != original.info().sections.size(); ++index) {
        const auto& section = original.info().sections[index];
        if (!section_has_characteristic(section, IMAGE_SCN_MEM_DISCARDABLE) ||
            section_has_characteristic(section, IMAGE_SCN_MEM_EXECUTE) ||
            !section_has_characteristic(section, IMAGE_SCN_MEM_READ)) {
            continue;
        }

        if (!write_section_name_if_anonymous(bytes, original.section_headers_offset(), index, ".reloc")) {
            return false;
        }
    }

    return true;
}

bool patch_section_disk_layout(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t section_headers_offset,
    const std::size_t index,
    const std::uint32_t virtual_size,
    const std::uint32_t raw_offset,
    const std::uint32_t raw_size) {
    const auto header_offset = static_cast<std::size_t>(section_headers_offset) + (index * sizeof(IMAGE_SECTION_HEADER));
    if (!range_fits(bytes.size(), header_offset, sizeof(IMAGE_SECTION_HEADER))) {
        return false;
    }

    IMAGE_SECTION_HEADER header{};
    if (!read_object(bytes, header_offset, header)) {
        return false;
    }

    header.Misc.VirtualSize = virtual_size;
    header.PointerToRawData = raw_offset;
    header.SizeOfRawData = raw_size;
    return write_object(bytes, header_offset, header);
}

bool section_name_equals(const IMAGE_SECTION_HEADER& section, const std::string_view expected) {
    const auto name = section_name(section.Name);
    return equals_no_case(name, expected);
}

bool is_themida_marker_section(const IMAGE_SECTION_HEADER& section) {
    return section_name_equals(section, ".themida") ||
           section_name_equals(section, ".winlice") ||
           section_name_equals(section, ".boot");
}

bool is_themida_tail_section(const IMAGE_SECTION_HEADER& section) {
    return section_name_equals(section, ".edata") ||
           section_name_equals(section, ".idata") ||
           section_name_equals(section, ".tls") ||
           section_name_equals(section, ".rsrc") ||
           section_name_equals(section, ".reloc") ||
           is_themida_marker_section(section);
}

bool is_themida_pre_marker_directory_section(const IMAGE_SECTION_HEADER& section) {
    return section_name_equals(section, ".edata") ||
           section_name_equals(section, ".idata") ||
           section_name_equals(section, ".tls") ||
           section_name_equals(section, ".rsrc");
}

std::uint64_t output_section_span(const IMAGE_SECTION_HEADER& section) noexcept {
    return std::max<std::uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);
}

bool output_rva_in_section(
    const IMAGE_SECTION_HEADER& section,
    const std::uint32_t rva,
    const std::uint32_t size) noexcept {
    const auto span = output_section_span(section);
    if (span == 0u) {
        return false;
    }

    const auto begin = static_cast<std::uint64_t>(section.VirtualAddress);
    const auto end = begin + span;
    const auto value = static_cast<std::uint64_t>(rva);
    const auto checked_size = std::max<std::uint32_t>(size, 1u);
    return value >= begin && value < end && checked_size <= end - value;
}

bool section_owns_live_data_directory(
    const std::vector<IMAGE_SECTION_HEADER>& sections,
    const std::size_t section_index,
    const IMAGE_DATA_DIRECTORY* directories,
    const std::uint32_t directory_count) noexcept {
    const auto& section = sections[section_index];

    for (auto index = 0u; index != directory_count; ++index) {
        if (index == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            continue;
        }

        const auto& directory = directories[index];
        if (directory.VirtualAddress == 0u) {
            continue;
        }

        if (!output_rva_in_section(section, directory.VirtualAddress, directory.Size)) {
            continue;
        }

        auto later_section_owns_directory = false;
        for (auto later = section_index + 1u; later < sections.size(); ++later) {
            if (output_rva_in_section(sections[later], directory.VirtualAddress, directory.Size)) {
                later_section_owns_directory = true;
                break;
            }
        }

        if (!later_section_owns_directory) {
            return true;
        }
    }

    return false;
}

bool patch_dump_headers(
    std::vector<std::uint8_t>& bytes,
    const pe_file& original,
    const std::uint64_t image_base,
    const std::uint32_t oep_rva) {
    const auto optional_offset = static_cast<std::size_t>(original.optional_header_offset());
    const auto file_characteristics_offset = static_cast<std::size_t>(original.nt_headers_offset()) + sizeof(DWORD) +
                                             offsetof(IMAGE_FILE_HEADER, Characteristics);

    std::uint16_t file_characteristics = 0;
    if (!read_object(bytes, file_characteristics_offset, file_characteristics)) {
        return false;
    }

    file_characteristics = static_cast<std::uint16_t>(file_characteristics | IMAGE_FILE_RELOCS_STRIPPED);
    if (!write_object(bytes, file_characteristics_offset, file_characteristics)) {
        return false;
    }

    IMAGE_DATA_DIRECTORY empty_directory{};

    if (original.is_64()) {
        auto aep_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);
        auto image_base_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase);
        auto checksum_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
        auto dll_characteristics_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, DllCharacteristics);
        auto reloc_directory_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
                                      (IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof(IMAGE_DATA_DIRECTORY));

        std::uint32_t checksum = 0;
        std::uint16_t dll_characteristics = 0;
        if (!write_object(bytes, aep_offset, oep_rva) || !write_object(bytes, image_base_offset, image_base) ||
            !write_object(bytes, checksum_offset, checksum) ||
            !read_object(bytes, dll_characteristics_offset, dll_characteristics) ||
            !write_object(bytes, reloc_directory_offset, empty_directory)) {
            return false;
        }

        dll_characteristics = static_cast<std::uint16_t>(
            dll_characteristics &
            ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
        return write_object(bytes, dll_characteristics_offset, dll_characteristics);
    }

    if (image_base > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    auto aep_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint);
    auto image_base_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase);
    auto checksum_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum);
    auto dll_characteristics_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, DllCharacteristics);
    auto reloc_directory_offset = optional_offset + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
                                  (IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof(IMAGE_DATA_DIRECTORY));

    std::uint32_t checksum = 0;
    const auto image_base32 = static_cast<std::uint32_t>(image_base);
    std::uint16_t dll_characteristics = 0;
    if (!write_object(bytes, aep_offset, oep_rva) || !write_object(bytes, image_base_offset, image_base32) ||
        !write_object(bytes, checksum_offset, checksum) ||
        !read_object(bytes, dll_characteristics_offset, dll_characteristics) ||
        !write_object(bytes, reloc_directory_offset, empty_directory)) {
        return false;
    }

    dll_characteristics = static_cast<std::uint16_t>(
        dll_characteristics & ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
    return write_object(bytes, dll_characteristics_offset, dll_characteristics);
}

std::uint32_t trimmed_mapped_section_size(
    const std::vector<std::uint8_t>& mapped_image,
    const pe_section& section,
    const std::uint64_t copy_size) {
    const auto source_offset = static_cast<std::size_t>(section.virtual_address);
    auto used_size = static_cast<std::size_t>(copy_size);

    while (used_size != 0u && mapped_image[source_offset + used_size - 1u] == 0u) {
        --used_size;
    }

    return static_cast<std::uint32_t>(used_size);
}

} // namespace

result<pe_file> load_pe_file(const std::wstring& path) {
    unique_handle file(CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!file) {
        return make_last_error(L"failed to open PE file");
    }

    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file.get(), &file_size)) {
        return make_last_error(L"failed to query PE file size");
    }

    if (file_size.QuadPart < 0) {
        return make_error(status_code::invalid_argument, L"PE file size is invalid");
    }

    const auto unsigned_size = static_cast<unsigned long long>(file_size.QuadPart);
    if (unsigned_size > static_cast<unsigned long long>(std::vector<std::uint8_t>().max_size())) {
        return make_error(status_code::invalid_argument, L"PE file is too large to map into memory");
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(unsigned_size));
    auto total_read = std::size_t{0};
    while (total_read < bytes.size()) {
        const auto remaining = bytes.size() - total_read;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1u << 20u));
        DWORD bytes_read = 0;
        if (!ReadFile(file.get(), bytes.data() + total_read, chunk, &bytes_read, nullptr)) {
            return make_last_error(L"failed to read PE file");
        }

        if (bytes_read == 0u) {
            return make_error(status_code::system_error, L"PE file ended before the expected size");
        }

        total_read += bytes_read;
    }

    return parse_pe_file_from_bytes(std::move(bytes));
}

result<pe_info> inspect_pe_file(const std::wstring& path) {
    auto loaded = load_pe_file(path);
    if (loaded.is_error()) {
        return loaded.error();
    }

    return std::move(loaded).value().info();
}

result<std::uint32_t> detect_packer_version(const pe_file& pe) {
    for (const auto& section : pe.info().sections) {
        if (equals_no_case(section.name, ".themida") || equals_no_case(section.name, ".winlice")) {
            return 3u;
        }
    }

    if (has_themida2_import_signature(pe) || has_themida2_section_pattern(pe)) {
        return 2u;
    }

    return 0u;
}

std::vector<memory_range> section_ranges(const pe_file& pe) {
    std::vector<memory_range> ranges;
    ranges.reserve(pe.info().sections.size());

    for (const auto& section : pe.info().sections) {
        ranges.push_back(memory_range{
            section.virtual_address,
            section.virtual_size,
            section.characteristics,
        });
    }

    return ranges;
}

result<std::vector<memory_range>> probe_text_sections(const pe_file& pe) {
    std::vector<memory_range> ranges;

    for (const auto& section : pe.info().sections) {
        const auto text_name =
            is_anonymous_section_name(section.name) || equals_no_case(section.name, ".text") ||
            equals_no_case(section.name, ".textbss") || equals_no_case(section.name, ".textidx");

        if (!text_name) {
            break;
        }

        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0u) {
            continue;
        }

        ranges.push_back(memory_range{
            section.virtual_address,
            section.virtual_size,
            section.characteristics,
        });
    }

    return ranges;
}

result<std::vector<std::uint8_t>> build_dump_image(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    const std::uint64_t image_base,
    const std::uint64_t oep_va,
    const std::uint64_t iat_va,
    const std::uint32_t iat_size,
    const bool add_new_iat) {
    (void)iat_va;
    (void)iat_size;
    (void)add_new_iat;

    if (oep_va < image_base) {
        return make_error(status_code::invalid_argument, L"OEP VA is below the image base");
    }

    const auto oep_rva64 = oep_va - image_base;
    if (oep_rva64 > std::numeric_limits<std::uint32_t>::max()) {
        return make_error(status_code::invalid_argument, L"OEP RVA does not fit in a PE header");
    }

    const auto oep_rva = static_cast<std::uint32_t>(oep_rva64);

    std::vector<std::uint8_t> output(original.info().headers_size);

    const auto header_copy_size = std::min<std::size_t>(
        {static_cast<std::size_t>(original.info().headers_size), original.bytes().size(), output.size()});
    if (header_copy_size != 0u) {
        std::memcpy(output.data(), original.bytes().data(), header_copy_size);
    }

    const auto file_alignment = std::max(original.info().file_alignment, 1u);
    const auto section_alignment = std::max(original.info().section_alignment, 1u);

    for (std::size_t section_index = 0; section_index != original.info().sections.size(); ++section_index) {
        const auto& section = original.info().sections[section_index];
        const auto virtual_span = section_virtual_span(section);
        if (virtual_span == 0u) {
            if (!patch_section_disk_layout(output, original.section_headers_offset(), section_index, 0u, 0u, 0u)) {
                return make_error(status_code::invalid_argument, L"failed to patch section layout");
            }
            continue;
        }

        if (virtual_span > std::numeric_limits<std::uint32_t>::max()) {
            return make_error(status_code::invalid_argument, L"section virtual span is too large");
        }

        const auto source_offset = static_cast<std::size_t>(section.virtual_address);
        const auto copy_size = static_cast<std::size_t>(virtual_span);
        if (!range_fits(mapped_image.size(), source_offset, copy_size)) {
            return make_error(status_code::invalid_argument, L"mapped image does not contain a full section");
        }

        const auto used_size = trimmed_mapped_section_size(mapped_image, section, virtual_span);
        const auto raw_size = align_up_u32(used_size, file_alignment);
        const auto raw_offset = raw_size == 0u ? 0u : static_cast<std::uint32_t>(align_up_size(output.size(), file_alignment));
        const auto virtual_size = align_up_u32(static_cast<std::uint32_t>(virtual_span), section_alignment);

        if (raw_size != 0u) {
            output.resize(raw_offset + raw_size);
            std::memcpy(output.data() + raw_offset, mapped_image.data() + source_offset, used_size);
        }

        if (!patch_section_disk_layout(
                output,
                original.section_headers_offset(),
                section_index,
                virtual_size,
                raw_offset,
                raw_size)) {
            return make_error(status_code::invalid_argument, L"failed to patch section layout");
        }
    }

    //
    // Import descriptors are recovered by the import pass; this stage only
    // serializes the current mapped bytes back through the original PE layout.
    //
    if (!patch_dump_headers(output, original, image_base, oep_rva)) {
        return make_error(status_code::invalid_argument, L"failed to patch rebuilt PE headers");
    }

    if (!patch_recovered_runtime_directories(output, original, mapped_image, image_base, oep_rva)) {
        return make_error(status_code::invalid_argument, L"failed to patch recovered runtime directories");
    }

    if (const auto entry_section = find_section_index_containing_rva(original, oep_rva); entry_section.has_value()) {
        if (!write_section_name(output, original.section_headers_offset(), *entry_section, ".text")) {
            return make_error(status_code::invalid_argument, L"failed to rename entrypoint section");
        }
    }

    if (const auto recovered_exception = find_exception_directory_candidate(original, mapped_image, oep_rva);
        recovered_exception.has_value()) {
        if (const auto exception_section =
                find_section_index_containing_rva(original, recovered_exception->VirtualAddress);
            exception_section.has_value()) {
            if (!write_section_name(output, original.section_headers_offset(), *exception_section, ".pdata")) {
                return make_error(status_code::invalid_argument, L"failed to rename exception section");
            }
        }
    }

    auto resource_table_rva = original.info().resource_table_rva;
    if (const auto recovered_resource = find_resource_directory_candidate(original, mapped_image);
        recovered_resource.has_value()) {
        resource_table_rva = recovered_resource->VirtualAddress;
    }

    if (resource_table_rva != 0u) {
        if (const auto resource_section = find_section_index_containing_rva(original, resource_table_rva);
            resource_section.has_value()) {
            if (!write_section_name(output, original.section_headers_offset(), *resource_section, ".rsrc")) {
                return make_error(status_code::invalid_argument, L"failed to rename resource section");
            }
        }
    }

    if (const auto exports = find_export_directory_candidate(original, mapped_image); exports.has_value()) {
        if (!rename_runtime_data_section(output, original, *exports)) {
            return make_error(status_code::invalid_argument, L"failed to rename runtime data section");
        }
    }

    if (const auto tls = find_tls_directory_candidate(original, mapped_image, image_base); tls.has_value()) {
        if (!rename_runtime_data_section(output, original, *tls)) {
            return make_error(status_code::invalid_argument, L"failed to rename runtime data section");
        }
    }

    if (const auto load_config = find_load_config_directory_candidate(original, mapped_image, image_base);
        load_config.has_value()) {
        if (!rename_runtime_data_section(output, original, *load_config)) {
            return make_error(status_code::invalid_argument, L"failed to rename runtime data section");
        }
    }

    if (const auto debug = find_debug_directory_candidate(original, mapped_image); debug.has_value()) {
        if (!rename_runtime_data_section(output, original, *debug)) {
            return make_error(status_code::invalid_argument, L"failed to rename runtime data section");
        }
    }

    if (!rename_common_data_sections(output, original)) {
        return make_error(status_code::invalid_argument, L"failed to rename common data sections");
    }

    return output;
}

status scrub_themida_sections(std::vector<std::uint8_t>& bytes, const pe_file& original) {
    const auto file_header_offset = static_cast<std::size_t>(original.nt_headers_offset()) + sizeof(DWORD);
    IMAGE_FILE_HEADER file_header{};
    if (!read_object(bytes, file_header_offset, file_header)) {
        return make_error(status_code::invalid_argument, L"failed to read PE file header");
    }

    IMAGE_DATA_DIRECTORY directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};
    auto directory_count = 0u;
    auto section_alignment = original.info().section_alignment;
    std::size_t size_of_image_offset = 0;
    if (original.is_64()) {
        IMAGE_OPTIONAL_HEADER64 optional{};
        if (!read_object(bytes, original.optional_header_offset(), optional)) {
            return make_error(status_code::invalid_argument, L"failed to read PE optional header");
        }

        directory_count = std::min<std::uint32_t>(optional.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (auto index = 0u; index != directory_count; ++index) {
            directories[index] = optional.DataDirectory[index];
        }

        section_alignment = optional.SectionAlignment;
        size_of_image_offset = static_cast<std::size_t>(original.optional_header_offset()) +
                               offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage);
    } else {
        IMAGE_OPTIONAL_HEADER32 optional{};
        if (!read_object(bytes, original.optional_header_offset(), optional)) {
            return make_error(status_code::invalid_argument, L"failed to read PE optional header");
        }

        directory_count = std::min<std::uint32_t>(optional.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (auto index = 0u; index != directory_count; ++index) {
            directories[index] = optional.DataDirectory[index];
        }

        section_alignment = optional.SectionAlignment;
        size_of_image_offset = static_cast<std::size_t>(original.optional_header_offset()) +
                               offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage);
    }

    const auto section_headers_offset = static_cast<std::size_t>(original.section_headers_offset());
    std::vector<IMAGE_SECTION_HEADER> sections;
    sections.reserve(file_header.NumberOfSections);
    for (auto index = 0u; index != file_header.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section{};
        if (!read_object(bytes, section_headers_offset + (index * sizeof(section)), section)) {
            return make_error(status_code::invalid_argument, L"failed to read PE section header");
        }

        sections.push_back(section);
    }

    auto marker_index = std::optional<std::size_t>{};
    for (std::size_t index = 0; index != sections.size(); ++index) {
        if (is_themida_marker_section(sections[index])) {
            marker_index = index;
            break;
        }
    }

    if (!marker_index.has_value()) {
        return {};
    }

    auto removable_begin = *marker_index;
    while (removable_begin != 0u && is_themida_pre_marker_directory_section(sections[removable_begin - 1u])) {
        --removable_begin;
    }

    std::vector<IMAGE_SECTION_HEADER> kept;
    kept.reserve(sections.size());
    for (std::size_t index = 0; index != sections.size(); ++index) {
        const auto in_tail = index >= removable_begin && is_themida_tail_section(sections[index]);
        const auto keep = !in_tail || section_owns_live_data_directory(sections, index, directories, directory_count);
        if (keep) {
            kept.push_back(sections[index]);
        }
    }

    if (kept.size() == sections.size()) {
        return {};
    }

    if (kept.size() > std::numeric_limits<WORD>::max()) {
        return make_error(status_code::invalid_argument, L"section count does not fit in PE header");
    }

    file_header.NumberOfSections = static_cast<WORD>(kept.size());
    if (!write_object(bytes, file_header_offset, file_header)) {
        return make_error(status_code::invalid_argument, L"failed to patch PE section count");
    }

    for (std::size_t index = 0; index != kept.size(); ++index) {
        if (!write_object(bytes, section_headers_offset + (index * sizeof(IMAGE_SECTION_HEADER)), kept[index])) {
            return make_error(status_code::invalid_argument, L"failed to compact PE section headers");
        }
    }

    IMAGE_SECTION_HEADER empty_section{};
    for (auto index = kept.size(); index != sections.size(); ++index) {
        if (!write_object(bytes, section_headers_offset + (index * sizeof(IMAGE_SECTION_HEADER)), empty_section)) {
            return make_error(status_code::invalid_argument, L"failed to clear stale PE section header");
        }
    }

    auto image_end = std::uint32_t{0};
    for (const auto& section : kept) {
        const auto span = output_section_span(section);
        if (span == 0u) {
            continue;
        }

        const auto section_end = section.VirtualAddress + static_cast<std::uint32_t>(
            std::min<std::uint64_t>(span, std::numeric_limits<std::uint32_t>::max() - section.VirtualAddress));
        image_end = std::max<std::uint32_t>(image_end, section_end);
    }

    const auto size_of_image = align_up_u32(image_end, section_alignment);
    if (!write_object(bytes, size_of_image_offset, size_of_image)) {
        return make_error(status_code::invalid_argument, L"failed to patch PE image size");
    }

    return {};
}

status write_file_bytes(const std::wstring& path, const std::vector<std::uint8_t>& bytes) {
    unique_handle file(CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0u,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!file) {
        return make_last_error(L"failed to open output file");
    }

    auto total_written = std::size_t{0};
    while (total_written < bytes.size()) {
        const auto remaining = bytes.size() - total_written;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1u << 20u));
        DWORD written = 0;
        if (!WriteFile(file.get(), bytes.data() + total_written, chunk, &written, nullptr)) {
            return make_last_error(L"failed to write output file");
        }

        if (written == 0u) {
            return make_error(status_code::system_error, L"output file write made no progress");
        }

        total_written += written;
    }

    return {};
}

} // namespace demida
