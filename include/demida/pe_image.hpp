#pragma once

#include <demida/common.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace demida {

struct DEMIDA_TRIVIAL_ABI memory_range {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint32_t characteristics = 0;

    DEMIDA_FORCE_INLINE constexpr bool contains(const std::uint64_t value) const noexcept {
        return value >= base && (value - base) < size;
    }
};

struct pe_section {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_data_offset = 0;
    std::uint32_t raw_data_size = 0;
    std::uint32_t characteristics = 0;
};

struct pe_info {
    arch architecture = arch::unknown;
    bool is_64 = false;
    std::uint64_t image_base = 0;
    std::uint32_t image_size = 0;
    std::uint32_t headers_size = 0;
    std::uint32_t entry_point_rva = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint32_t import_table_rva = 0;
    std::uint32_t import_table_size = 0;
    std::uint32_t resource_table_rva = 0;
    std::uint32_t resource_table_size = 0;
    std::vector<pe_section> sections;
};

class pe_file {
public:
    DEMIDA_FORCE_INLINE const std::vector<std::uint8_t>& bytes() const noexcept {
        return bytes_;
    }

    DEMIDA_FORCE_INLINE const pe_info& info() const noexcept {
        return info_;
    }

    DEMIDA_FORCE_INLINE bool is_64() const noexcept {
        return info_.is_64;
    }

    DEMIDA_FORCE_INLINE std::uint32_t nt_headers_offset() const noexcept {
        return nt_headers_offset_;
    }

    DEMIDA_FORCE_INLINE std::uint32_t optional_header_offset() const noexcept {
        return optional_header_offset_;
    }

    DEMIDA_FORCE_INLINE std::uint32_t section_headers_offset() const noexcept {
        return section_headers_offset_;
    }

    DEMIDA_FORCE_INLINE std::uint16_t size_of_optional_header() const noexcept {
        return size_of_optional_header_;
    }

private:
    friend result<pe_file> load_pe_file(const std::wstring& path);
    friend result<pe_file> parse_pe_file_from_bytes(std::vector<std::uint8_t> bytes);

    std::vector<std::uint8_t> bytes_;
    pe_info info_;
    std::uint32_t nt_headers_offset_ = 0;
    std::uint32_t optional_header_offset_ = 0;
    std::uint32_t section_headers_offset_ = 0;
    std::uint16_t size_of_optional_header_ = 0;
};

result<pe_file> load_pe_file(const std::wstring& path);
result<pe_info> inspect_pe_file(const std::wstring& path);
result<std::uint32_t> detect_packer_version(const pe_file& pe);
std::vector<memory_range> section_ranges(const pe_file& pe);
result<std::vector<memory_range>> probe_text_sections(const pe_file& pe);
result<std::vector<std::uint8_t>> build_dump_image(
    const pe_file& original,
    const std::vector<std::uint8_t>& mapped_image,
    std::uint64_t image_base,
    std::uint64_t oep_va,
    std::uint64_t iat_va,
    std::uint32_t iat_size,
    bool add_new_iat);
status scrub_themida_sections(std::vector<std::uint8_t>& bytes, const pe_file& original);

//
// common.hpp does not currently provide a result<void> specialization.
//
status write_file_bytes(const std::wstring& path, const std::vector<std::uint8_t>& bytes);

} // namespace demida
