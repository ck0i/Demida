#pragma once

#include <demida/common.hpp>

#if defined(__has_include)
#if __has_include(<demida/pe_image.hpp>)
#include <demida/pe_image.hpp>
#define DEMIDA_PROCESS_HAS_PE_IMAGE 1
#endif
#endif

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace demida {

#if !defined(DEMIDA_PROCESS_HAS_PE_IMAGE)
#if !defined(DEMIDA_MEMORY_RANGE_DEFINED)
#define DEMIDA_MEMORY_RANGE_DEFINED 1
struct memory_range {
    std::uint64_t base = 0;
    std::uint64_t size = 0;

    DEMIDA_FORCE_INLINE constexpr bool contains(const std::uint64_t address) const noexcept {
        return size != 0 && address >= base && (address - base) < size;
    }
};
#endif
#endif

struct module_info {
    std::wstring name;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
};

struct module_export {
    std::uint64_t address = 0;
    std::wstring module_name;
    std::string name;
    std::uint16_t ordinal = 0;
    bool has_ordinal = false;
};

struct process_memory_range {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint32_t protect = PAGE_NOACCESS;

    DEMIDA_FORCE_INLINE constexpr bool contains(const std::uint64_t address) const noexcept {
        return size != 0 && address >= base && (address - base) < size;
    }
};

struct oep_trace_options {
    std::wstring target_path;
    std::vector<memory_range> expected_text_ranges;
    std::uint32_t timeout_seconds = 30;
    bool pause_on_oep = false;
    bool verbose = false;
};

struct oep_trace_result {
    std::uint32_t process_id = 0;
    std::wstring main_module_name;
    demida::arch architecture = demida::arch::unknown;
    std::uint32_t pointer_size = 0;
    std::uint32_t page_size = 0;
    std::uint64_t image_base = 0;
    std::uint64_t oep_va = 0;
    bool is_dotnet = false;
};

namespace process_detail {

struct tls_callback_context {
    demida::arch architecture = demida::arch::unknown;
    std::uint64_t image_base = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    std::uint64_t stack_arg_0 = 0;
    std::uint64_t stack_arg_1 = 0;
};

process_memory_range resolve_runtime_range(memory_range range, std::uint64_t image_base) noexcept;
bool contains_runtime_address(
    std::span<const memory_range> ranges,
    std::uint64_t image_base,
    std::uint64_t address) noexcept;
std::optional<std::uint64_t> exact_guarded_export_hit(
    std::uint64_t exception_address,
    std::span<const std::uint64_t> export_addresses) noexcept;
bool is_guardable_export_page_protect(std::uint32_t protect) noexcept;
bool is_trapped_wrapper_entry_fault(
    std::uint32_t exception_code,
    std::uint64_t exception_address,
    std::uint64_t fault_address,
    std::uint64_t wrapper_address) noexcept;
bool is_non_export_wrapper_guard_fault(
    std::uint64_t exception_address,
    std::uint64_t fault_address,
    std::span<const process_memory_range> armed_export_pages) noexcept;
bool is_export_page_data_guard_fault(
    std::uint64_t exception_address,
    std::uint64_t fault_address,
    std::span<const process_memory_range> armed_export_pages) noexcept;
bool looks_like_tls_callback(const tls_callback_context& context) noexcept;
std::wstring target_module_name(std::wstring_view target_path);
bool is_dll_target(std::wstring_view target_path);

} // namespace process_detail

class debugged_process {
public:
    debugged_process() = default;

    debugged_process(const debugged_process&) = delete;
    debugged_process& operator=(const debugged_process&) = delete;

    debugged_process(debugged_process&&) noexcept = default;
    debugged_process& operator=(debugged_process&&) noexcept = default;

    static result<debugged_process> spawn_suspended_or_debugged(const std::wstring& target_path);

    status terminate();
    status continue_from_oep(bool detach_after_continue);

    result<std::vector<std::uint8_t>> read_memory(std::uint64_t address, std::size_t size) const;
    status write_memory(std::uint64_t address, std::span<const std::uint8_t> data) const;
    result<process_memory_range> query_memory(std::uint64_t address) const;
    status protect_memory(
        std::uint64_t address,
        std::size_t size,
        std::uint32_t protect,
        std::uint32_t* old_protect = nullptr) const;
    result<std::uint64_t> allocate_near(std::uint64_t near_address, std::size_t size, std::uint32_t protect) const;
    result<std::vector<module_info>> enumerate_modules() const;
    result<std::uint64_t> find_export(const std::wstring& module_name, const char* export_name) const;
    result<std::vector<module_export>> enumerate_exports(const std::wstring& excluded_module_name = L"") const;

    status set_expected_text_ranges(std::vector<memory_range> ranges);
    status reprotect_expected_ranges() const;
    status restore_expected_ranges() const;
    status allow_expected_page_data_access(std::uint64_t address) const;
    result<std::unordered_map<std::uint64_t, std::uint64_t>> resolve_wrapped_import_targets(
        std::span<const std::uint64_t> wrapper_addresses,
        std::span<const module_export> exports,
        bool verbose = false);
    bool expected_ranges_contain(std::uint64_t address) const noexcept;

    DEMIDA_FORCE_INLINE HANDLE process_handle() const noexcept {
        return process_.get();
    }

    DEMIDA_FORCE_INLINE HANDLE main_thread_handle() const noexcept {
        return main_thread_.get();
    }

    DEMIDA_FORCE_INLINE std::uint32_t process_id() const noexcept {
        return process_id_;
    }

    DEMIDA_FORCE_INLINE std::uint64_t image_base() const noexcept {
        return image_base_;
    }

    DEMIDA_FORCE_INLINE const std::wstring& main_module_name() const noexcept {
        return main_module_name_;
    }

    DEMIDA_FORCE_INLINE demida::arch architecture() const noexcept {
        return architecture_;
    }

    DEMIDA_FORCE_INLINE std::uint32_t pointer_size() const noexcept {
        return pointer_size_;
    }

    DEMIDA_FORCE_INLINE std::uint32_t page_size() const noexcept {
        return page_size_;
    }

private:
    struct protected_range {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::uint32_t original_protect = PAGE_EXECUTE_READ;
    };

    friend result<oep_trace_result> trace_oep(const oep_trace_options& options, debugged_process* out_process);

    debugged_process(
        unique_handle process,
        unique_handle main_thread,
        std::uint32_t process_id,
        std::uint64_t image_base,
        std::wstring main_module_name,
        demida::arch architecture,
        std::uint32_t pointer_size,
        std::uint32_t page_size) noexcept;

    status temporarily_restore_expected_range(std::uint64_t address, std::size_t size) const;

    unique_handle process_;
    unique_handle main_thread_;
    std::uint32_t process_id_ = 0;
    std::uint64_t image_base_ = 0;
    std::wstring main_module_name_;
    demida::arch architecture_ = demida::arch::unknown;
    std::uint32_t pointer_size_ = 0;
    std::uint32_t page_size_ = 0;
    std::vector<memory_range> expected_text_ranges_;
    std::vector<protected_range> protected_ranges_;
    bool has_pending_debug_event_ = false;
    std::uint32_t pending_debug_process_id_ = 0;
    std::uint32_t pending_debug_thread_id_ = 0;
    std::uint32_t pending_debug_continue_status_ = DBG_CONTINUE;
};

result<oep_trace_result> trace_oep(const oep_trace_options& options, debugged_process* out_process);

} // namespace demida
