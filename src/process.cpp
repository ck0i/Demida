#include <demida/process.hpp>

#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace demida {
namespace {

constexpr auto trap_flag = 0x100u;
constexpr auto max_remote_string = 4096u;
constexpr auto status_guard_page_violation = 0x80000001u;
constexpr auto wrapper_magic_return = 0xDEADBEEFull;
constexpr auto wrapper_resolve_stack_pages = 4u;
constexpr auto wrapper_resolve_timeout_ms = 1500u;
constexpr auto wrapper_resolve_max_events = 512u;

struct launch_spec {
    std::wstring application_path;
    std::wstring command_line;
    std::wstring main_module_name;
    bool dll_target = false;
};

struct normalized_context {
    demida::arch architecture = demida::arch::unknown;
    std::uint64_t instruction_pointer = 0;
    std::uint64_t stack_pointer = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    CONTEXT native_context{};
#if defined(_M_X64)
    WOW64_CONTEXT wow64_context{};
    bool wow64 = false;
#endif
};

struct process_architecture_info {
    demida::arch architecture = demida::arch::unknown;
    std::uint32_t pointer_size = 0;
};

status make_error(const status_code code, std::wstring message) {
    return status{code, std::move(message)};
}

std::wstring trim_system_message(std::wstring message) {
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }

    return message;
}

status make_win32_error(const std::wstring_view prefix, const DWORD error = GetLastError()) {
    LPWSTR buffer = nullptr;
    const auto length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message(prefix);
    message += L": ";

    if (length != 0 && buffer != nullptr) {
        message += trim_system_message(buffer);
        LocalFree(buffer);
    } else {
        message += L"Win32 error ";
        message += std::to_wstring(error);
    }

    return make_error(status_code::system_error, std::move(message));
}

DEMIDA_FORCE_INLINE bool add_overflows(const std::uint64_t value, const std::uint64_t addend) noexcept {
    return value > (std::numeric_limits<std::uint64_t>::max)() - addend;
}

std::uint64_t saturating_end(const std::uint64_t base, const std::uint64_t size) noexcept {
    if (add_overflows(base, size)) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }

    return base + size;
}

bool ranges_overlap(
    const std::uint64_t left_base,
    const std::uint64_t left_size,
    const std::uint64_t right_base,
    const std::uint64_t right_size) noexcept {
    if (left_size == 0 || right_size == 0) {
        return false;
    }

    const auto left_end = saturating_end(left_base, left_size);
    const auto right_end = saturating_end(right_base, right_size);
    return left_base < right_end && right_base < left_end;
}

std::wstring lower_copy(const std::wstring_view text) {
    std::wstring lowered(text);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](const wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return lowered;
}

bool iequals(const std::wstring_view left, const std::wstring_view right) {
    return lower_copy(left) == lower_copy(right);
}

std::string lower_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    return value;
}

std::wstring widen_ascii(std::string_view text);

std::wstring normalized_module_name(std::wstring module_name) {
    module_name = lower_copy(process_detail::target_module_name(module_name));
    if (module_name.find(L'.') == std::wstring::npos) {
        module_name += L".dll";
    }

    return module_name;
}

std::wstring export_lookup_key(const std::wstring& module_name, const std::string& export_name) {
    auto key = normalized_module_name(module_name);
    key.push_back(L'!');
    key += widen_ascii(export_name);
    return key;
}

bool is_api_set_module_name(const std::wstring& module_name) {
    const auto normalized = normalized_module_name(module_name);
    return normalized.rfind(L"api-", 0u) == 0u || normalized.rfind(L"ext-", 0u) == 0u;
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

    if (is_api_set_module_name(normalized)) {
        return 4u;
    }

    return 1u;
}

bool should_prefer_export_alias(const module_export& candidate, const module_export& current) {
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

bool starts_with_variable(const std::wstring_view entry, const std::wstring_view name) {
    if (entry.size() <= name.size() || entry[name.size()] != L'=') {
        return false;
    }

    return iequals(entry.substr(0, name.size()), name);
}

std::wstring quote_command_argument(const std::wstring_view argument) {
    std::wstring quoted;
    quoted.reserve(argument.size() + 2);
    quoted.push_back(L'"');

    auto backslashes = 0u;
    for (const auto ch : argument) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }

        if (ch == L'"') {
            quoted.append(backslashes * 2u + 1u, L'\\');
            quoted.push_back(ch);
            backslashes = 0;
            continue;
        }

        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(ch);
    }

    quoted.append(backslashes * 2u, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

result<std::vector<wchar_t>> build_runasinvoker_environment() {
    const auto raw_environment = GetEnvironmentStringsW();
    if (raw_environment == nullptr) {
        return make_win32_error(L"GetEnvironmentStringsW failed");
    }

    std::vector<std::wstring> entries;
    for (auto current = raw_environment; *current != L'\0'; current += std::wcslen(current) + 1) {
        const std::wstring_view entry(current);
        if (!starts_with_variable(entry, L"__COMPAT_LAYER")) {
            entries.emplace_back(entry);
        }
    }

    FreeEnvironmentStringsW(raw_environment);

    entries.emplace_back(L"__COMPAT_LAYER=RUNASINVOKER");
    std::sort(entries.begin(), entries.end(), [](const std::wstring& left, const std::wstring& right) {
        return lower_copy(left) < lower_copy(right);
    });

    std::vector<wchar_t> block;
    for (const auto& entry : entries) {
        block.insert(block.end(), entry.begin(), entry.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');

    return block;
}

result<std::wstring> system_rundll32_path() {
    std::array<wchar_t, MAX_PATH> buffer{};
    const auto length = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
    if (length == 0) {
        return make_win32_error(L"GetSystemDirectoryW failed");
    }

    if (length >= buffer.size()) {
        return make_error(status_code::system_error, L"system directory path is too long");
    }

    std::wstring path(buffer.data(), length);
    if (!path.empty() && path.back() != L'\\') {
        path.push_back(L'\\');
    }
    path += L"rundll32.exe";
    return path;
}

result<launch_spec> make_launch_spec(const std::wstring& target_path) {
    if (target_path.empty()) {
        return make_error(status_code::invalid_argument, L"target path is empty");
    }

    launch_spec spec;
    spec.dll_target = process_detail::is_dll_target(target_path);
    spec.main_module_name = process_detail::target_module_name(target_path);

    if (!spec.dll_target) {
        spec.application_path = target_path;
        spec.command_line = quote_command_argument(target_path);
        return spec;
    }

    auto rundll32 = system_rundll32_path();
    if (rundll32.is_error()) {
        return rundll32.error();
    }

    spec.application_path = std::move(rundll32.value());
    spec.command_line = quote_command_argument(spec.application_path);
    spec.command_line.push_back(L' ');
    spec.command_line += quote_command_argument(target_path);
    spec.command_line += L",#0";
    return spec;
}

std::wstring file_name_from_handle(const HANDLE file) {
    if (file == nullptr || file == INVALID_HANDLE_VALUE) {
        return {};
    }

    auto length = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0) {
        return {};
    }

    std::wstring path(length + 1, L'\0');
    length = GetFinalPathNameByHandleW(
        file,
        path.data(),
        static_cast<DWORD>(path.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= path.size()) {
        return {};
    }

    path.resize(length);
    return process_detail::target_module_name(path);
}

std::uint32_t pointer_size_for_arch(const demida::arch architecture) noexcept {
    switch (architecture) {
    case demida::arch::x86:
        return 4;
    case demida::arch::x64:
        return 8;
    default:
        return 0;
    }
}

demida::arch arch_from_machine(const USHORT machine) noexcept {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
        return demida::arch::x86;
    case IMAGE_FILE_MACHINE_AMD64:
        return demida::arch::x64;
    default:
        return demida::arch::unknown;
    }
}

demida::arch fallback_process_architecture(const HANDLE process) {
    using is_wow64_process2_type = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

    const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto is_wow64_process2 = kernel32 != nullptr
        ? reinterpret_cast<is_wow64_process2_type>(GetProcAddress(kernel32, "IsWow64Process2"))
        : nullptr;

    if (is_wow64_process2 != nullptr) {
        USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (is_wow64_process2(process, &process_machine, &native_machine) != FALSE) {
            if (process_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
                return arch_from_machine(process_machine);
            }

            return arch_from_machine(native_machine);
        }
    }

    BOOL wow64 = FALSE;
    if (IsWow64Process(process, &wow64) != FALSE && wow64 != FALSE) {
        return demida::arch::x86;
    }

#if defined(_M_X64)
    return demida::arch::x64;
#else
    return demida::arch::x86;
#endif
}

bool read_exact_raw(const HANDLE process, const std::uint64_t address, void* const buffer, const std::size_t size) {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               process,
               reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
               buffer,
               size,
               &bytes_read) != FALSE &&
        bytes_read == size;
}

template <typename value_type>
std::optional<value_type> read_remote_value_raw(const HANDLE process, const std::uint64_t address) {
    value_type value{};
    if (!read_exact_raw(process, address, &value, sizeof(value))) {
        return std::nullopt;
    }

    return value;
}

demida::arch remote_pe_architecture(const HANDLE process, const std::uint64_t image_base) {
    const auto dos = read_remote_value_raw<IMAGE_DOS_HEADER>(process, image_base);
    if (!dos.has_value() || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
        return demida::arch::unknown;
    }

    const auto nt_base = image_base + static_cast<std::uint32_t>(dos->e_lfanew);
    const auto signature = read_remote_value_raw<DWORD>(process, nt_base);
    if (!signature.has_value() || *signature != IMAGE_NT_SIGNATURE) {
        return demida::arch::unknown;
    }

    const auto file_header = read_remote_value_raw<IMAGE_FILE_HEADER>(process, nt_base + sizeof(DWORD));
    if (!file_header.has_value()) {
        return demida::arch::unknown;
    }

    const auto machine_arch = arch_from_machine(file_header->Machine);
    if (machine_arch != demida::arch::unknown) {
        return machine_arch;
    }

    const auto optional_magic =
        read_remote_value_raw<WORD>(process, nt_base + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    if (!optional_magic.has_value()) {
        return demida::arch::unknown;
    }

    if (*optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return demida::arch::x86;
    }

    if (*optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return demida::arch::x64;
    }

    return demida::arch::unknown;
}

std::optional<std::uint32_t> remote_image_size(const HANDLE process, const std::uint64_t image_base) {
    const auto dos = read_remote_value_raw<IMAGE_DOS_HEADER>(process, image_base);
    if (!dos.has_value() || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
        return std::nullopt;
    }

    const auto nt_base = image_base + static_cast<std::uint32_t>(dos->e_lfanew);
    const auto signature = read_remote_value_raw<DWORD>(process, nt_base);
    if (!signature.has_value() || *signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    const auto optional_base = nt_base + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto magic = read_remote_value_raw<WORD>(process, optional_base);
    if (!magic.has_value()) {
        return std::nullopt;
    }

    if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const auto optional = read_remote_value_raw<IMAGE_OPTIONAL_HEADER32>(process, optional_base);
        return optional.has_value() ? std::optional<std::uint32_t>(optional->SizeOfImage) : std::nullopt;
    }

    if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto optional = read_remote_value_raw<IMAGE_OPTIONAL_HEADER64>(process, optional_base);
        return optional.has_value() ? std::optional<std::uint32_t>(optional->SizeOfImage) : std::nullopt;
    }

    return std::nullopt;
}

std::optional<IMAGE_DATA_DIRECTORY> remote_export_directory(const HANDLE process, const std::uint64_t image_base) {
    const auto dos = read_remote_value_raw<IMAGE_DOS_HEADER>(process, image_base);
    if (!dos.has_value() || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
        return std::nullopt;
    }

    const auto nt_base = image_base + static_cast<std::uint32_t>(dos->e_lfanew);
    const auto signature = read_remote_value_raw<DWORD>(process, nt_base);
    if (!signature.has_value() || *signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    const auto optional_base = nt_base + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto magic = read_remote_value_raw<WORD>(process, optional_base);
    if (!magic.has_value()) {
        return std::nullopt;
    }

    if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const auto optional = read_remote_value_raw<IMAGE_OPTIONAL_HEADER32>(process, optional_base);
        return optional.has_value()
            ? std::optional<IMAGE_DATA_DIRECTORY>(optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT])
            : std::nullopt;
    }

    if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto optional = read_remote_value_raw<IMAGE_OPTIONAL_HEADER64>(process, optional_base);
        return optional.has_value()
            ? std::optional<IMAGE_DATA_DIRECTORY>(optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT])
            : std::nullopt;
    }

    return std::nullopt;
}

std::wstring widen_ascii(const std::string_view text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const auto ch : text) {
        wide.push_back(static_cast<unsigned char>(ch));
    }

    return wide;
}

std::optional<std::string> read_remote_c_string_raw(
    const HANDLE process,
    const std::uint64_t address,
    const std::size_t max_length = 260u) {
    std::string value;
    value.reserve(32);

    for (std::size_t index = 0; index < max_length; ++index) {
        char ch = 0;
        if (!read_exact_raw(process, address + index, &ch, sizeof(ch))) {
            return std::nullopt;
        }

        if (ch == '\0') {
            return value;
        }

        value.push_back(ch);
    }

    return std::nullopt;
}

std::wstring remote_module_name_from_export(const HANDLE process, const std::uint64_t image_base) {
    const auto directory = remote_export_directory(process, image_base);
    if (!directory.has_value() || directory->VirtualAddress == 0 || directory->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return {};
    }

    const auto exports = read_remote_value_raw<IMAGE_EXPORT_DIRECTORY>(process, image_base + directory->VirtualAddress);
    if (!exports.has_value() || exports->Name == 0) {
        return {};
    }

    const auto name = read_remote_c_string_raw(process, image_base + exports->Name);
    return name.has_value() ? widen_ascii(*name) : std::wstring{};
}

std::wstring remote_module_name_from_mapping(const HANDLE process, const std::uint64_t image_base) {
    std::array<wchar_t, MAX_PATH * 4u> buffer{};
    const auto length = GetModuleFileNameExW(
        process,
        reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(image_base)),
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length != 0 && length < buffer.size()) {
        return std::wstring(buffer.data(), length);
    }

    return remote_module_name_from_export(process, image_base);
}

result<std::vector<module_info>> enumerate_modules_by_memory(const HANDLE process) {
    SYSTEM_INFO system_info{};
    GetNativeSystemInfo(&system_info);

    auto cursor = reinterpret_cast<std::uint64_t>(system_info.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uint64_t>(system_info.lpMaximumApplicationAddress);
    std::vector<std::uint64_t> seen_bases;
    std::vector<module_info> modules;

    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION memory_info{};
        if (VirtualQueryEx(
                process,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(cursor)),
                &memory_info,
                sizeof(memory_info)) == 0) {
            const auto next = cursor + system_info.dwPageSize;
            if (next <= cursor) {
                break;
            }
            cursor = next;
            continue;
        }

        const auto allocation_base =
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(memory_info.AllocationBase));
        if (memory_info.State == MEM_COMMIT && memory_info.Type == MEM_IMAGE &&
            std::find(seen_bases.begin(), seen_bases.end(), allocation_base) == seen_bases.end()) {
            seen_bases.push_back(allocation_base);

            const auto image_size = remote_image_size(process, allocation_base);
            modules.push_back(module_info{
                .name = remote_module_name_from_mapping(process, allocation_base),
                .base = allocation_base,
                .size = image_size.value_or(static_cast<std::uint64_t>(memory_info.RegionSize)),
            });
        }

        const auto next = reinterpret_cast<std::uint64_t>(memory_info.BaseAddress) + memory_info.RegionSize;
        if (next <= cursor) {
            break;
        }
        cursor = next;
    }

    return modules;
}

process_architecture_info detect_process_architecture(const HANDLE process, const std::uint64_t image_base) {
    auto architecture = remote_pe_architecture(process, image_base);
    if (architecture == demida::arch::unknown) {
        architecture = fallback_process_architecture(process);
    }

    return process_architecture_info{
        .architecture = architecture,
        .pointer_size = pointer_size_for_arch(architecture),
    };
}

template <typename value_type>
result<value_type> read_remote_value(const debugged_process& process, const std::uint64_t address) {
    auto bytes = process.read_memory(address, sizeof(value_type));
    if (bytes.is_error()) {
        return bytes.error();
    }

    value_type value{};
    std::memcpy(&value, bytes.value().data(), sizeof(value));
    return value;
}

result<std::string> read_remote_c_string(
    const debugged_process& process,
    const std::uint64_t address,
    const std::size_t max_length = max_remote_string) {
    std::string value;
    value.reserve(64);

    for (std::size_t offset = 0; offset < max_length; ++offset) {
        const auto ch = read_remote_value<char>(process, address + offset);
        if (ch.is_error()) {
            return ch.error();
        }

        if (ch.value() == '\0') {
            return value;
        }

        value.push_back(ch.value());
    }

    return make_error(status_code::system_error, L"remote string is not null terminated");
}

constexpr auto process_basic_information_class = 0u;
constexpr auto process_wow64_information_class = 26u;
constexpr auto process_debug_port_class = 7u;
constexpr auto process_debug_object_handle_class = 30u;
constexpr auto process_debug_flags_class = 31u;
constexpr auto thread_hide_from_debugger_class = 17u;
constexpr auto status_port_not_set = 0xC0000353u;

struct process_basic_information_native {
    void* reserved_0 = nullptr;
    void* peb_base_address = nullptr;
    void* reserved_1[2]{};
    ULONG_PTR unique_process_id = 0;
    void* reserved_2 = nullptr;
};

using nt_query_information_process_type = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

nt_query_information_process_type local_nt_query_information_process() {
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<nt_query_information_process_type>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
}

bool nt_success(const LONG status) noexcept {
    return status >= 0;
}

template <typename value_type>
void append_value(std::vector<std::uint8_t>& bytes, const value_type value) {
    static_assert(std::is_integral_v<value_type>);
    for (std::size_t index = 0; index < sizeof(value_type); ++index) {
        bytes.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(value) >> (index * 8u)) & 0xffu));
    }
}

void append_bytes(std::vector<std::uint8_t>& out, const std::initializer_list<std::uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

std::vector<std::uint8_t> make_x64_absolute_jump(const std::uint64_t destination, const std::size_t patch_size) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(patch_size);
    append_bytes(bytes, {0x49, 0xBB});
    append_value<std::uint64_t>(bytes, destination);
    append_bytes(bytes, {0x41, 0xFF, 0xE3});
    bytes.resize(patch_size, 0x90);
    return bytes;
}

void append_x64_return_length(std::vector<std::uint8_t>& code, const std::uint32_t length) {
    append_bytes(code, {
        0x48, 0x8B, 0x44, 0x24, 0x28, // mov rax, qword ptr [rsp+28h]
        0x48, 0x85, 0xC0,             // test rax, rax
        0x74, 0x06,                   // jz +6
        0xC7, 0x00,                   // mov dword ptr [rax], imm32
    });
    append_value<std::uint32_t>(code, length);
}

std::vector<std::uint8_t> make_x64_nt_query_information_process_hook(const std::uint64_t trampoline) {
    std::vector<std::uint8_t> code;
    code.reserve(128);

    const auto patch_rel8 = [&code](const std::size_t offset, const std::size_t target) {
        const auto displacement = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(offset + 1u);
        code[offset] = static_cast<std::uint8_t>(static_cast<std::int8_t>(displacement));
    };

    append_bytes(code, {0x83, 0xFA, process_debug_port_class, 0x74, 0x00}); // cmp edx, 7 / je
    const auto jump_debug_port = code.size() - 1u;
    append_bytes(code, {0x83, 0xFA, process_debug_object_handle_class, 0x74, 0x00}); // cmp edx, 30 / je
    const auto jump_debug_object = code.size() - 1u;
    append_bytes(code, {0x83, 0xFA, process_debug_flags_class, 0x74, 0x00}); // cmp edx, 31 / je
    const auto jump_debug_flags = code.size() - 1u;

    append_bytes(code, {0x48, 0xB8});
    append_value<std::uint64_t>(code, trampoline);
    append_bytes(code, {0xFF, 0xE0});

    const auto debug_port = code.size();
    patch_rel8(jump_debug_port, debug_port);
    append_bytes(code, {
        0x4D, 0x85, 0xC0,       // test r8, r8
        0x74, 0x00,             // jz success
        0x41, 0x83, 0xF9, 0x08, // cmp r9d, 8
        0x72, 0x00,             // jb success
        0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, // mov qword ptr [r8], 0
    });
    const auto debug_port_null = debug_port + 4u;
    const auto debug_port_short = debug_port + 10u;
    append_x64_return_length(code, sizeof(std::uint64_t));
    const auto debug_port_success = code.size();
    patch_rel8(debug_port_null, debug_port_success);
    patch_rel8(debug_port_short, debug_port_success);
    append_bytes(code, {0x31, 0xC0, 0xC3}); // xor eax, eax / ret

    const auto debug_object = code.size();
    patch_rel8(jump_debug_object, debug_object);
    append_bytes(code, {0xB8});
    append_value<std::uint32_t>(code, status_port_not_set);
    append_bytes(code, {0xC3});

    const auto debug_flags = code.size();
    patch_rel8(jump_debug_flags, debug_flags);
    append_bytes(code, {
        0x4D, 0x85, 0xC0,       // test r8, r8
        0x74, 0x00,             // jz success
        0x41, 0x83, 0xF9, 0x04, // cmp r9d, 4
        0x72, 0x00,             // jb success
        0x41, 0xC7, 0x00,       // mov dword ptr [r8], 1
    });
    append_value<std::uint32_t>(code, 1u);
    const auto debug_flags_null = debug_flags + 4u;
    const auto debug_flags_short = debug_flags + 10u;
    append_x64_return_length(code, sizeof(std::uint32_t));
    const auto debug_flags_success = code.size();
    patch_rel8(debug_flags_null, debug_flags_success);
    patch_rel8(debug_flags_short, debug_flags_success);
    append_bytes(code, {0x31, 0xC0, 0xC3});

    return code;
}

std::vector<std::uint8_t> make_x64_nt_set_information_thread_hook(const std::uint64_t trampoline) {
    std::vector<std::uint8_t> code;
    code.reserve(32);

    append_bytes(code, {0x83, 0xFA, thread_hide_from_debugger_class, 0x74, 0x0D}); // cmp edx, 11h / je success
    append_bytes(code, {0x49, 0xBB});
    append_value<std::uint64_t>(code, trampoline);
    append_bytes(code, {0x41, 0xFF, 0xE3}); // jmp r11
    append_bytes(code, {0x31, 0xC0, 0xC3}); // xor eax, eax / ret
    return code;
}

std::vector<std::uint8_t> make_x64_nt_protect_virtual_memory_rearm_hook(
    const std::uint64_t trampoline,
    const std::span<const memory_range> ranges,
    const std::uint64_t image_base) {
    std::vector<std::uint8_t> code;
    code.reserve(128u + ranges.size() * 64u);

    append_bytes(code, {0x4C, 0x8B, 0x54, 0x24, 0x28}); // mov r10, qword ptr [rsp+28h]
    append_bytes(code, {0x48, 0x83, 0xEC, 0x78});       // sub rsp, 78h
    append_bytes(code, {0x4C, 0x89, 0x54, 0x24, 0x20}); // mov qword ptr [rsp+20h], r10
    append_bytes(code, {0x49, 0xBB});
    append_value<std::uint64_t>(code, trampoline);
    append_bytes(code, {0x41, 0xFF, 0xD3});             // call r11
    append_bytes(code, {0x89, 0x44, 0x24, 0x28});       // mov dword ptr [rsp+28h], eax

    for (const auto& range : ranges) {
        const auto runtime_range = process_detail::resolve_runtime_range(range, image_base);
        if (runtime_range.size == 0) {
            continue;
        }

        append_bytes(code, {0x48, 0xB8});
        append_value<std::uint64_t>(code, runtime_range.base);
        append_bytes(code, {0x48, 0x89, 0x44, 0x24, 0x30}); // mov qword ptr [rsp+30h], rax
        append_bytes(code, {0x48, 0xB8});
        append_value<std::uint64_t>(code, runtime_range.size);
        append_bytes(code, {0x48, 0x89, 0x44, 0x24, 0x38}); // mov qword ptr [rsp+38h], rax
        append_bytes(code, {0x48, 0xC7, 0x44, 0x24, 0x40});
        append_value<std::uint32_t>(code, PAGE_NOACCESS);

        append_bytes(code, {0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF}); // mov rcx, -1
        append_bytes(code, {0x48, 0x8D, 0x54, 0x24, 0x30});             // lea rdx, [rsp+30h]
        append_bytes(code, {0x4C, 0x8D, 0x44, 0x24, 0x38});             // lea r8, [rsp+38h]
        append_bytes(code, {0x41, 0xB9});
        append_value<std::uint32_t>(code, PAGE_NOACCESS);
        append_bytes(code, {0x48, 0x8D, 0x44, 0x24, 0x40});             // lea rax, [rsp+40h]
        append_bytes(code, {0x48, 0x89, 0x44, 0x24, 0x20});             // mov qword ptr [rsp+20h], rax
        append_bytes(code, {0x49, 0xBB});
        append_value<std::uint64_t>(code, trampoline);
        append_bytes(code, {0x41, 0xFF, 0xD3});                         // call r11
    }

    append_bytes(code, {0x8B, 0x44, 0x24, 0x28});       // mov eax, dword ptr [rsp+28h]
    append_bytes(code, {0x48, 0x83, 0xC4, 0x78});       // add rsp, 78h
    append_bytes(code, {0xC3});                         // ret
    return code;
}

status write_remote_code(
    const debugged_process& process,
    const std::uint64_t address,
    const std::span<const std::uint8_t> bytes) {
    std::uint32_t old_protect = 0;
    auto protect_status = process.protect_memory(address, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect);
    if (protect_status.is_error()) {
        return protect_status;
    }

    auto write_status = process.write_memory(address, bytes);
    const auto restore_status = process.protect_memory(address, bytes.size(), old_protect);
    if (write_status.is_error()) {
        return write_status;
    }

    return restore_status;
}

template <typename value_type>
status write_remote_value(debugged_process& process, const std::uint64_t address, const value_type value) {
    return process.write_memory(
        address,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(&value),
            sizeof(value)));
}

result<std::uint64_t> query_remote_peb_address(const debugged_process& process) {
    const auto nt_query_information_process = local_nt_query_information_process();
    if (nt_query_information_process == nullptr) {
        return make_error(status_code::system_error, L"NtQueryInformationProcess is not available");
    }

#if defined(_M_X64)
    if (process.architecture() == demida::arch::x86) {
        ULONG_PTR wow64_peb = 0;
        const auto wow64_status = nt_query_information_process(
            process.process_handle(),
            process_wow64_information_class,
            &wow64_peb,
            sizeof(wow64_peb),
            nullptr);
        if (nt_success(wow64_status) && wow64_peb != 0) {
            return static_cast<std::uint64_t>(wow64_peb);
        }
    }
#endif

    process_basic_information_native basic_info{};
    const auto status = nt_query_information_process(
        process.process_handle(),
        process_basic_information_class,
        &basic_info,
        sizeof(basic_info),
        nullptr);
    if (!nt_success(status) || basic_info.peb_base_address == nullptr) {
        return make_error(status_code::system_error, L"failed to query remote PEB address");
    }

    return reinterpret_cast<std::uint64_t>(basic_info.peb_base_address);
}

status mask_remote_peb_debug_state(debugged_process& process) {
    auto peb = query_remote_peb_address(process);
    if (peb.is_error()) {
        return peb.error();
    }

    constexpr auto being_debugged_offset = 0x2ull;
    const auto nt_global_flag_offset = process.architecture() == demida::arch::x64 ? 0xBCull : 0x68ull;

    auto clear_debugged = write_remote_value<std::uint8_t>(process, peb.value() + being_debugged_offset, 0u);
    if (clear_debugged.is_error()) {
        return clear_debugged;
    }

    auto flags = read_remote_value<std::uint32_t>(process, peb.value() + nt_global_flag_offset);
    if (flags.is_error()) {
        return flags.error();
    }

    flags.value() &= ~0x70u;
    return write_remote_value<std::uint32_t>(process, peb.value() + nt_global_flag_offset, flags.value());
}

status install_nt_query_information_process_mask(debugged_process& process) {
    if (process.architecture() != demida::arch::x64) {
        return {};
    }

    constexpr auto patch_size = 16u;
    auto export_address = process.find_export(L"ntdll.dll", "NtQueryInformationProcess");
    if (export_address.is_error()) {
        return export_address.error();
    }

    auto original = process.read_memory(export_address.value(), patch_size);
    if (original.is_error()) {
        return original.error();
    }

    if (original.value().size() < patch_size || original.value()[0] != 0x4Cu || original.value()[1] != 0x8Bu ||
        original.value()[2] != 0xD1u) {
        return make_error(status_code::unsupported_version, L"unsupported NtQueryInformationProcess prologue");
    }

    auto allocation = process.allocate_near(export_address.value(), 0x1000u, PAGE_EXECUTE_READWRITE);
    if (allocation.is_error()) {
        return allocation.error();
    }

    auto trampoline = original.value();
    const auto trampoline_tail = make_x64_absolute_jump(export_address.value() + patch_size, 13u);
    trampoline.insert(trampoline.end(), trampoline_tail.begin(), trampoline_tail.end());

    const auto handler_address = allocation.value() + trampoline.size();
    auto handler = make_x64_nt_query_information_process_hook(allocation.value());

    std::vector<std::uint8_t> remote_code;
    remote_code.reserve(trampoline.size() + handler.size());
    remote_code.insert(remote_code.end(), trampoline.begin(), trampoline.end());
    remote_code.insert(remote_code.end(), handler.begin(), handler.end());

    auto write_stub = process.write_memory(
        allocation.value(),
        std::span<const std::uint8_t>(remote_code.data(), remote_code.size()));
    if (write_stub.is_error()) {
        return write_stub;
    }

    const auto patch = make_x64_absolute_jump(handler_address, patch_size);
    return write_remote_code(process, export_address.value(), std::span<const std::uint8_t>(patch.data(), patch.size()));
}

status install_nt_set_information_thread_mask(debugged_process& process) {
    if (process.architecture() != demida::arch::x64) {
        return {};
    }

    constexpr auto patch_size = 16u;
    auto export_address = process.find_export(L"ntdll.dll", "NtSetInformationThread");
    if (export_address.is_error()) {
        return export_address.error();
    }

    auto original = process.read_memory(export_address.value(), patch_size);
    if (original.is_error()) {
        return original.error();
    }

    if (original.value().size() < patch_size || original.value()[0] != 0x4Cu || original.value()[1] != 0x8Bu ||
        original.value()[2] != 0xD1u) {
        return make_error(status_code::unsupported_version, L"unsupported NtSetInformationThread prologue");
    }

    auto allocation = process.allocate_near(export_address.value(), 0x1000u, PAGE_EXECUTE_READWRITE);
    if (allocation.is_error()) {
        return allocation.error();
    }

    auto trampoline = original.value();
    const auto trampoline_tail = make_x64_absolute_jump(export_address.value() + patch_size, 13u);
    trampoline.insert(trampoline.end(), trampoline_tail.begin(), trampoline_tail.end());

    const auto handler_address = allocation.value() + trampoline.size();
    auto handler = make_x64_nt_set_information_thread_hook(allocation.value());

    std::vector<std::uint8_t> remote_code;
    remote_code.reserve(trampoline.size() + handler.size());
    remote_code.insert(remote_code.end(), trampoline.begin(), trampoline.end());
    remote_code.insert(remote_code.end(), handler.begin(), handler.end());

    auto write_stub = process.write_memory(
        allocation.value(),
        std::span<const std::uint8_t>(remote_code.data(), remote_code.size()));
    if (write_stub.is_error()) {
        return write_stub;
    }

    const auto patch = make_x64_absolute_jump(handler_address, patch_size);
    return write_remote_code(process, export_address.value(), std::span<const std::uint8_t>(patch.data(), patch.size()));
}

status install_nt_protect_virtual_memory_rearm(
    debugged_process& process,
    const std::span<const memory_range> expected_ranges) {
    if (process.architecture() != demida::arch::x64 || expected_ranges.empty()) {
        return {};
    }

    constexpr auto patch_size = 16u;
    auto export_address = process.find_export(L"ntdll.dll", "NtProtectVirtualMemory");
    if (export_address.is_error()) {
        return export_address.error();
    }

    auto original = process.read_memory(export_address.value(), patch_size);
    if (original.is_error()) {
        return original.error();
    }

    if (original.value().size() < patch_size || original.value()[0] != 0x4Cu || original.value()[1] != 0x8Bu ||
        original.value()[2] != 0xD1u) {
        return make_error(status_code::unsupported_version, L"unsupported NtProtectVirtualMemory prologue");
    }

    auto allocation = process.allocate_near(export_address.value(), 0x2000u, PAGE_EXECUTE_READWRITE);
    if (allocation.is_error()) {
        return allocation.error();
    }

    auto trampoline = original.value();
    const auto trampoline_tail = make_x64_absolute_jump(export_address.value() + patch_size, 13u);
    trampoline.insert(trampoline.end(), trampoline_tail.begin(), trampoline_tail.end());

    const auto handler_address = allocation.value() + trampoline.size();
    auto handler = make_x64_nt_protect_virtual_memory_rearm_hook(
        allocation.value(),
        expected_ranges,
        process.image_base());

    std::vector<std::uint8_t> remote_code;
    remote_code.reserve(trampoline.size() + handler.size());
    remote_code.insert(remote_code.end(), trampoline.begin(), trampoline.end());
    remote_code.insert(remote_code.end(), handler.begin(), handler.end());

    if (remote_code.size() > 0x2000u) {
        return make_error(status_code::system_error, L"NtProtectVirtualMemory hook is larger than its code allocation");
    }

    auto write_stub = process.write_memory(
        allocation.value(),
        std::span<const std::uint8_t>(remote_code.data(), remote_code.size()));
    if (write_stub.is_error()) {
        return write_stub;
    }

    const auto patch = make_x64_absolute_jump(handler_address, patch_size);
    return write_remote_code(process, export_address.value(), std::span<const std::uint8_t>(patch.data(), patch.size()));
}

status mask_initial_debugger_state(debugged_process& process) {
    auto peb_status = mask_remote_peb_debug_state(process);
    if (peb_status.is_error()) {
        return peb_status;
    }

    auto query_mask_status = install_nt_query_information_process_mask(process);
    if (query_mask_status.is_error()) {
        return query_mask_status;
    }

    return install_nt_set_information_thread_mask(process);
}

bool module_name_matches(const std::wstring& observed, const std::wstring& requested) {
    if (iequals(observed, requested)) {
        return true;
    }

    return iequals(process_detail::target_module_name(observed), process_detail::target_module_name(requested));
}

result<module_info> find_module(const debugged_process& process, const std::wstring& module_name) {
    auto modules = process.enumerate_modules();
    if (modules.is_error()) {
        return modules.error();
    }

    for (auto& module : modules.value()) {
        if (module_name_matches(module.name, module_name)) {
            return std::move(module);
        }
    }

    return make_error(status_code::invalid_argument, L"module was not found: " + module_name);
}

bool is_dotnet_loaded(const debugged_process& process) {
    auto modules = process.enumerate_modules();
    if (modules.is_error()) {
        return false;
    }

    return std::any_of(modules.value().begin(), modules.value().end(), [](const module_info& module) {
        return iequals(process_detail::target_module_name(module.name), L"clr.dll");
    });
}

result<normalized_context> get_thread_context_for_process(const debugged_process& process, const HANDLE thread) {
    normalized_context context;
    context.architecture = process.architecture();

    if (context.architecture == demida::arch::x86) {
#if defined(_M_X64)
        context.wow64 = true;
        context.wow64_context.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
        if (Wow64GetThreadContext(thread, &context.wow64_context) == FALSE) {
            return make_win32_error(L"Wow64GetThreadContext failed");
        }

        context.instruction_pointer = context.wow64_context.Eip;
        context.stack_pointer = context.wow64_context.Esp;
        return context;
#else
        context.native_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"GetThreadContext failed");
        }

        context.instruction_pointer = context.native_context.Eip;
        context.stack_pointer = context.native_context.Esp;
        return context;
#endif
    }

    if (context.architecture == demida::arch::x64) {
#if defined(_M_X64)
        context.native_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"GetThreadContext failed");
        }

        context.instruction_pointer = context.native_context.Rip;
        context.stack_pointer = context.native_context.Rsp;
        context.rcx = context.native_context.Rcx;
        context.rdx = context.native_context.Rdx;
        return context;
#else
        return make_error(status_code::unsupported_version, L"x86 builds cannot trace x64 thread context");
#endif
    }

    return make_error(status_code::unsupported_version, L"target architecture is unknown");
}

result<std::uint64_t> read_stack_return_address(
    const debugged_process& process,
    std::uint64_t stack_pointer,
    std::uint32_t pointer_size);

status enable_single_step(const HANDLE thread, normalized_context& context) {
    if (context.architecture == demida::arch::x86) {
#if defined(_M_X64)
        context.wow64_context.EFlags |= trap_flag;
        if (Wow64SetThreadContext(thread, &context.wow64_context) == FALSE) {
            return make_win32_error(L"Wow64SetThreadContext failed");
        }

        return status{};
#else
        context.native_context.EFlags |= trap_flag;
        if (SetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"SetThreadContext failed");
        }

        return status{};
#endif
    }

    if (context.architecture == demida::arch::x64) {
#if defined(_M_X64)
        context.native_context.EFlags |= trap_flag;
        if (SetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"SetThreadContext failed");
        }

        return status{};
#else
        return make_error(status_code::unsupported_version, L"x86 builds cannot update x64 thread context");
#endif
    }

    return make_error(status_code::unsupported_version, L"target architecture is unknown");
}

process_detail::tls_callback_context make_tls_context(
    const debugged_process& process,
    const normalized_context& context) {
    process_detail::tls_callback_context tls_context{
        .architecture = context.architecture,
        .image_base = process.image_base(),
        .rcx = context.rcx,
        .rdx = context.rdx,
    };

    if (context.architecture == demida::arch::x86) {
        const auto arg0 = process.read_memory(context.stack_pointer + 4, sizeof(std::uint32_t));
        const auto arg1 = process.read_memory(context.stack_pointer + 8, sizeof(std::uint32_t));

        if (arg0.is_success() && arg1.is_success()) {
            std::uint32_t raw_arg0 = 0;
            std::uint32_t raw_arg1 = 0;
            std::memcpy(&raw_arg0, arg0.value().data(), sizeof(raw_arg0));
            std::memcpy(&raw_arg1, arg1.value().data(), sizeof(raw_arg1));
            tls_context.stack_arg_0 = raw_arg0;
            tls_context.stack_arg_1 = raw_arg1;
        }
    }

    return tls_context;
}

result<std::uint64_t> read_stack_return_address(
    const debugged_process& process,
    const std::uint64_t stack_pointer,
    const std::uint32_t pointer_size) {
    auto bytes = process.read_memory(stack_pointer, pointer_size);
    if (bytes.is_error()) {
        return bytes.error();
    }

    if (pointer_size == sizeof(std::uint32_t)) {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.value().data(), sizeof(value));
        return static_cast<std::uint64_t>(value);
    }

    if (pointer_size == sizeof(std::uint64_t)) {
        std::uint64_t value = 0;
        std::memcpy(&value, bytes.value().data(), sizeof(value));
        return value;
    }

    return make_error(status_code::unsupported_version, L"unsupported pointer size while skipping TLS callback");
}

status skip_tls_callback(
    const debugged_process& process,
    const HANDLE thread,
    normalized_context& context) {
    auto return_address = read_stack_return_address(process, context.stack_pointer, process.pointer_size());
    if (return_address.is_error()) {
        return return_address.error();
    }

    if (context.architecture == demida::arch::x86) {
#if defined(_M_X64)
        context.wow64_context.Eip = static_cast<DWORD>(return_address.value());
        context.wow64_context.Esp += sizeof(std::uint32_t) + 0x0cu;
        if (Wow64SetThreadContext(thread, &context.wow64_context) == FALSE) {
            return make_win32_error(L"Wow64SetThreadContext failed");
        }

        return {};
#else
        context.native_context.Eip = static_cast<DWORD>(return_address.value());
        context.native_context.Esp += sizeof(std::uint32_t) + 0x0cu;
        if (SetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"SetThreadContext failed");
        }

        return {};
#endif
    }

    if (context.architecture == demida::arch::x64) {
#if defined(_M_X64)
        context.native_context.Rip = return_address.value();
        context.native_context.Rsp += sizeof(std::uint64_t);
        if (SetThreadContext(thread, &context.native_context) == FALSE) {
            return make_win32_error(L"SetThreadContext failed");
        }

        return {};
#else
        return make_error(status_code::unsupported_version, L"x86 builds cannot update x64 thread context");
#endif
    }

    return make_error(status_code::unsupported_version, L"target architecture is unknown");
}

unique_handle open_debug_event_thread(const DWORD thread_id) {
    return unique_handle(OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_id));
}

unique_handle open_executor_thread(const DWORD thread_id) {
    return unique_handle(OpenThread(
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
        FALSE,
        thread_id));
}

result<std::vector<unique_handle>> suspend_other_threads(const DWORD process_id, const DWORD executor_thread_id) {
    auto snapshot = unique_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) {
        return make_win32_error(L"CreateToolhelp32Snapshot failed");
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot.get(), &entry) == FALSE) {
        return make_win32_error(L"Thread32First failed");
    }

    std::vector<unique_handle> suspended;
    do {
        if (entry.th32OwnerProcessID != process_id || entry.th32ThreadID == executor_thread_id) {
            continue;
        }

        auto thread = unique_handle(OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID));
        if (!thread) {
            continue;
        }

        if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
            continue;
        }

        suspended.push_back(std::move(thread));
    } while (Thread32Next(snapshot.get(), &entry) != FALSE);

    return suspended;
}

void resume_threads(std::vector<unique_handle>& threads) {
    for (auto& thread : threads) {
        if (thread) {
            ResumeThread(thread.get());
        }
    }

    threads.clear();
}

struct export_guard_page {
    std::uint64_t base = 0;
    std::uint32_t protect = PAGE_EXECUTE_READ;
};

result<std::vector<export_guard_page>> collect_export_guard_pages(
    const debugged_process& process,
    const std::span<const module_export> exports) {
    std::vector<export_guard_page> pages;
    std::unordered_set<std::uint64_t> seen;

    const auto page_size = static_cast<std::uint64_t>(process.page_size());
    if (page_size == 0) {
        return make_error(status_code::system_error, L"process page size is unknown");
    }

    for (const auto& symbol : exports) {
        if (symbol.address == 0) {
            continue;
        }

        const auto page_base = symbol.address - (symbol.address % page_size);
        if (!seen.insert(page_base).second) {
            continue;
        }

        auto range = process.query_memory(page_base);
        if (range.is_error()) {
            continue;
        }

        const auto protect = range.value().protect;
        //
        // Forwarded exports point into .rdata strings. Guarding those pages
        // stops wrappers while they are still walking metadata instead of
        // reaching the final imported code.
        //
        if (!process_detail::is_guardable_export_page_protect(protect)) {
            continue;
        }

        pages.push_back(export_guard_page{
            .base = page_base,
            .protect = protect & ~static_cast<std::uint32_t>(PAGE_GUARD),
        });
    }

    return pages;
}

status arm_export_guards(const debugged_process& process, const std::span<const export_guard_page> pages) {
    for (const auto& page : pages) {
        const auto protect_status =
            process.protect_memory(page.base, process.page_size(), page.protect | PAGE_GUARD, nullptr);
        if (protect_status.is_error()) {
            return protect_status;
        }
    }

    return {};
}

status write_remote_u64(const debugged_process& process, const std::uint64_t address, const std::uint64_t value) {
    std::array<std::uint8_t, sizeof(value)> bytes{};
    std::memcpy(bytes.data(), &value, sizeof(value));
    return process.write_memory(address, bytes);
}

status set_x64_wrapper_context(
    const debugged_process& process,
    const HANDLE thread,
    const std::uint64_t wrapper_address,
    const std::uint64_t stack_pointer) {
#if defined(_M_X64)
    const auto write_status = write_remote_u64(process, stack_pointer, wrapper_magic_return);
    if (write_status.is_error()) {
        return write_status;
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"GetThreadContext failed");
    }

    context.Rip = wrapper_address;
    context.Rsp = stack_pointer;
    context.Rbp = stack_pointer;
    context.Rax = 0;
    context.Rcx = 0;
    context.Rdx = 0;
    context.R8 = 0;
    context.R9 = 0;
    context.EFlags &= ~trap_flag;

    if (SetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"SetThreadContext failed");
    }

    return {};
#else
    (void)process;
    (void)thread;
    (void)wrapper_address;
    (void)stack_pointer;
    return make_error(status_code::unsupported_version, L"x86 builds cannot resolve x64 wrappers");
#endif
}

status enable_x64_single_step(const HANDLE thread) {
#if defined(_M_X64)
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"GetThreadContext failed");
    }

    context.EFlags |= trap_flag;
    if (SetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"SetThreadContext failed");
    }

    return {};
#else
    (void)thread;
    return make_error(status_code::unsupported_version, L"x86 builds cannot single-step x64 wrappers");
#endif
}

result<std::uint64_t> current_x64_rax(const HANDLE thread) {
#if defined(_M_X64)
    CONTEXT context{};
    context.ContextFlags = CONTEXT_INTEGER;
    if (GetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"GetThreadContext failed");
    }

    return context.Rax;
#else
    (void)thread;
    return make_error(status_code::unsupported_version, L"x86 builds cannot read x64 context");
#endif
}

result<std::uint64_t> current_x64_rcx(const HANDLE thread) {
#if defined(_M_X64)
    CONTEXT context{};
    context.ContextFlags = CONTEXT_INTEGER;
    if (GetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"GetThreadContext failed");
    }

    return context.Rcx;
#else
    (void)thread;
    return make_error(status_code::unsupported_version, L"x86 builds cannot read x64 context");
#endif
}

result<std::uint64_t> remote_ansi_string_length(
    const debugged_process& process,
    const std::uint64_t address,
    const std::size_t max_length = max_remote_string) {
    if (address == 0u) {
        return 0ull;
    }

    for (std::size_t offset = 0; offset < max_length; ++offset) {
        auto ch = read_remote_value<char>(process, address + offset);
        if (ch.is_error()) {
            return ch.error();
        }

        if (ch.value() == '\0') {
            return static_cast<std::uint64_t>(offset);
        }
    }

    return make_error(status_code::system_error, L"remote ANSI string is not null terminated");
}

result<std::uint64_t> remote_wide_string_length(
    const debugged_process& process,
    const std::uint64_t address,
    const std::size_t max_length = max_remote_string) {
    if (address == 0u) {
        return 0ull;
    }

    for (std::size_t offset = 0; offset < max_length; ++offset) {
        auto ch = read_remote_value<wchar_t>(process, address + (offset * sizeof(wchar_t)));
        if (ch.is_error()) {
            return ch.error();
        }

        if (ch.value() == L'\0') {
            return static_cast<std::uint64_t>(offset);
        }
    }

    return make_error(status_code::system_error, L"remote wide string is not null terminated");
}

status simulate_x64_api_return(
    const debugged_process& process,
    const HANDLE thread,
    const std::uint64_t return_value) {
#if defined(_M_X64)
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"GetThreadContext failed");
    }

    auto return_address = read_stack_return_address(process, context.Rsp, process.pointer_size());
    if (return_address.is_error()) {
        return return_address.error();
    }

    context.Rip = return_address.value();
    context.Rsp += sizeof(std::uint64_t);
    context.Rax = return_value;

    if (SetThreadContext(thread, &context) == FALSE) {
        return make_win32_error(L"SetThreadContext failed");
    }

    return {};
#else
    (void)process;
    (void)thread;
    (void)return_value;
    return make_error(status_code::unsupported_version, L"x86 builds cannot update x64 context");
#endif
}

result<bool> try_simulate_x64_wrapper_helper_api(
    const debugged_process& process,
    const HANDLE thread,
    const std::string& export_name) {
    if (export_name == "Sleep") {
        auto simulate_status = simulate_x64_api_return(process, thread, 0);
        if (simulate_status.is_error()) {
            return simulate_status;
        }

        return true;
    }

    if (export_name != "lstrlen" && export_name != "lstrlenA" && export_name != "lstrlenW" &&
        export_name != "uaw_lstrlenW") {
        return false;
    }

    auto string_address = current_x64_rcx(thread);
    if (string_address.is_error()) {
        return string_address.error();
    }

    const auto wide = export_name == "lstrlenW" || export_name == "uaw_lstrlenW";
    auto length = wide
        ? remote_wide_string_length(process, string_address.value())
        : remote_ansi_string_length(process, string_address.value());
    if (length.is_error()) {
        return length.error();
    }

    auto simulate_status = simulate_x64_api_return(process, thread, length.value());
    if (simulate_status.is_error()) {
        return simulate_status;
    }

    return true;
}

enum class access_violation_action : std::uint8_t {
    pass_to_process = 0,
    continue_after_single_step = 1,
    found_oep = 2,
    continue_after_context_update = 3,
};

result<access_violation_action> handle_access_violation(
    debugged_process& process,
    const DEBUG_EVENT& event,
    std::optional<DWORD>& pending_reprotect_thread,
    const bool verbose) {
    const auto& exception = event.u.Exception.ExceptionRecord;
    const auto exception_address = reinterpret_cast<std::uint64_t>(exception.ExceptionAddress);
    auto fault_address = 0ull;

    if (exception.NumberParameters >= 2) {
        fault_address = exception.ExceptionInformation[1];
    }

    const auto thread = open_debug_event_thread(event.dwThreadId);
    if (!thread) {
        return make_win32_error(L"OpenThread failed");
    }

    auto context = get_thread_context_for_process(process, thread.get());
    if (context.is_error()) {
        return context.error();
    }

    const auto instruction_pointer = context.value().instruction_pointer != 0
        ? context.value().instruction_pointer
        : exception_address;

    const auto ip_in_expected_range = process.expected_ranges_contain(instruction_pointer);
    const auto fault_in_expected_range = process.expected_ranges_contain(fault_address);

    if (verbose) {
        std::wcerr << L"trace: av tid=" << event.dwThreadId << L" ip=0x" << std::hex << instruction_pointer
                   << L" fault=0x" << fault_address << std::dec << L" ip_expected=" << ip_in_expected_range
                   << L" fault_expected=" << fault_in_expected_range << L"\n";
    }

    if (ip_in_expected_range) {
        const auto tls_context = make_tls_context(process, context.value());
        if (process_detail::looks_like_tls_callback(tls_context)) {
            if (verbose) {
                std::wcerr << L"trace: tls callback skipped at 0x" << std::hex << instruction_pointer << std::dec
                           << L"\n";
            }

            auto skip_status = skip_tls_callback(process, thread.get(), context.value());
            if (skip_status.is_error()) {
                return skip_status;
            }

            return access_violation_action::continue_after_context_update;
        }

        if (verbose) {
            std::wcerr << L"trace: oep candidate at 0x" << std::hex << instruction_pointer << std::dec << L"\n";
        }

        return access_violation_action::found_oep;
    }

    if (fault_in_expected_range) {
        if (verbose) {
            std::wcerr << L"trace: allowing data access to trapped page at 0x" << std::hex << fault_address
                       << std::dec << L"\n";
        }

        const auto access_status = process.allow_expected_page_data_access(fault_address);
        if (access_status.is_error()) {
            return access_status;
        }

        pending_reprotect_thread.reset();
        return access_violation_action::continue_after_context_update;
    }

    return access_violation_action::pass_to_process;
}

bool timeout_expired(const ULONGLONG started, const std::uint32_t timeout_seconds) {
    if (timeout_seconds == 0) {
        return false;
    }

    const auto timeout_ms = static_cast<ULONGLONG>(timeout_seconds) * 1000ull;
    return GetTickCount64() - started >= timeout_ms;
}

DWORD debug_wait_slice(const ULONGLONG started, const std::uint32_t timeout_seconds) {
    if (timeout_seconds == 0) {
        return 100;
    }

    const auto elapsed = GetTickCount64() - started;
    const auto timeout_ms = static_cast<ULONGLONG>(timeout_seconds) * 1000ull;
    if (elapsed >= timeout_ms) {
        return 0;
    }

    const auto remaining = timeout_ms - elapsed;
    return static_cast<DWORD>((std::min)(remaining, 100ull));
}

status cleanup_after_trace(debugged_process& process, const DEBUG_EVENT& event, const DWORD continue_status) {
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
    return process.terminate();
}

} // namespace

namespace process_detail {

process_memory_range resolve_runtime_range(const memory_range range, const std::uint64_t image_base) noexcept {
    auto runtime_base = range.base;
    if (image_base != 0 && range.base < image_base && !add_overflows(image_base, range.base)) {
        runtime_base = image_base + range.base;
    }

    return process_memory_range{
        .base = runtime_base,
        .size = range.size,
        .protect = PAGE_NOACCESS,
    };
}

bool contains_runtime_address(
    const std::span<const memory_range> ranges,
    const std::uint64_t image_base,
    const std::uint64_t address) noexcept {
    for (const auto& range : ranges) {
        if (resolve_runtime_range(range, image_base).contains(address)) {
            return true;
        }
    }

    return false;
}

std::optional<std::uint64_t> exact_guarded_export_hit(
    const std::uint64_t exception_address,
    const std::span<const std::uint64_t> export_addresses) noexcept {
    if (exception_address == 0) {
        return std::nullopt;
    }

    for (const auto export_address : export_addresses) {
        if (export_address == exception_address) {
            return exception_address;
        }
    }

    return std::nullopt;
}

bool is_guardable_export_page_protect(const std::uint32_t protect) noexcept {
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

bool is_trapped_wrapper_entry_fault(
    const std::uint32_t exception_code,
    const std::uint64_t exception_address,
    const std::uint64_t fault_address,
    const std::uint64_t wrapper_address) noexcept {
    return exception_code == EXCEPTION_ACCESS_VIOLATION && wrapper_address != 0 &&
           exception_address == wrapper_address && fault_address == wrapper_address;
}

bool is_non_export_wrapper_guard_fault(
    const std::uint64_t exception_address,
    const std::uint64_t fault_address,
    const std::span<const process_memory_range> armed_export_pages) noexcept {
    const auto touches_armed_export_page = [armed_export_pages](const std::uint64_t address) noexcept {
        if (address == 0) {
            return false;
        }

        for (const auto& page : armed_export_pages) {
            if (page.contains(address)) {
                return true;
            }
        }

        return false;
    };

    return !touches_armed_export_page(exception_address) && !touches_armed_export_page(fault_address);
}

bool is_export_page_data_guard_fault(
    const std::uint64_t exception_address,
    const std::uint64_t fault_address,
    const std::span<const process_memory_range> armed_export_pages) noexcept {
    const auto touches_armed_export_page = [armed_export_pages](const std::uint64_t address) noexcept {
        if (address == 0) {
            return false;
        }

        for (const auto& page : armed_export_pages) {
            if (page.contains(address)) {
                return true;
            }
        }

        return false;
    };

    return !touches_armed_export_page(exception_address) && touches_armed_export_page(fault_address);
}

bool looks_like_tls_callback(const tls_callback_context& context) noexcept {
    if (context.image_base == 0) {
        return false;
    }

    if (context.architecture == demida::arch::x64) {
        return context.rcx == context.image_base && context.rdx <= 4;
    }

    if (context.architecture == demida::arch::x86) {
        return context.stack_arg_0 == context.image_base && context.stack_arg_1 <= 4;
    }

    return false;
}

std::wstring target_module_name(const std::wstring_view target_path) {
    const auto slash = target_path.find_last_of(L"\\/");
    if (slash == std::wstring_view::npos) {
        return std::wstring(target_path);
    }

    return std::wstring(target_path.substr(slash + 1));
}

bool is_dll_target(const std::wstring_view target_path) {
    const auto name = target_module_name(target_path);
    const auto dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos) {
        return false;
    }

    return iequals(std::wstring_view(name).substr(dot), L".dll");
}

} // namespace process_detail

debugged_process::debugged_process(
    unique_handle process,
    unique_handle main_thread,
    const std::uint32_t process_id,
    const std::uint64_t image_base,
    std::wstring main_module_name,
    const demida::arch architecture,
    const std::uint32_t pointer_size,
    const std::uint32_t page_size) noexcept
    : process_(std::move(process)),
      main_thread_(std::move(main_thread)),
      process_id_(process_id),
      image_base_(image_base),
      main_module_name_(std::move(main_module_name)),
      architecture_(architecture),
      pointer_size_(pointer_size),
      page_size_(page_size) {
}

result<debugged_process> debugged_process::spawn_suspended_or_debugged(const std::wstring& target_path) {
    auto launch = make_launch_spec(target_path);
    if (launch.is_error()) {
        return launch.error();
    }

    auto environment = build_runasinvoker_environment();
    if (environment.is_error()) {
        return environment.error();
    }

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);

    PROCESS_INFORMATION process_info{};
    auto command_line = launch.value().command_line;

    const auto flags = DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT;
    if (CreateProcessW(
            launch.value().application_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            flags,
            environment.value().data(),
            nullptr,
            &startup_info,
            &process_info) == FALSE) {
        return make_win32_error(L"CreateProcessW failed");
    }

    unique_handle process(process_info.hProcess);
    unique_handle thread(process_info.hThread);

    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);

    const auto architecture = fallback_process_architecture(process.get());
    return debugged_process(
        std::move(process),
        std::move(thread),
        process_info.dwProcessId,
        0,
        std::move(launch.value().main_module_name),
        architecture,
        pointer_size_for_arch(architecture),
        system_info.dwPageSize);
}

status debugged_process::terminate() {
    if (!process_) {
        return {};
    }

    if (has_pending_debug_event_) {
        ContinueDebugEvent(pending_debug_process_id_, pending_debug_thread_id_, pending_debug_continue_status_);
        has_pending_debug_event_ = false;
    }

    if (TerminateProcess(process_.get(), 1) == FALSE) {
        return make_win32_error(L"TerminateProcess failed");
    }

    WaitForSingleObject(process_.get(), 5000);
    main_thread_.reset();
    process_.reset();
    return {};
}

status debugged_process::continue_from_oep(const bool detach_after_continue) {
    if (!has_pending_debug_event_) {
        return {};
    }

    if (ContinueDebugEvent(pending_debug_process_id_, pending_debug_thread_id_, pending_debug_continue_status_) == FALSE) {
        return make_win32_error(L"ContinueDebugEvent failed");
    }

    has_pending_debug_event_ = false;

    if (detach_after_continue) {
        DebugSetProcessKillOnExit(FALSE);
        if (DebugActiveProcessStop(process_id_) == FALSE) {
            return make_win32_error(L"DebugActiveProcessStop failed");
        }
    }

    return {};
}

result<std::unordered_map<std::uint64_t, std::uint64_t>> debugged_process::resolve_wrapped_import_targets(
    const std::span<const std::uint64_t> wrapper_addresses,
    const std::span<const module_export> exports,
    const bool verbose) {
    std::unordered_map<std::uint64_t, std::uint64_t> resolved;
    if (wrapper_addresses.empty()) {
        return resolved;
    }

    if (architecture_ != demida::arch::x64 || pointer_size_ != sizeof(std::uint64_t)) {
        return make_error(status_code::unsupported_version, L"runtime wrapper resolution currently requires an x64 target");
    }

    if (!has_pending_debug_event_) {
        return make_error(status_code::invalid_argument, L"wrapper resolution requires a pending OEP debug event");
    }

    const auto restore_expected_status = restore_expected_ranges();
    if (restore_expected_status.is_error()) {
        return restore_expected_status;
    }

    std::unordered_map<std::uint64_t, const module_export*> export_by_address;
    export_by_address.reserve(exports.size());
    std::vector<std::uint64_t> export_addresses;
    export_addresses.reserve(exports.size());
    for (const auto& symbol : exports) {
        if (symbol.address != 0) {
            auto existing = export_by_address.find(symbol.address);
            if (existing == export_by_address.end() || should_prefer_export_alias(symbol, *existing->second)) {
                export_by_address[symbol.address] = &symbol;
            }
            export_addresses.push_back(symbol.address);
        }
    }

    auto guard_pages = collect_export_guard_pages(*this, exports);
    if (guard_pages.is_error()) {
        return guard_pages.error();
    }

    const auto& export_guard_pages = guard_pages.value();
    std::vector<process_memory_range> export_guard_ranges;
    export_guard_ranges.reserve(export_guard_pages.size());
    for (const auto& page : export_guard_pages) {
        export_guard_ranges.push_back(process_memory_range{
            .base = page.base,
            .size = page_size_,
            .protect = page.protect | PAGE_GUARD,
        });
    }

    const auto executor_thread_id = pending_debug_thread_id_;
    auto executor_thread = open_executor_thread(executor_thread_id);
    if (!executor_thread) {
        return make_win32_error(L"OpenThread failed");
    }

    auto suspended_threads = suspend_other_threads(process_id_, executor_thread_id);
    if (suspended_threads.is_error()) {
        return suspended_threads.error();
    }

    const auto stack_size = static_cast<std::size_t>(page_size_) * wrapper_resolve_stack_pages;
    const auto stack_base = VirtualAllocEx(process_.get(), nullptr, stack_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (stack_base == nullptr) {
        resume_threads(suspended_threads.value());
        return make_win32_error(L"VirtualAllocEx failed");
    }

    const auto stack_top = reinterpret_cast<std::uint64_t>(stack_base) + stack_size;
    const auto stack_pointer = ((stack_top - 0x80ull) & ~0xfull) - sizeof(std::uint64_t);

    std::unordered_set<std::uint64_t> seen_wrappers;
    auto guard_resolved = 0u;
    auto return_resolved = 0u;
    auto return_unresolved = 0u;
    auto helper_calls = 0u;
    auto continued_guard_faults = 0u;
    auto export_data_guard_steps = 0u;
    auto trapped_entry_faults = 0u;
    auto unexpected_exceptions = 0u;
    auto logged_unexpected = 0u;

    for (const auto wrapper_address : wrapper_addresses) {
        if (wrapper_address == 0 || !seen_wrappers.insert(wrapper_address).second) {
            continue;
        }

        const auto context_status =
            set_x64_wrapper_context(*this, executor_thread.get(), wrapper_address, stack_pointer);
        if (context_status.is_error()) {
            resume_threads(suspended_threads.value());
            return context_status;
        }

        const auto guard_status = arm_export_guards(*this, export_guard_pages);
        if (guard_status.is_error()) {
            resume_threads(suspended_threads.value());
            return guard_status;
        }

        if (ContinueDebugEvent(pending_debug_process_id_, pending_debug_thread_id_, DBG_CONTINUE) == FALSE) {
            resume_threads(suspended_threads.value());
            return make_win32_error(L"ContinueDebugEvent failed");
        }
        has_pending_debug_event_ = false;

        auto wrapper_done = false;
        auto pending_export_guard_rearm = false;
        for (auto event_index = 0u; event_index != wrapper_resolve_max_events && !wrapper_done; ++event_index) {
            DEBUG_EVENT event{};
            if (WaitForDebugEvent(&event, wrapper_resolve_timeout_ms) == FALSE) {
                const auto error = GetLastError();
                if (error == ERROR_SEM_TIMEOUT) {
                    resume_threads(suspended_threads.value());
                    return make_error(status_code::system_error, L"wrapper resolution timed out");
                }

                resume_threads(suspended_threads.value());
                return make_win32_error(L"WaitForDebugEvent failed", error);
            }

            auto continue_status = DBG_CONTINUE;
            if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                resume_threads(suspended_threads.value());
                return make_error(status_code::system_error, L"target exited while resolving import wrappers");
            }

            if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.dwProcessId == process_id_ &&
                event.dwThreadId == executor_thread_id) {
                const auto& exception = event.u.Exception.ExceptionRecord;
                const auto exception_code = exception.ExceptionCode;
                const auto exception_address =
                    reinterpret_cast<std::uint64_t>(exception.ExceptionAddress);
                auto fault_address = 0ull;
                if (exception.NumberParameters >= 2) {
                    fault_address = exception.ExceptionInformation[1];
                }

                if (exception_code == EXCEPTION_SINGLE_STEP && pending_export_guard_rearm) {
                    pending_export_guard_rearm = false;
                    const auto rearm_status = arm_export_guards(*this, export_guard_pages);
                    if (rearm_status.is_error()) {
                        resume_threads(suspended_threads.value());
                        return rearm_status;
                    }

                    if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) == FALSE) {
                        resume_threads(suspended_threads.value());
                        return make_win32_error(L"ContinueDebugEvent failed");
                    }
                    continue;
                }

                const auto export_hit_address = process_detail::exact_guarded_export_hit(
                    exception_address,
                    export_addresses);
                if (exception_code == status_guard_page_violation && export_hit_address.has_value()) {
                    const auto export_hit = export_by_address.find(*export_hit_address);
                    if (export_hit == export_by_address.end()) {
                        resume_threads(suspended_threads.value());
                        return make_error(status_code::system_error, L"guarded export lookup lost its export entry");
                    }

                    auto helper_status =
                        try_simulate_x64_wrapper_helper_api(*this, executor_thread.get(), export_hit->second->name);
                    if (helper_status.is_error()) {
                        resume_threads(suspended_threads.value());
                        return helper_status.error();
                    }

                    if (helper_status.value()) {
                        ++helper_calls;

                        const auto rearm_status = arm_export_guards(*this, export_guard_pages);
                        if (rearm_status.is_error()) {
                            resume_threads(suspended_threads.value());
                            return rearm_status;
                        }

                        if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) == FALSE) {
                            resume_threads(suspended_threads.value());
                            return make_win32_error(L"ContinueDebugEvent failed");
                        }
                        continue;
                    }

                    resolved.emplace(wrapper_address, *export_hit_address);
                    ++guard_resolved;
                    pending_debug_process_id_ = event.dwProcessId;
                    pending_debug_thread_id_ = event.dwThreadId;
                    pending_debug_continue_status_ = DBG_CONTINUE;
                    has_pending_debug_event_ = true;
                    wrapper_done = true;
                    break;
                }

                if (exception_code == status_guard_page_violation &&
                    process_detail::is_export_page_data_guard_fault(
                        exception_address,
                        fault_address,
                        export_guard_ranges)) {
                    const auto step_status = enable_x64_single_step(executor_thread.get());
                    if (step_status.is_error()) {
                        resume_threads(suspended_threads.value());
                        return step_status;
                    }

                    pending_export_guard_rearm = true;
                    ++export_data_guard_steps;
                    if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) == FALSE) {
                        resume_threads(suspended_threads.value());
                        return make_win32_error(L"ContinueDebugEvent failed");
                    }
                    continue;
                }

                if (exception_code == status_guard_page_violation &&
                    process_detail::is_non_export_wrapper_guard_fault(
                        exception_address,
                        fault_address,
                        export_guard_ranges)) {
                    ++continued_guard_faults;
                    if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) == FALSE) {
                        resume_threads(suspended_threads.value());
                        return make_win32_error(L"ContinueDebugEvent failed");
                    }
                    continue;
                }

                if (exception_code == EXCEPTION_ACCESS_VIOLATION &&
                    (exception_address == wrapper_magic_return || fault_address == wrapper_magic_return)) {
                    auto rax = current_x64_rax(executor_thread.get());
                    if (rax.is_error()) {
                        resume_threads(suspended_threads.value());
                        return rax.error();
                    }

                    if (export_by_address.find(rax.value()) != export_by_address.end()) {
                        resolved.emplace(wrapper_address, rax.value());
                        ++return_resolved;
                    } else {
                        ++return_unresolved;
                        if (verbose && logged_unexpected < 16u) {
                            std::wcerr << L"trace: wrapper returned unresolved rax wrapper=0x" << std::hex
                                       << wrapper_address << L" rax=0x" << rax.value() << std::dec << L"\n";
                            ++logged_unexpected;
                        }
                    }

                    pending_debug_process_id_ = event.dwProcessId;
                    pending_debug_thread_id_ = event.dwThreadId;
                    pending_debug_continue_status_ = DBG_CONTINUE;
                    has_pending_debug_event_ = true;
                    wrapper_done = true;
                    break;
                }

                if (process_detail::is_trapped_wrapper_entry_fault(
                        exception_code,
                        exception_address,
                        fault_address,
                        wrapper_address)) {
                    ++trapped_entry_faults;
                }

                ++unexpected_exceptions;
                if (verbose && logged_unexpected < 16u) {
                    std::wcerr << L"trace: wrapper unresolved exception wrapper=0x" << std::hex << wrapper_address
                               << L" code=0x" << exception_code << L" address=0x" << exception_address
                               << L" fault=0x" << fault_address << std::dec << L"\n";
                    ++logged_unexpected;
                }

                pending_debug_process_id_ = event.dwProcessId;
                pending_debug_thread_id_ = event.dwThreadId;
                pending_debug_continue_status_ = DBG_CONTINUE;
                has_pending_debug_event_ = true;
                wrapper_done = true;
                break;
            }

            if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status) == FALSE) {
                resume_threads(suspended_threads.value());
                return make_win32_error(L"ContinueDebugEvent failed");
            }
        }

        if (!wrapper_done || !has_pending_debug_event_) {
            resume_threads(suspended_threads.value());
            return make_error(status_code::system_error, L"wrapper resolution did not regain a pending debug event");
        }
    }

    resume_threads(suspended_threads.value());

    if (verbose) {
        std::wcerr << L"trace: wrapper resolver unique=" << seen_wrappers.size() << L" resolved=" << resolved.size()
                   << L" guard=" << guard_resolved << L" return=" << return_resolved
                   << L" return_unresolved=" << return_unresolved << L" helper_calls=" << helper_calls
                   << L" continued_guard_faults=" << continued_guard_faults
                   << L" export_data_guard_steps=" << export_data_guard_steps
                   << L" trapped_entry_faults=" << trapped_entry_faults << L" unexpected=" << unexpected_exceptions << L"\n";
    }

    return resolved;
}

result<std::vector<std::uint8_t>> debugged_process::read_memory(
    const std::uint64_t address,
    const std::size_t size) const {
    std::vector<std::uint8_t> bytes(size);
    if (size == 0) {
        return bytes;
    }

    const auto restore_status = temporarily_restore_expected_range(address, size);
    const auto had_trapped_overlap = restore_status.is_success();
    if (restore_status.is_error() && restore_status.code != status_code::invalid_argument) {
        return restore_status;
    }

    SIZE_T bytes_read = 0;
    const auto ok = ReadProcessMemory(
        process_.get(),
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
        bytes.data(),
        size,
        &bytes_read) != FALSE &&
        bytes_read == size;

    if (had_trapped_overlap) {
        const auto reprotect_status = reprotect_expected_ranges();
        if (reprotect_status.is_error()) {
            return reprotect_status;
        }
    }

    if (!ok) {
        return make_win32_error(L"ReadProcessMemory failed");
    }

    return bytes;
}

status debugged_process::write_memory(
    const std::uint64_t address,
    const std::span<const std::uint8_t> data) const {
    if (data.empty()) {
        return {};
    }

    const auto restore_status = temporarily_restore_expected_range(address, data.size());
    const auto had_trapped_overlap = restore_status.is_success();
    if (restore_status.is_error() && restore_status.code != status_code::invalid_argument) {
        return restore_status;
    }

    SIZE_T bytes_written = 0;
    const auto ok = WriteProcessMemory(
        process_.get(),
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
        data.data(),
        data.size(),
        &bytes_written) != FALSE &&
        bytes_written == data.size();

    FlushInstructionCache(process_.get(), reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), data.size());

    if (had_trapped_overlap) {
        const auto reprotect_status = reprotect_expected_ranges();
        if (reprotect_status.is_error()) {
            return reprotect_status;
        }
    }

    if (!ok) {
        return make_win32_error(L"WriteProcessMemory failed");
    }

    return {};
}

result<process_memory_range> debugged_process::query_memory(const std::uint64_t address) const {
    MEMORY_BASIC_INFORMATION memory_info{};
    if (VirtualQueryEx(
            process_.get(),
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            &memory_info,
            sizeof(memory_info)) == 0) {
        return make_win32_error(L"VirtualQueryEx failed");
    }

    return process_memory_range{
        .base = reinterpret_cast<std::uint64_t>(memory_info.BaseAddress),
        .size = memory_info.RegionSize,
        .protect = memory_info.Protect,
    };
}

status debugged_process::protect_memory(
    const std::uint64_t address,
    const std::size_t size,
    const std::uint32_t protect,
    std::uint32_t* const old_protect) const {
    DWORD old_value = 0;
    if (VirtualProtectEx(
            process_.get(),
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
            size,
            protect,
            &old_value) == FALSE) {
        return make_win32_error(L"VirtualProtectEx failed");
    }

    if (old_protect != nullptr) {
        *old_protect = old_value;
    }

    FlushInstructionCache(process_.get(), reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), size);
    return {};
}

result<std::uint64_t> debugged_process::allocate_near(
    const std::uint64_t near_address,
    const std::size_t size,
    const std::uint32_t protect) const {
    if (size == 0) {
        return make_error(status_code::invalid_argument, L"allocation size is zero");
    }

    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const auto granularity = static_cast<std::uint64_t>(system_info.dwAllocationGranularity);
    const auto aligned_near = near_address & ~(granularity - 1);
    constexpr auto window = 0x7fff0000ull;

    for (std::uint64_t delta = 0; delta <= window; delta += granularity) {
        const std::array<std::optional<std::uint64_t>, 2> candidates = {
            delta <= aligned_near ? std::optional<std::uint64_t>(aligned_near - delta) : std::nullopt,
            !add_overflows(aligned_near, delta) ? std::optional<std::uint64_t>(aligned_near + delta) : std::nullopt,
        };

        for (const auto candidate : candidates) {
            if (!candidate.has_value()) {
                continue;
            }

            const auto allocation = VirtualAllocEx(
                process_.get(),
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(*candidate)),
                size,
                MEM_RESERVE | MEM_COMMIT,
                protect);
            if (allocation != nullptr) {
                return reinterpret_cast<std::uint64_t>(allocation);
            }
        }
    }

    const auto fallback = VirtualAllocEx(process_.get(), nullptr, size, MEM_RESERVE | MEM_COMMIT, protect);
    if (fallback == nullptr) {
        return make_win32_error(L"VirtualAllocEx failed");
    }

    return reinterpret_cast<std::uint64_t>(fallback);
}

result<std::vector<module_info>> debugged_process::enumerate_modules() const {
    auto snapshot = unique_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id_));
    if (!snapshot) {
        auto fallback = enumerate_modules_by_memory(process_.get());
        if (fallback.is_success() && !fallback.value().empty()) {
            return fallback;
        }

        return make_win32_error(L"CreateToolhelp32Snapshot failed");
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    std::vector<module_info> modules;
    if (Module32FirstW(snapshot.get(), &entry) == FALSE) {
        const auto error = GetLastError();
        if (error == ERROR_NO_MORE_FILES) {
            return modules;
        }

        auto fallback = enumerate_modules_by_memory(process_.get());
        if (fallback.is_success() && !fallback.value().empty()) {
            return fallback;
        }

        return make_win32_error(L"Module32FirstW failed", error);
    }

    do {
        modules.push_back(module_info{
            .name = entry.szModule,
            .base = reinterpret_cast<std::uint64_t>(entry.modBaseAddr),
            .size = entry.modBaseSize,
        });
        entry.dwSize = sizeof(entry);
    } while (Module32NextW(snapshot.get(), &entry) != FALSE);

    return modules;
}

result<std::uint64_t> debugged_process::find_export(
    const std::wstring& module_name,
    const char* const export_name) const {
    if (export_name == nullptr || export_name[0] == '\0') {
        return make_error(status_code::invalid_argument, L"export name is empty");
    }

    auto module = find_module(*this, module_name);
    if (module.is_error()) {
        return module.error();
    }

    const auto base = module.value().base;
    const auto dos = read_remote_value<IMAGE_DOS_HEADER>(*this, base);
    if (dos.is_error()) {
        return dos.error();
    }

    if (dos.value().e_magic != IMAGE_DOS_SIGNATURE || dos.value().e_lfanew <= 0) {
        return make_error(status_code::system_error, L"module has an invalid DOS header");
    }

    const auto nt_base = base + static_cast<std::uint32_t>(dos.value().e_lfanew);
    const auto signature = read_remote_value<DWORD>(*this, nt_base);
    if (signature.is_error()) {
        return signature.error();
    }

    if (signature.value() != IMAGE_NT_SIGNATURE) {
        return make_error(status_code::system_error, L"module has an invalid NT header");
    }

    const auto optional_base = nt_base + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto magic = read_remote_value<WORD>(*this, optional_base);
    if (magic.is_error()) {
        return magic.error();
    }

    IMAGE_DATA_DIRECTORY export_directory{};
    if (magic.value() == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const auto optional = read_remote_value<IMAGE_OPTIONAL_HEADER32>(*this, optional_base);
        if (optional.is_error()) {
            return optional.error();
        }
        export_directory = optional.value().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else if (magic.value() == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto optional = read_remote_value<IMAGE_OPTIONAL_HEADER64>(*this, optional_base);
        if (optional.is_error()) {
            return optional.error();
        }
        export_directory = optional.value().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        return make_error(status_code::system_error, L"module has an unknown optional header");
    }

    if (export_directory.VirtualAddress == 0 || export_directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return make_error(status_code::invalid_argument, L"module has no export directory");
    }

    const auto exports = read_remote_value<IMAGE_EXPORT_DIRECTORY>(*this, base + export_directory.VirtualAddress);
    if (exports.is_error()) {
        return exports.error();
    }

    for (DWORD index = 0; index < exports.value().NumberOfNames; ++index) {
        const auto name_rva = read_remote_value<DWORD>(*this, base + exports.value().AddressOfNames + (index * sizeof(DWORD)));
        if (name_rva.is_error()) {
            return name_rva.error();
        }

        const auto name = read_remote_c_string(*this, base + name_rva.value());
        if (name.is_error()) {
            return name.error();
        }

        if (std::strcmp(name.value().c_str(), export_name) != 0) {
            continue;
        }

        const auto ordinal = read_remote_value<WORD>(
            *this,
            base + exports.value().AddressOfNameOrdinals + (index * sizeof(WORD)));
        if (ordinal.is_error()) {
            return ordinal.error();
        }

        if (ordinal.value() >= exports.value().NumberOfFunctions) {
            return make_error(status_code::system_error, L"export ordinal is outside the function table");
        }

        const auto function_rva = read_remote_value<DWORD>(
            *this,
            base + exports.value().AddressOfFunctions + (ordinal.value() * sizeof(DWORD)));
        if (function_rva.is_error()) {
            return function_rva.error();
        }

        return base + function_rva.value();
    }

    std::wstring wide_export_name;
    for (const auto* current = export_name; *current != '\0'; ++current) {
        wide_export_name.push_back(static_cast<wchar_t>(*current));
    }

    return make_error(status_code::invalid_argument, L"export was not found: " + wide_export_name);
}

result<std::vector<module_export>> debugged_process::enumerate_exports(const std::wstring& excluded_module_name) const {
    auto modules = enumerate_modules();
    if (modules.is_error()) {
        return modules.error();
    }

    struct forwarder_record {
        std::wstring module_name;
        std::string export_name;
        std::uint16_t ordinal = 0;
        bool has_ordinal = false;
        std::string target;
    };

    std::vector<module_export> exports_out;
    std::vector<forwarder_record> forwarders;
    std::unordered_map<std::wstring, std::uint64_t> direct_export_by_key;
    std::unordered_map<std::string, module_export> preferred_direct_export_by_name;

    for (const auto& module : modules.value()) {
        if (!excluded_module_name.empty() && module_name_matches(module.name, excluded_module_name)) {
            continue;
        }

        const auto base = module.base;
        const auto dos = read_remote_value<IMAGE_DOS_HEADER>(*this, base);
        if (dos.is_error() || dos.value().e_magic != IMAGE_DOS_SIGNATURE || dos.value().e_lfanew <= 0) {
            continue;
        }

        const auto nt_base = base + static_cast<std::uint32_t>(dos.value().e_lfanew);
        const auto signature = read_remote_value<DWORD>(*this, nt_base);
        if (signature.is_error() || signature.value() != IMAGE_NT_SIGNATURE) {
            continue;
        }

        const auto optional_base = nt_base + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        const auto magic = read_remote_value<WORD>(*this, optional_base);
        if (magic.is_error()) {
            continue;
        }

        IMAGE_DATA_DIRECTORY export_directory{};
        if (magic.value() == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto optional = read_remote_value<IMAGE_OPTIONAL_HEADER32>(*this, optional_base);
            if (optional.is_error()) {
                continue;
            }
            export_directory = optional.value().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else if (magic.value() == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const auto optional = read_remote_value<IMAGE_OPTIONAL_HEADER64>(*this, optional_base);
            if (optional.is_error()) {
                continue;
            }
            export_directory = optional.value().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else {
            continue;
        }

        if (export_directory.VirtualAddress == 0 || export_directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            continue;
        }

        const auto export_table = read_remote_value<IMAGE_EXPORT_DIRECTORY>(*this, base + export_directory.VirtualAddress);
        if (export_table.is_error()) {
            continue;
        }

        exports_out.reserve(exports_out.size() + export_table.value().NumberOfNames);
        for (DWORD index = 0; index < export_table.value().NumberOfNames; ++index) {
            const auto name_rva =
                read_remote_value<DWORD>(*this, base + export_table.value().AddressOfNames + (index * sizeof(DWORD)));
            const auto ordinal = read_remote_value<WORD>(
                *this,
                base + export_table.value().AddressOfNameOrdinals + (index * sizeof(WORD)));

            if (name_rva.is_error() || ordinal.is_error() || ordinal.value() >= export_table.value().NumberOfFunctions) {
                continue;
            }

            const auto function_rva = read_remote_value<DWORD>(
                *this,
                base + export_table.value().AddressOfFunctions + (ordinal.value() * sizeof(DWORD)));
            if (function_rva.is_error() || function_rva.value() == 0) {
                continue;
            }

            const auto name = read_remote_c_string(*this, base + name_rva.value());
            if (name.is_error() || name.value().empty()) {
                continue;
            }

            const auto function_rva_value = function_rva.value();
            const auto export_ordinal = static_cast<std::uint64_t>(export_table.value().Base) + ordinal.value();
            const auto has_import_ordinal = export_ordinal <= (std::numeric_limits<std::uint16_t>::max)();
            const auto export_begin = static_cast<std::uint64_t>(export_directory.VirtualAddress);
            const auto export_end = export_begin + export_directory.Size;
            if (function_rva_value >= export_begin && function_rva_value < export_end) {
                auto forwarder = read_remote_c_string(*this, base + function_rva_value);
                if (forwarder.is_success() && !forwarder.value().empty()) {
                    forwarders.push_back(forwarder_record{
                        .module_name = module.name,
                        .export_name = name.value(),
                        .ordinal = has_import_ordinal ? static_cast<std::uint16_t>(export_ordinal) : 0u,
                        .has_ordinal = has_import_ordinal,
                        .target = std::move(forwarder).value(),
                    });
                }

                continue;
            }

            const module_export symbol{
                .address = base + function_rva.value(),
                .module_name = module.name,
                .name = name.value(),
                .ordinal = has_import_ordinal ? static_cast<std::uint16_t>(export_ordinal) : 0u,
                .has_ordinal = has_import_ordinal,
            };

            exports_out.push_back(symbol);
            direct_export_by_key[export_lookup_key(symbol.module_name, symbol.name)] = symbol.address;

            auto by_name = preferred_direct_export_by_name.find(symbol.name);
            if (by_name == preferred_direct_export_by_name.end() || should_prefer_export_alias(symbol, by_name->second)) {
                preferred_direct_export_by_name[symbol.name] = symbol;
            }
        }
    }

    for (const auto& forwarder : forwarders) {
        const auto dot = forwarder.target.find('.');
        if (dot == std::string::npos || dot == 0u || dot + 1u >= forwarder.target.size()) {
            continue;
        }

        const auto target_module = widen_ascii(std::string_view(forwarder.target).substr(0u, dot));
        const auto target_name = forwarder.target.substr(dot + 1u);
        if (target_name.empty() || target_name.front() == '#') {
            continue;
        }

        auto target_address = std::optional<std::uint64_t>{};
        if (const auto exact = direct_export_by_key.find(export_lookup_key(target_module, target_name));
            exact != direct_export_by_key.end()) {
            target_address = exact->second;
        } else if (is_api_set_module_name(target_module)) {
            if (const auto by_name = preferred_direct_export_by_name.find(target_name);
                by_name != preferred_direct_export_by_name.end()) {
                target_address = by_name->second.address;
            }
        }

        if (!target_address.has_value()) {
            continue;
        }

        exports_out.push_back(module_export{
            .address = *target_address,
            .module_name = forwarder.module_name,
            .name = forwarder.export_name,
            .ordinal = forwarder.ordinal,
            .has_ordinal = forwarder.has_ordinal,
        });
    }

    return exports_out;
}

status debugged_process::set_expected_text_ranges(std::vector<memory_range> ranges) {
    const auto restore_status = restore_expected_ranges();
    if (restore_status.is_error()) {
        return restore_status;
    }

    expected_text_ranges_ = std::move(ranges);
    protected_ranges_.clear();

    for (const auto& range : expected_text_ranges_) {
        auto runtime_range = process_detail::resolve_runtime_range(range, image_base_);
        auto cursor = runtime_range.base;
        const auto end = saturating_end(runtime_range.base, runtime_range.size);

        while (cursor < end) {
            auto queried = query_memory(cursor);
            if (queried.is_error()) {
                restore_expected_ranges();
                return queried.error();
            }

            const auto region_end = saturating_end(queried.value().base, queried.value().size);
            const auto chunk_end = (std::min)(region_end, end);
            if (chunk_end <= cursor) {
                restore_expected_ranges();
                return make_error(status_code::system_error, L"memory query did not advance through expected range");
            }

            std::uint32_t old_protect = PAGE_NOACCESS;
            auto protect_status = protect_memory(cursor, static_cast<std::size_t>(chunk_end - cursor), PAGE_NOACCESS, &old_protect);
            if (protect_status.is_error()) {
                restore_expected_ranges();
                return protect_status;
            }

            protected_ranges_.push_back(protected_range{
                .base = cursor,
                .size = chunk_end - cursor,
                .original_protect = old_protect,
            });

            cursor = chunk_end;
        }
    }

    return {};
}

status debugged_process::reprotect_expected_ranges() const {
    for (const auto& range : protected_ranges_) {
        auto protect_status = protect_memory(range.base, static_cast<std::size_t>(range.size), PAGE_NOACCESS, nullptr);
        if (protect_status.is_error()) {
            return protect_status;
        }
    }

    return {};
}

status debugged_process::restore_expected_ranges() const {
    for (const auto& range : protected_ranges_) {
        auto protect_status = protect_memory(range.base, static_cast<std::size_t>(range.size), range.original_protect, nullptr);
        if (protect_status.is_error()) {
            return protect_status;
        }
    }

    return {};
}

status debugged_process::allow_expected_page_data_access(const std::uint64_t address) const {
    if (page_size_ == 0) {
        return make_error(status_code::system_error, L"process page size is unknown");
    }

    const auto page_size = static_cast<std::uint64_t>(page_size_);
    const auto page_base = address - (address % page_size);
    const auto page_end = saturating_end(page_base, page_size);

    for (const auto& range : protected_ranges_) {
        if (!process_memory_range{.base = range.base, .size = range.size, .protect = PAGE_NOACCESS}.contains(address)) {
            continue;
        }

        const auto range_end = saturating_end(range.base, range.size);
        const auto protect_base = (std::max)(page_base, range.base);
        const auto protect_end = (std::min)(page_end, range_end);
        if (protect_end <= protect_base) {
            return make_error(status_code::system_error, L"trapped page access produced an empty protection range");
        }

        return protect_memory(protect_base, static_cast<std::size_t>(protect_end - protect_base), PAGE_READWRITE, nullptr);
    }

    return make_error(status_code::invalid_argument, L"address is not inside a trapped range");
}

bool debugged_process::expected_ranges_contain(const std::uint64_t address) const noexcept {
    for (const auto& range : protected_ranges_) {
        if (process_memory_range{.base = range.base, .size = range.size, .protect = PAGE_NOACCESS}.contains(address)) {
            return true;
        }
    }

    return false;
}

status debugged_process::temporarily_restore_expected_range(const std::uint64_t address, const std::size_t size) const {
    auto restored_any = false;
    for (const auto& range : protected_ranges_) {
        if (!ranges_overlap(range.base, range.size, address, size)) {
            continue;
        }

        auto protect_status = protect_memory(range.base, static_cast<std::size_t>(range.size), range.original_protect, nullptr);
        if (protect_status.is_error()) {
            if (restored_any) {
                reprotect_expected_ranges();
            }
            return protect_status;
        }

        restored_any = true;
    }

    if (!restored_any) {
        return make_error(status_code::invalid_argument, L"address is not inside a trapped range");
    }

    return {};
}

result<oep_trace_result> trace_oep(const oep_trace_options& options, debugged_process* const out_process) {
    if (options.target_path.empty()) {
        return make_error(status_code::invalid_argument, L"target path is empty");
    }

    if (options.expected_text_ranges.empty()) {
        return make_error(status_code::invalid_argument, L"expected text ranges are empty");
    }

    const auto target_module_name = process_detail::target_module_name(options.target_path);
    const auto dll_target = process_detail::is_dll_target(options.target_path);

    auto spawned = debugged_process::spawn_suspended_or_debugged(options.target_path);
    if (spawned.is_error()) {
        return spawned.error();
    }

    auto process = std::move(spawned).value();
    auto expected_ranges_armed = false;
    auto pending_reprotect_thread = std::optional<DWORD>{};
    const auto started = GetTickCount64();

    if (options.verbose) {
        std::wcerr << L"trace: waiting for debug events, ranges=" << options.expected_text_ranges.size() << L"\n";
    }

    for (;;) {
        if (timeout_expired(started, options.timeout_seconds)) {
            process.terminate();
            return make_error(status_code::system_error, L"OEP trace timed out");
        }

        DEBUG_EVENT event{};
        const auto wait_ms = debug_wait_slice(started, options.timeout_seconds);
        if (WaitForDebugEvent(&event, wait_ms) == FALSE) {
            const auto error = GetLastError();
            if (error == ERROR_SEM_TIMEOUT) {
                continue;
            }

            process.terminate();
            return make_win32_error(L"WaitForDebugEvent failed", error);
        }

        auto continue_status = DBG_CONTINUE;
        auto continue_event = true;

        if (expected_ranges_armed && !pending_reprotect_thread.has_value()) {
            auto reprotect_status = process.reprotect_expected_ranges();
            if (reprotect_status.is_error()) {
                process.terminate();
                return reprotect_status;
            }
        }

        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            unique_handle file(event.u.CreateProcessInfo.hFile);
            const auto image_base = reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);

            if (!dll_target) {
                process.image_base_ = image_base;
                process.main_module_name_ = target_module_name;
                const auto architecture = detect_process_architecture(process.process_handle(), image_base);
                process.architecture_ = architecture.architecture;
                process.pointer_size_ = architecture.pointer_size;

                if (options.verbose) {
                    std::wcerr << L"trace: main image base=0x" << std::hex << image_base << std::dec
                               << L" pointer_size=" << process.pointer_size() << L"\n";
                    for (const auto& range : options.expected_text_ranges) {
                        std::wcerr << L"trace: expected range rva=0x" << std::hex << range.base << L" size=0x"
                                   << range.size << std::dec << L"\n";
                    }
                }

                auto anti_debug_status = mask_initial_debugger_state(process);
                if (anti_debug_status.is_error()) {
                    process.terminate();
                    return anti_debug_status;
                }

                auto protect_status = process.set_expected_text_ranges(options.expected_text_ranges);
                if (protect_status.is_error()) {
                    process.terminate();
                    return protect_status;
                }

                auto rearm_status = install_nt_protect_virtual_memory_rearm(process, options.expected_text_ranges);
                if (rearm_status.is_error()) {
                    process.terminate();
                    return rearm_status;
                }

                expected_ranges_armed = true;
            }
            break;
        }

        case LOAD_DLL_DEBUG_EVENT: {
            unique_handle file(event.u.LoadDll.hFile);
            if (!dll_target) {
                break;
            }

            const auto loaded_module_name = file_name_from_handle(file.get());
            if (!loaded_module_name.empty() && iequals(loaded_module_name, target_module_name)) {
                const auto image_base = reinterpret_cast<std::uint64_t>(event.u.LoadDll.lpBaseOfDll);
                process.image_base_ = image_base;
                process.main_module_name_ = target_module_name;
                const auto architecture = detect_process_architecture(process.process_handle(), image_base);
                process.architecture_ = architecture.architecture;
                process.pointer_size_ = architecture.pointer_size;

                if (options.verbose) {
                    std::wcerr << L"trace: dll image base=0x" << std::hex << image_base << std::dec
                               << L" pointer_size=" << process.pointer_size() << L"\n";
                }

                auto anti_debug_status = mask_initial_debugger_state(process);
                if (anti_debug_status.is_error()) {
                    process.terminate();
                    return anti_debug_status;
                }

                auto protect_status = process.set_expected_text_ranges(options.expected_text_ranges);
                if (protect_status.is_error()) {
                    process.terminate();
                    return protect_status;
                }

                auto rearm_status = install_nt_protect_virtual_memory_rearm(process, options.expected_text_ranges);
                if (rearm_status.is_error()) {
                    process.terminate();
                    return rearm_status;
                }

                expected_ranges_armed = true;
            }
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            const auto exception_code = event.u.Exception.ExceptionRecord.ExceptionCode;

            if (exception_code == EXCEPTION_SINGLE_STEP && pending_reprotect_thread == event.dwThreadId) {
                auto protect_status = process.reprotect_expected_ranges();
                if (protect_status.is_error()) {
                    process.terminate();
                    return protect_status;
                }

                pending_reprotect_thread.reset();
                continue_status = DBG_CONTINUE;
                break;
            }

            if (exception_code == EXCEPTION_ACCESS_VIOLATION && expected_ranges_armed) {
                auto action = handle_access_violation(process, event, pending_reprotect_thread, options.verbose);
                if (action.is_error()) {
                    process.terminate();
                    return action.error();
                }

                if (action.value() == access_violation_action::continue_after_single_step) {
                    continue_status = DBG_CONTINUE;
                    break;
                }

                if (action.value() == access_violation_action::continue_after_context_update) {
                    continue_status = DBG_CONTINUE;
                    break;
                }

                if (action.value() == access_violation_action::found_oep) {
                    const auto restore_status = process.restore_expected_ranges();
                    if (restore_status.is_error()) {
                        process.terminate();
                        return restore_status;
                    }

                    const auto exception_address =
                        reinterpret_cast<std::uint64_t>(event.u.Exception.ExceptionRecord.ExceptionAddress);

                    oep_trace_result result{
                        .process_id = process.process_id(),
                        .main_module_name = process.main_module_name(),
                        .architecture = process.architecture(),
                        .pointer_size = process.pointer_size(),
                        .page_size = process.page_size(),
                        .image_base = process.image_base(),
                        .oep_va = exception_address,
                        .is_dotnet = is_dotnet_loaded(process),
                    };

                    if (out_process != nullptr) {
                        process.has_pending_debug_event_ = true;
                        process.pending_debug_process_id_ = event.dwProcessId;
                        process.pending_debug_thread_id_ = event.dwThreadId;
                        process.pending_debug_continue_status_ = DBG_CONTINUE;
                        *out_process = std::move(process);
                        return result;
                    }

                    const auto cleanup_status = cleanup_after_trace(process, event, DBG_CONTINUE);
                    if (cleanup_status.is_error()) {
                        process.terminate();
                        return cleanup_status;
                    }

                    return result;
                }
            }

            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            process.terminate();
            return make_error(status_code::system_error, L"target exited before OEP was reached");

        default:
            break;
        }

        if (continue_event) {
            if (ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status) == FALSE) {
                process.terminate();
                return make_win32_error(L"ContinueDebugEvent failed");
            }
        }
    }
}

} // namespace demida
