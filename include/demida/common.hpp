#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <cstdint>
#include <type_traits>
#include <utility>
#include <variant>
#include <string>

#if defined(_MSC_VER)
#define DEMIDA_FORCE_INLINE __forceinline
#define DEMIDA_NO_INLINE __declspec(noinline)
#define DEMIDA_TRIVIAL_ABI
#elif defined(__clang__)
#define DEMIDA_FORCE_INLINE __attribute__((always_inline)) inline
#define DEMIDA_NO_INLINE __attribute__((noinline))
#define DEMIDA_TRIVIAL_ABI [[clang::trivial_abi]]
#else
#define DEMIDA_FORCE_INLINE inline
#define DEMIDA_NO_INLINE
#define DEMIDA_TRIVIAL_ABI
#endif

namespace demida {

enum class arch : std::uint8_t {
    unknown = 0,
    x86 = 1,
    x64 = 2,
};

enum class log_level : std::uint8_t {
    quiet = 0,
    info = 1,
    verbose = 2,
};

enum class status_code : std::uint8_t {
    ok = 0,
    invalid_argument = 1,
    unsupported_version = 2,
    system_error = 3,
    not_implemented = 4,
};

struct status {
    status_code code = status_code::ok;
    std::wstring message;

    DEMIDA_FORCE_INLINE constexpr bool is_success() const noexcept {
        return code == status_code::ok;
    }

    DEMIDA_FORCE_INLINE constexpr bool is_error() const noexcept {
        return code != status_code::ok;
    }
};

template <typename value_type>
class result {
public:
    result(const value_type& value) : storage_(value) {
    }

    result(value_type&& value) noexcept(std::is_nothrow_move_constructible_v<value_type>) : storage_(std::move(value)) {
    }

    result(const status& error) : storage_(error) {
    }

    result(status&& error) noexcept : storage_(std::move(error)) {
    }

    DEMIDA_FORCE_INLINE bool is_success() const noexcept {
        return std::holds_alternative<value_type>(storage_);
    }

    DEMIDA_FORCE_INLINE bool is_error() const noexcept {
        return !is_success();
    }

    DEMIDA_FORCE_INLINE value_type& value() & noexcept {
        return std::get<value_type>(storage_);
    }

    DEMIDA_FORCE_INLINE const value_type& value() const& noexcept {
        return std::get<value_type>(storage_);
    }

    DEMIDA_FORCE_INLINE value_type&& value() && noexcept {
        return std::move(std::get<value_type>(storage_));
    }

    DEMIDA_FORCE_INLINE status& error() & noexcept {
        return std::get<status>(storage_);
    }

    DEMIDA_FORCE_INLINE const status& error() const& noexcept {
        return std::get<status>(storage_);
    }

private:
    std::variant<value_type, status> storage_;
};

class DEMIDA_TRIVIAL_ABI unique_handle {
public:
    unique_handle() = default;

    explicit unique_handle(HANDLE handle) noexcept : handle_(handle) {
    }

    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;

    unique_handle(unique_handle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {
    }

    unique_handle& operator=(unique_handle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.handle_, nullptr));
        }

        return *this;
    }

    ~unique_handle() {
        reset();
    }

    DEMIDA_FORCE_INLINE HANDLE get() const noexcept {
        return handle_;
    }

    DEMIDA_FORCE_INLINE explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    DEMIDA_FORCE_INLINE HANDLE release() noexcept {
        return std::exchange(handle_, nullptr);
    }

    void reset(HANDLE handle = nullptr) noexcept {
        const auto old_handle = std::exchange(handle_, handle);
        if (old_handle != nullptr && old_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(old_handle);
        }
    }

private:
    HANDLE handle_ = nullptr;
};

} // namespace demida
