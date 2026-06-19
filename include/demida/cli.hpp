#pragma once

#include <demida/common.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace demida {

struct cli_options {
    std::wstring target_path;
    std::wstring output_path;
    bool help = false;
    bool verbose = false;
    bool pause_on_oep = false;
    bool no_imports = false;
    bool strict_imports = false;
    std::optional<std::uint32_t> force_oep;
    std::optional<std::uint32_t> target_version;
    std::uint32_t timeout_seconds = 30;
};

result<cli_options> parse_cli(const std::vector<std::wstring_view>& args);
std::wstring cli_usage(std::wstring_view executable_name);

} // namespace demida
