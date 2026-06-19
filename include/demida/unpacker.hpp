#pragma once

#include <demida/cli.hpp>
#include <demida/common.hpp>

#include <cstdint>
#include <string>

namespace demida {

struct unpack_result {
    std::wstring output_path;
    std::uint32_t target_version = 0;
    std::uint64_t image_base = 0;
    std::uint64_t oep_va = 0;
    std::uint32_t import_count = 0;
    bool is_dotnet = false;
    bool import_recovery_failed = false;
    std::wstring import_error_message;
};

result<unpack_result> run_unpacker(const cli_options& options);

} // namespace demida
