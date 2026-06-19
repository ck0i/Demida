#include <demida/cli.hpp>

#include <cwctype>
#include <limits>

namespace demida {
namespace {

status make_error(const status_code code, std::wstring message) {
    return status{code, std::move(message)};
}

bool is_option(const std::wstring_view arg) noexcept {
    return arg.size() > 2 && arg[0] == L'-' && arg[1] == L'-';
}

result<std::uint32_t> parse_u32(const std::wstring_view text, const std::wstring_view option_name) {
    if (text.empty()) {
        return make_error(status_code::invalid_argument, std::wstring(option_name) + L" requires a numeric value");
    }

    auto radix = 10u;
    std::size_t index = 0;

    if (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        radix = 16u;
        index = 2;
    }

    if (index == text.size()) {
        return make_error(status_code::invalid_argument, std::wstring(option_name) + L" has no digits");
    }

    std::uint64_t value = 0;
    for (; index < text.size(); ++index) {
        const auto ch = text[index];
        std::uint32_t digit = 0;

        if (ch >= L'0' && ch <= L'9') {
            digit = static_cast<std::uint32_t>(ch - L'0');
        } else if (radix == 16u && ch >= L'a' && ch <= L'f') {
            digit = static_cast<std::uint32_t>((ch - L'a') + 10);
        } else if (radix == 16u && ch >= L'A' && ch <= L'F') {
            digit = static_cast<std::uint32_t>((ch - L'A') + 10);
        } else {
            return make_error(status_code::invalid_argument, std::wstring(option_name) + L" contains invalid digits");
        }

        if (digit >= radix) {
            return make_error(status_code::invalid_argument, std::wstring(option_name) + L" contains invalid digits");
        }

        value = (value * radix) + digit;
        if (value > std::numeric_limits<std::uint32_t>::max()) {
            return make_error(status_code::invalid_argument, std::wstring(option_name) + L" is too large");
        }
    }

    return static_cast<std::uint32_t>(value);
}

result<std::wstring_view> read_option_value(
    const std::vector<std::wstring_view>& args,
    const std::size_t index,
    const std::wstring_view option_name) {
    if (index + 1 >= args.size()) {
        return make_error(status_code::invalid_argument, std::wstring(option_name) + L" requires a value");
    }

    const auto value = args[index + 1];
    if (is_option(value)) {
        return make_error(status_code::invalid_argument, std::wstring(option_name) + L" requires a value");
    }

    return value;
}

} // namespace

std::wstring cli_usage(const std::wstring_view executable_name) {
    std::wstring usage;
    usage += L"usage: ";
    usage += executable_name.empty() ? L"demida.exe" : executable_name;
    usage += L" [options] <target-pe>\n\n";
    usage += L"options:\n";
    usage += L"  --help                   Show this help text.\n";
    usage += L"  --verbose                Enable verbose logging.\n";
    usage += L"  --pause-on-oep           Pause when the original entry point is reached.\n";
    usage += L"  --no-imports             Skip import reconstruction in this run.\n";
    usage += L"  --strict-imports         Fail the run if import reconstruction fails.\n";
    usage += L"  --force-oep <rva>        Force original entry point RVA, hex or decimal.\n";
    usage += L"  --target-version <2|3>   Themida/WinLicense major version.\n";
    usage += L"  --timeout <seconds>      Process-control timeout, default 30.\n";
    usage += L"  --output <path>          Output path for the rebuilt PE.\n";
    return usage;
}

result<cli_options> parse_cli(const std::vector<std::wstring_view>& args) {
    cli_options options;

    auto positional_count = 0u;

    for (std::size_t index = 1; index < args.size(); ++index) {
        const auto arg = args[index];

        if (arg == L"--help") {
            options.help = true;
            continue;
        }

        if (arg == L"--verbose") {
            options.verbose = true;
            continue;
        }

        if (arg == L"--pause-on-oep") {
            options.pause_on_oep = true;
            continue;
        }

        if (arg == L"--no-imports") {
            options.no_imports = true;
            continue;
        }

        if (arg == L"--strict-imports") {
            options.strict_imports = true;
            continue;
        }

        if (arg == L"--force-oep") {
            const auto value_arg = read_option_value(args, index, arg);
            if (value_arg.is_error()) {
                return value_arg.error();
            }

            auto parsed = parse_u32(value_arg.value(), arg);
            if (parsed.is_error()) {
                return parsed.error();
            }

            options.force_oep = parsed.value();
            ++index;
            continue;
        }

        if (arg == L"--target-version") {
            const auto value_arg = read_option_value(args, index, arg);
            if (value_arg.is_error()) {
                return value_arg.error();
            }

            auto parsed = parse_u32(value_arg.value(), arg);
            if (parsed.is_error()) {
                return parsed.error();
            }

            const auto version = parsed.value();
            if (version != 2u && version != 3u) {
                return make_error(status_code::unsupported_version, L"--target-version must be 2 or 3");
            }

            options.target_version = version;
            ++index;
            continue;
        }

        if (arg == L"--timeout") {
            const auto value_arg = read_option_value(args, index, arg);
            if (value_arg.is_error()) {
                return value_arg.error();
            }

            auto parsed = parse_u32(value_arg.value(), arg);
            if (parsed.is_error()) {
                return parsed.error();
            }

            options.timeout_seconds = parsed.value();
            ++index;
            continue;
        }

        if (arg == L"--output") {
            const auto value_arg = read_option_value(args, index, arg);
            if (value_arg.is_error()) {
                return value_arg.error();
            }

            options.output_path = std::wstring(value_arg.value());
            ++index;
            continue;
        }

        if (is_option(arg)) {
            return make_error(status_code::invalid_argument, L"unknown option: " + std::wstring(arg));
        }

        if (positional_count != 0u) {
            return make_error(status_code::invalid_argument, L"only one target PE path can be provided");
        }

        options.target_path = std::wstring(arg);
        ++positional_count;
    }

    if (!options.help && options.target_path.empty()) {
        return make_error(status_code::invalid_argument, L"missing target PE path");
    }

    return options;
}

} // namespace demida
