#include <demida/cli.hpp>
#include <demida/unpacker.hpp>

#include <Windows.h>

#include <iostream>
#include <string_view>
#include <vector>

namespace {

std::vector<std::wstring_view> command_line_args(int argc, wchar_t** argv) {
    std::vector<std::wstring_view> args;
    args.reserve(static_cast<std::size_t>(argc));

    for (auto index = 0; index < argc; ++index) {
        args.emplace_back(argv[index]);
    }

    return args;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const auto args = command_line_args(argc, argv);
    const auto parsed = demida::parse_cli(args);

    if (parsed.is_error()) {
        std::wcerr << L"error: " << parsed.error().message << L"\n\n";
        std::wcerr << demida::cli_usage(argc > 0 ? argv[0] : L"demida.exe");
        return 1;
    }

    const auto& options = parsed.value();
    if (options.help) {
        std::wcout << demida::cli_usage(argc > 0 ? argv[0] : L"demida.exe");
        return 0;
    }

    auto unpacked = demida::run_unpacker(options);
    if (unpacked.is_error()) {
        std::wcerr << L"error: " << unpacked.error().message << L"\n";
        return 2;
    }

    std::wcout << L"unpacked: " << unpacked.value().output_path << L"\n";
    std::wcout << L"version: Themida/WinLicense " << unpacked.value().target_version << L".x\n";
    std::wcout << L"image base: 0x" << std::hex << unpacked.value().image_base << L"\n";
    std::wcout << L"oep: 0x" << unpacked.value().oep_va << std::dec << L"\n";
    if (unpacked.value().is_dotnet) {
        std::wcout << L"mode: .NET image dump\n";
    } else if (options.no_imports) {
        std::wcout << L"imports: skipped\n";
    } else if (unpacked.value().import_recovery_failed) {
        std::wcout << L"imports: best-effort failed";
        if (!unpacked.value().import_error_message.empty()) {
            std::wcout << L" (" << unpacked.value().import_error_message << L")";
        }
        std::wcout << L"\n";
    } else {
        std::wcout << L"imports: " << unpacked.value().import_count << L"\n";
    }
    return 0;
}
