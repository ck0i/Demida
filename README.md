# Demida

Demida is a native C++20 Windows unpacker for Themida and WinLicense protected Portable Executable (PE) files. It is not a purely static unpacker. Demida starts the target under the Windows debugger, allows the protector to execute until control reaches the Original Entry Point (OEP), captures the mapped image at that boundary, and then rebuilds a cleaner PE file from the runtime state.

The result is a runtime unpack followed by static reconstruction. The protected wrapper executes far enough to unpack, decrypt, resolve runtime state, and transfer toward the original program. The original application does not run normally by default, because Demida traps the first transfer into the original code range and dumps before normal startup continues.

## Execution Model

Demida uses debug event tracing rather than offline file emulation. The target process is created with Windows debug flags, and Demida monitors process creation, module loading, exceptions, and memory protection changes. It arms the expected original text ranges so the first attempted execution inside the restored original code is treated as the OEP boundary.

This means the following code can run before the dump:

- The Windows loader path for the target process.
- Themida or WinLicense loader code.
- Protector unpack, decrypt, relocation, and import setup logic.
- Protector checks that execute before the OEP boundary.
- Thread Local Storage (TLS) callbacks when the protected startup path invokes them before OEP.

This code does not run by default after Demida identifies the OEP:

- The original OEP instruction stream after the trap.
- C runtime startup reached from the original entry point.
- Static constructors reached through normal runtime startup.
- `main`, `WinMain`, or equivalent application entry logic.
- Application owned protection checks that only execute after original startup begins.

`--pause-on-oep` changes the operator workflow by pausing at the OEP before dumping. It does not turn Demida into a normal launcher; it gives the researcher a controlled inspection point at the same boundary.

## Capabilities

- Detects Themida and WinLicense 2.x and 3.x layouts used by the current source logic.
- Traces the OEP through Win32 debug events.
- Masks initial debugger state during tracing.
- Protects expected original text ranges and identifies early transfer back into original code.
- Handles TLS callback shaped control flow during process tracing.
- Dumps the mapped runtime image after the protector has unpacked it.
- Rebuilds PE headers, section layout, entry point metadata, checksum state, and image base metadata.
- Clears relocation metadata and disables Address Space Layout Randomization (ASLR) in rebuilt output.
- Recovers runtime directories from the mapped image, including export, resource, exception, debug, TLS, load configuration, Import Address Table (IAT), and delay import directories when the evidence is present.
- Rewrites debug directory raw file pointers to match the rebuilt file layout.
- Recovers Themida and WinLicense 2.x wrapper imports and patches wrapper call sites.
- Recovers Themida and WinLicense 3.x IAT based imports and emits rebuilt import descriptors.
- Preserves ordinal imports for known ordinal based Automation functions in `oleaut32.dll`.
- Removes stale Themida section headers after import recovery while preserving live directories.
- Names recovered sections by role where the rebuilt image proves the role: `.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `.rsrc`, `.reloc`, and `.idata`.
- Writes a best effort dump by default when import recovery fails, unless strict import recovery is requested.

## Non Goals

Demida does not devirtualize protected functions, reconstruct original compiler level control flow, restore original symbols, or guarantee byte identical output. It aims to make Themida and WinLicense protections ineffective for practical reverse engineering by producing a runnable and analyzable unpacked image with restored headers, imports, directories, and section structure.

Demida does not currently allow the original application to execute to completion as part of normal unpacking. Running past the OEP is a different workflow because it executes application code and can trigger application owned startup checks.

## Current Limitations

- Import recovery remains heuristic and version specific.
- Some 3.x wrappers require deeper per slot execution tracing on heavily protected samples.
- Managed images are dumped without native import reconstruction.
- Debugging hostile targets can still detect or react to process debugging before Demida reaches OEP.
- Broad corpus validation is still required across Themida and WinLicense versions.

## Build

Run the commands from a Visual Studio 2022 Developer Command Prompt.

Ninja:

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Visual Studio generator:

```bat
cmake -S . -B build-vs -G "Visual Studio 17 2022" -A x64
cmake --build build-vs --config Release
```

The main executable target is `demida`, which produces `demida.exe`.

## Usage

```bat
demida.exe [options] <target-pe>
```

Options:

- `--help` shows usage text.
- `--verbose` enables trace logging.
- `--pause-on-oep` pauses when the OEP is reached so the process can be inspected before dumping.
- `--no-imports` skips import reconstruction for the run.
- `--strict-imports` makes import reconstruction failures fatal instead of writing a best effort dump.
- `--target-version <2|3>` selects the Themida or WinLicense major version when automatic detection is not enough.
- `--force-oep <rva>` forces the OEP relative virtual address. Hex and decimal values are accepted.
- `--timeout <seconds>` sets the process control timeout. The default is 30 seconds.
- `--output <path>` sets the output path for the rebuilt PE.

Example:

```bat
demida.exe --target-version 3 --timeout 60 --output unpacked_sample.exe sample.exe
```

## Output

When no output path is provided, Demida writes `unpacked_<input name>` in the current working directory. On success, the tool prints the rebuilt path, detected Themida or WinLicense version, image base, OEP, and import recovery status.

The rebuilt image is serialized from the debugged process mapping through a cleaned PE layout. Demida patches the entry point, clears the checksum, strips relocation metadata, disables ASLR, recovers runtime directories, rewrites debug raw pointers, rebuilds imports when possible, and removes stale Themida section headers after import recovery.

Import recovery is best effort unless `--strict-imports` is used. If recovery fails in non strict mode, Demida writes the rebuilt runtime dump and reports the import error.

## Repository Layout

- `CMakeLists.txt` defines the `Demida` project, `demida` executable, and `demida_core` library.
- `include/demida/` contains public headers under the `demida` namespace.
- `src/` contains the command line frontend, PE handling, process tracing, import recovery, and unpacker pipeline.

## License

Demida is released under the MIT License. See `LICENSE` for details.
