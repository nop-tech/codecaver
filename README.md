# CodeCaver

A WinDbg extension that scans loaded modules for code caves within executable memory.

You can read a more detailed explanation over here on my blog: [nopblog/codecaver](https://nop-blog.tech/posts/codecaver).

## What Are Code Caves?

Code caves are regions of unused space within a module's executable memory. These are typically padding bytes inserted by the compiler/linker and can be identified by repeating patterns of:

| Byte   | Name    | Description                     |
|--------|---------|---------------------------------|
| `0x90` | NOP     | No-operation instruction        |
| `0xCC` | INT3    | Software breakpoint instruction |
| `0x00` | PADDING | Null padding bytes              |

These regions are particular useful for storing shellcode when exploiting an application.

## Features

- Scans any loaded module by name
- Detects NOP, INT3, and NULL padding caves
- Configurable minimum cave size (hex or decimal)
- Reports memory protection for each cave (e.g. `PAGE_EXECUTE_READ`)
- Efficient page-by-page scanning with automatic skipping of non-executable regions
- Supports both 32-bit and 64-bit targets

## Usage

Load the extension in WinDbg:

```
.load codecaver
```

Search for code caves by using the following command:
```
!cave <module_name> [min_size]    Scan a module for code caves
!cave -h                          Show detailed help
```

### Parameters

| Parameter     | Description                                              | Default  |
|---------------|----------------------------------------------------------|----------|
| `module_name` | Name of the loaded module (e.g. `kernel32`, `ntdll`)     | Required |
| `min_size`    | Minimum cave size in bytes, supports hex (`0x100`) or decimal (`256`) | `0x40` (64 bytes) |

### Examples

```
!cave kernel32              Scan kernel32 with default min size (64 bytes)
!cave ntdll 0x100           Scan ntdll for caves >= 256 bytes
!cave myapp 10            Scan myapp for caves >= 10 bytes
```

### Sample Output

```
0:000> !cave ch 0x10

Found 5 code cave(s):

START ADDRESS       END ADDRESS         SIZE        PATTERN     PROTECTION               
------------------  ------------------  ----------  ----------  -------------------------
0x00007ff7a62e2b56  0x00007ff7a62e2b65  0x10        INT3        PAGE_EXECUTE_READ        
0x00007ff7a62e50a5  0x00007ff7a62e50b5  0x11        INT3        PAGE_EXECUTE_READ        
0x00007ff7a62fc136  0x00007ff7a62fc145  0x10        INT3        PAGE_EXECUTE_READ        
0x00007ff7a62fc791  0x00007ff7a62fc7a5  0x15        INT3        PAGE_EXECUTE_READ        
0x00007ff7a62fd6f6  0x00007ff7a62fdfff  0x90a       PADDING     PAGE_EXECUTE_READ     
```

## Building

### Requirements

- Visual Studio 2017 or later
- Windows SDK (included with Visual Studio)

### Build from Visual Studio

1. Open `codecaver.sln`
2. Select a configuration: `Debug` or `Release`
3. Select a platform: `x86` or `x64`
4. Build the solution (`Ctrl+Shift+B`)

### Build from Command Line

```
msbuild codecaver.sln /p:Configuration=Release /p:Platform=x64
```

### Output

The build produces `codecaver.dll` which can be loaded directly into WinDbg.

## Loading The Extension

Copy the built `codecaver.dll` to one of the following locations:

- The `winext` subdirectory inside the WinDbg installation directory
- A directory in the debugger's extension search path
- Any directory, then load explicitly with `.load <full_path_to_dll>`

**Note:** Match the DLL architecture (x86/x64) to the target being debugged.



## Author

Created by **nop** ([@thenopcode](https://github.com/nop-tech))
