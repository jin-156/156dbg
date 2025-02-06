# 156dbg\_Debugger for ELF

## Overview

- **Programming Language**: C
- **Key Technologies**: ptrace, parsing ELF
- **Version**: 1.0
- **Main Features**: Breakpoints, resume execution, etc.
- **Architecture**: x86-64

## Build Command

1. Give execute permission to the `build.sh` script:

   ```bash
   chmod 777 build.sh
   ```

2. Execute the `build.sh` script:

   ```bash
   ./build.sh
   ```

## Basic Usage

To use the debugger, run:

```bash
156dbg <file path>
```

## Version History

### Ver 1.0

- Developed basic execution flow-related features
  - `ni` (next instruction): Execute the next instruction
  - `si` (step instruction): Execute step by step
  - `breakpoint`: Set and manage breakpoints
  - `continue`: Resume paused execution
  - `start`: Start program execution

### Ver 1.1

- Added process protection technique checks
- Fixed `no pie` process error

