# rdb: Rust Debugger

A source-level debugger for Linux x86_64 written in Rust, based on [sdb](https://github.com/TartanLlama/sdb).

## Features

- Source-level debugging with accurate line information
- Function and line breakpoints
- Step into/over/out operations
- Inline frame support
- Syscall catching
- Register and memory inspection
- Disassembly view
- Process launch and attach

## Quick Start

### Build

```bash
cargo build --release
```

### Launch a Program

```bash
./target/release/rdb ./your_program
```

### Attach to Running Process

```bash
$ ./target/release/rdb -p <PID>
```

## Usage

### Commands

```
break (b)     - Set/manage breakpoints
cont (c)      - Continue execution
step (s)      - Step into functions
next (n)      - Step over functions
finish        - Step out of current function
stepi         - Step one instruction
reg           - Show/modify registers
mem           - Read/write memory
dis           - Disassemble instructions
catch         - Catch syscalls
watch         - Set watchpoints
help          - Show help
```

### Setting Breakpoints

```bash
# Function breakpoint
rdb> break set main

# Line breakpoint
rdb> break set file.rs:15

# Address breakpoint
rdb> break set 0x401000

# List breakpoints
rdb> break list
```

### Example Session

```bash
# Compile with debug info
$ rustc -g example.rs

# Launch debugger
$ ./target/release/rdb ./example

# Debug session
rdb> break set main
rdb> cont              # Continue to breakpoint
rdb> step              # Step into function
rdb> next              # Step over line
rdb> reg               # Show registers
rdb> finish            # Step out
rdb> cont              # Continue
```

## Manual Testing

Compile the demo program:
```bash
rustc -g test_programs/demo.rs -o target/test_bins/demo
```

Launch and test:
```bash
./target/release/rdb target/test_bins/demo

# Basic workflow
rdb> break set calculate
rdb> cont                    # Stops at calculate function
rdb> step                    # Steps into add function
rdb> next                    # Steps over println
rdb> cont                    # Continues to exit
```

### Test Scenarios

**Function breakpoints:**
```bash
rdb> break set add
rdb> break set multiply
rdb> cont                    # Hits add
rdb> cont                    # Hits multiply
```

**Line breakpoints:**
```bash
rdb> break set demo.rs:13
rdb> cont                    # Stops at line 13
```

**Step operations:**
```bash
rdb> break set main
rdb> cont
rdb> next                    # Step over (doesn't enter functions)
rdb> step                    # Step into (enters functions)
rdb> finish                  # Step out (returns from function)
```

**Inspection:**
```bash
rdb> break set calculate
rdb> cont
rdb> reg                     # Show registers
rdb> mem $rsp                # Show memory at stack pointer
rdb> dis                     # Disassemble current location
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Specific test
cargo test --test breakpoints
```

## Requirements

- Linux x86_64
- Programs must be compiled with debug info (`-g`)

## License

See [LICENSE.txt](LICENSE.txt)

## Credits

Based on [sdb](https://github.com/TartanLlama/sdb) by TartanLlama, following the book "Building a Debugger" by Sy Brand.
