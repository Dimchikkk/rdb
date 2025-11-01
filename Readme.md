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
$ rustc -g -C opt-level=0 example.rs

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

### Quick Test (2 minutes)

Run the automated test to verify everything works:

```bash
cargo test --test comprehensive_stepping -- --nocapture
```

You should see:
```
✓ Stopped at demo.rs:18
✓ Now at line 19
✓ Inside calculate at line 12
✓ After add() at line 13
✓ Inside multiply at line 7
✓ Back in calculate at line 14
✓ Program exited

=== All Stepping Operations Successful! ===
```

### Manual Interactive Test (5 minutes)

**Step 1: Compile the demo program**

```bash
rustc -g -C opt-level=0 test_programs/demo.rs -o target/test_bins/demo
```

**Step 2: Launch the debugger**

```bash
./target/release/rdb target/test_bins/demo
```

**Step 3: Test breakpoints and stepping**

```bash
# Set breakpoint on calculate function
rdb> break set calculate

# Start execution - should print "Starting calculation..." and stop
rdb> cont

# Step into the add function
rdb> step

# Step over the println
rdb> next

# Step over the addition
rdb> next

# Continue to finish
rdb> cont
```

**Expected output:**
```
rdb> break set calculate
Breakpoint 1 set on function calculate

rdb> cont
Starting calculation...
Stopped at demo.rs:12

rdb> step
Stopped at demo.rs:2

rdb> next
Adding 3 and 4

rdb> cont
Multiplying 3 and 4
Result: 19
Done!
Program exited
```

### Test Scenarios

#### Test 1: Function Breakpoints

```bash
./target/release/rdb target/test_bins/demo

rdb> break set add
rdb> break set multiply
rdb> break list        # Verify both breakpoints
rdb> cont              # Stops at add
rdb> cont              # Stops at multiply
rdb> cont              # Program completes
```

#### Test 2: Line Breakpoints

```bash
./target/release/rdb target/test_bins/demo

rdb> break set demo.rs:13
rdb> cont              # Stops at line 13
rdb> step              # Step to next line
rdb> cont
```

#### Test 3: Step Into/Over/Out

```bash
./target/release/rdb target/test_bins/demo

rdb> break set main
rdb> cont
rdb> next              # Step over println (doesn't enter function)
rdb> step              # Step into calculate
rdb> step              # Step into add
rdb> finish            # Step out of add back to calculate
rdb> cont
```

#### Test 4: Register and Memory Inspection

```bash
./target/release/rdb target/test_bins/demo

rdb> break set calculate
rdb> cont
rdb> reg               # Show all registers
rdb> mem $rsp          # Inspect stack pointer
rdb> dis               # Disassemble current location
rdb> cont
```

### Verify the Fix

The main bug that was fixed: **Line table lookup was returning wrong source locations**

**Before fix (BROKEN):**
```
Stopped at rt.rs:1  ❌ Wrong file!
```

**After fix (WORKING):**
```
Stopped at demo.rs:12  ✅ Correct!
```

When you debug, verify that:
- File names show your source files (demo.rs), not runtime libraries (rt.rs)
- Line numbers match your actual source code
- Breakpoints stop at the correct functions
- Stepping moves through your code accurately

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Specific test
cargo test --test breakpoints
```

All tests passing:
- ✅ `source_level_breakpoints`
- ✅ `stepping_behaviour`
- ✅ `test_debugger_demo`
- ✅ `test_comprehensive_stepping`

## Requirements

- Linux x86_64
- Programs must be compiled with debug info (`-g`)
- Disable optimizations for best results (`-C opt-level=0`)

## License

See [LICENSE.txt](LICENSE.txt)

## Credits

Based on [sdb](https://github.com/TartanLlama/sdb) by TartanLlama, following the book "Building a Debugger" by Sy Brand.
