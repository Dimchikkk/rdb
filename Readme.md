# rdb: rust debugger

Supports only `linux x86_64`, based on https://github.com/TartanLlama/sdb.

To launch process:

`cargo run -- "./test_programs/02-hello_world"`

To attach to process:

```
$ while sleep 7; do echo "test"; done &
[1] 1247

// from another terminal
$ cargo run -- -p 1247
```
Type `help` for usage:

```
rdb> help
Available commands:
    breakpoint  - Commands for operating on breakpoints
    continue    - Resume the process
    disassemble - Disassemble instructions from memory
    register    - Commands for operating on registers
    step        - Step over a single instruction
```
