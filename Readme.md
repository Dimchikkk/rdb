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
    break - Commands for operating on breakpoints
    c     - Resume the process
    dis   - Disassemble instructions from memory
    reg   - Commands for operating on registers
    step  - Step over a single instruction
    catch - Catch syscalls
    mem   - Read/write memory
rdb> help catch
Available catchpoint commands:
    sys         - Catch all syscalls
    sys none    - Catch no syscalls
    sys <list>  - Catch specific syscalls by id or name, comma-separated
rdb>
```
