# rdb: rust debugger

Supports only `x86_64`, based on https://github.com/TartanLlama/sdb.

To launch process:

`gcc -o ./test_programs/hello_world ./test_programs/hello_world.c`
`cargo run -- "./test_programs/hello_world"`

To attach to process:

```
$ while sleep 7; do echo "test"; done &
[1] 1247

// from another terminal
$ cargo run -- -p 1247
```
it will attach to the process and stop it, then type "continue" to continue running process until it halts again by sys call from `sleep`.
