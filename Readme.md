# rdb: rust debugger

To attach to process:

```
$ while sleep 7; do echo "test"; done &
[1] 1247

// from another terminal
$ tools/sdb -p 1247
```
it will attach to the process and stop it, then type "continue" to continue running process until it halts again. May need to type "continue" couple of times to see "test" output
