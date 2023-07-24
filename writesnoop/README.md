# writesnoop

功能基本等同于`bpftrace -e 'tracepoint:syscalls:sys_enter_write /pid == ? || comm == ?/ { printf("%s", str(args->buf)) }'`
