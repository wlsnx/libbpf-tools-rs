// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define COMM_LEN 256
#define DATA_LEN 8192
const volatile int target_pid = -1;
const volatile u8 target_comm[COMM_LEN] = "";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct event {
  int pid;
  int fd;
  int count;
  u8 data[DATA_LEN];
};

struct event _e = {};

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
  int pid = (int)bpf_get_current_pid_tgid();
  u8 comm[COMM_LEN] = "";
  bpf_get_current_comm(&comm, COMM_LEN);
  if (pid == target_pid || bpf_strncmp(comm, COMM_LEN, target_comm) == 0) {
    void *buf = (void *)ctx->args[1];
    int count = ctx->args[2];
    if (count >= DATA_LEN) {
      count = DATA_LEN - 1;
    }
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
      return 0;
    }
    e->pid = pid;
    e->fd = (int)ctx->args[0];
    e->count = count;
    bpf_probe_read_user(e->data, count & (DATA_LEN - 1), buf);
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
