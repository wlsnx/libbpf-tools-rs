// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define COMM_LEN 256
#define EVENT_LEN 8192
const volatile int target_pid = -1;
const volatile u8 target_comm[COMM_LEN] = "";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
  int pid = (int)bpf_get_current_pid_tgid();
  u8 comm[COMM_LEN] = "";
  bpf_get_current_comm(&comm, COMM_LEN);
  if (pid == target_pid || bpf_strncmp(comm, COMM_LEN, target_comm) == 0) {
    void *buf = (void *)ctx->args[1];
    size_t count = ctx->args[2];
    void *event = bpf_ringbuf_reserve(&events, EVENT_LEN, 0);
    if (!event) {
      return 0;
    }
    bpf_probe_read_user(event, count & EVENT_LEN, buf);
    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
