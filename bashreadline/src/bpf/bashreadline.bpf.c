/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"

#include "bashreadline.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct str_t _data = {0};

SEC("uretprobe/readline")
int BPF_KRETPROBE(printret, const void *ret) {
  struct str_t data;
  char comm[TASK_COMM_LEN];
  u32 pid;

  if (!ret)
    return 0;

  bpf_get_current_comm(&comm, sizeof(comm));
  if (bpf_strncmp(comm, TASK_COMM_LEN, "bash") != 0)
    return 0;

  pid = bpf_get_current_pid_tgid() >> 32;
  data.pid = pid;
  bpf_probe_read_user_str(&data.str, sizeof(data.str), ret);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return 0;
};

char LICENSE[] SEC("license") = "GPL";
