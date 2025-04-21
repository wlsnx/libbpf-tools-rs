// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"

#include "execsnoop.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// 全局配置变量
const volatile bool filter_cg = false;         // 是否启用 cgroup 过滤
const volatile bool ignore_failed = true;      // 是否忽略执行失败的进程
const volatile uid_t targ_uid = INVALID_UID;   // 目标用户ID，用于过滤特定用户
const volatile int max_args = DEFAULT_MAXARGS; // 最大参数数量

// 空事件结构体，用于初始化
const struct event empty_event = {};

// cgroup map定义，用于cgroup过滤功能
struct
{
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

/* struct { */
/*   __uint(type, BPF_MAP_TYPE_HASH); */
/*   __uint(max_entries, 10240); */
/*   __type(key, pid_t); */
/*   __type(value, struct event); */
/* } execs SEC(".maps"); */

// Ring Buffer map定义，用于向用户空间传递数据
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20); // 1MB 大小的 ring buffer
} events SEC(".maps");

// 检查用户ID是否有效
static __always_inline bool valid_uid(uid_t uid)
{
  return uid != INVALID_UID;
}

// 跟踪execve系统调用的入口点
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
  u64 id;
  pid_t pid, tgid;
  unsigned int ret;
  struct event *event;
  struct task_struct *task;
  const char **args = (const char **)(ctx->args[1]); // 获取命令行参数数组
  const char *argp;

  // 检查cgroup过滤条件
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
    return 0;

  // 获取当前进程的用户ID
  uid_t uid = (u32)bpf_get_current_uid_gid();
  int i;

  // 检查用户ID过滤条件
  if (valid_uid(targ_uid) && targ_uid != uid)
    return 0;

  // 获取进程ID信息
  id = bpf_get_current_pid_tgid();
  pid = (pid_t)id;
  tgid = id >> 32;

  // 在ring buffer中预留事件空间
  event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event)
    return 0;

  // 填充事件基本信息
  event->pid = tgid;
  event->uid = uid;
  task = (struct task_struct *)bpf_get_current_task();
  event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid); // 获取父进程ID
  event->args_count = 0;
  event->args_size = 0;
  bpf_get_current_comm(&event->comm, sizeof(event->comm)); // 获取进程名

  // 读取程序路径（第一个参数）
  ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char *)ctx->args[0]);
  if (ret <= ARGSIZE)
  {
    event->args_size += ret;
  }
  else
  {
    event->args[0] = '\0';
    event->args_size++;
  }
  event->args_count++;

  // 读取命令行参数
  for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++)
  {
    bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (!argp)
      goto submit;

    if (event->args_size > LAST_ARG)
      goto submit;

    ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
    if (ret > ARGSIZE)
      goto submit;

    event->args_count++;
    event->args_size += ret;
  }

  // 检查是否还有更多参数
  bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
  if (!argp)
    goto submit;

  event->args_count++; // 标记还有更多参数未记录

submit:
  // 提交事件到ring buffer
  bpf_ringbuf_submit(event, 0);
  return 0;
}

/* SEC("tracepoint/syscalls/sys_exit_execve") */
/* int tracepoint__syscalls__sys_exit_execve( */
/*     struct trace_event_raw_sys_exit *ctx) { */
/*   u64 id; */
/*   pid_t pid; */
/*   int ret; */
/*   struct event *event; */

/*   if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) */
/*     return 0; */

/*   u32 uid = (u32)bpf_get_current_uid_gid(); */

/*   if (valid_uid(targ_uid) && targ_uid != uid) */
/*     return 0; */
/*   id = bpf_get_current_pid_tgid(); */
/*   pid = (pid_t)id; */
/*   event = bpf_map_lookup_elem(&execs, &pid); */
/*   if (!event) */
/*     return 0; */
/*   ret = ctx->ret; */
/*   if (ignore_failed && ret < 0) */
/*     goto cleanup; */

/*   event->retval = ret; */
/*   /\* bpf_get_current_comm(&event->comm, sizeof(event->comm)); *\/ */
/*   size_t len = EVENT_SIZE(event); */
/*   if (len <= sizeof(*event)) */
/*     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len); */
/* cleanup: */
/*   bpf_map_delete_elem(&execs, &pid); */
/*   return 0; */
/* } */

// 许可证声明
char LICENSE[] SEC("license") = "GPL";
