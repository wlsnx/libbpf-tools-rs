// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

// 包含所需的内核头文件和 BPF 辅助函数
#include "vmlinux.h"

#include "filelife.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 目标进程 ID，用于过滤特定进程
const volatile pid_t targ_tgid = 0;

// 事件结构体实例
struct event _event = {};

// 哈希表 map：用于存储文件创建时间
// key: dentry 指针
// value: 创建时间戳
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, struct dentry *);
  __type(value, u64);
} start SEC(".maps");

// 环形缓冲区 map：用于向用户空间传递事件数据
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 10000);
} events SEC(".maps");

// 通用的文件创建探测函数
// 记录文件创建时间到 start map 中
static __always_inline int probe_create(struct dentry *dentry) {
  // 获取当前进程 ID
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u64 ts;

  // 如果指定了目标进程且不匹配，则返回
  if (targ_tgid && targ_tgid != tgid)
    return 0;

  // 记录当前时间戳
  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start, &dentry, &ts, 0);
  return 0;
}

// 跟踪 vfs_create 系统调用
SEC("fentry/vfs_create")
int BPF_KPROBE(vfs_create, struct user_namespace *mnt_userns, struct inode *dir,
               struct dentry *dentry) {
  return probe_create(dentry);
}

// 跟踪 vfs_open 系统调用
// 只关注带有特定标志的文件打开操作
SEC("fentry/vfs_open")
int BPF_KPROBE(vfs_open, struct path *path, struct file *file) {
  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  u32 f_mode = BPF_CORE_READ(file, f_mode);
  if (!(f_mode & 0x100000)) {
    return 0;
  }
  return probe_create(dentry);
};

// 跟踪文件创建时的安全检查
SEC("fentry/security_inode_create")
int BPF_KPROBE(security_inode_create, struct inode *dir,
               struct dentry *dentry) {
  return probe_create(dentry);
}

// 跟踪文件删除操作
// 计算文件生命周期并发送事件到用户空间
SEC("fentry/vfs_unlink")
int BPF_KPROBE(vfs_unlink, struct user_namespace *mnt_userns, struct inode *dir,
               struct dentry *dentry) {
  u64 id = bpf_get_current_pid_tgid();
  struct event *event;
  const u8 *qs_name_ptr;
  u32 tgid = id >> 32;
  u64 *tsp, delta_ns;

  // 查找文件创建时间
  tsp = bpf_map_lookup_elem(&start, &dentry);
  if (!tsp)
    return 0; // 如果未找到创建记录则返回

  // 在环形缓冲区中预留事件空间
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  // 计算文件存活时间
  delta_ns = bpf_ktime_get_ns() - *tsp;
  bpf_map_delete_elem(&start, &dentry);

  // 填充事件信息
  qs_name_ptr = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(event->file, sizeof(event->file), qs_name_ptr);
  bpf_get_current_comm(event->task, sizeof(event->task));
  event->delta_ns = delta_ns;
  event->tgid = tgid;

  // 提交事件到环形缓冲区
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// 声明 GPL 许可证
char LICENSE[] SEC("license") = "GPL";
