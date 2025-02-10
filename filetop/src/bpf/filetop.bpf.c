/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include "vmlinux.h"

#include "filetop.h"
#include "stat.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool regular_file_only = true;
struct file_stat zero_value = {};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct file_id);
  __type(value, struct file_stat);
} entries SEC(".maps");

static void get_file_path(struct file *file, char *buf, size_t size) {
  size_t DPATH_LEN = 128;
  struct qstr dname;
  u32 pos = 0;
  struct dentry *d = BPF_CORE_READ(file, f_path.dentry);

  for (int i = 0; i < 64; i++) {
    if (!d)
      return;
    dname = BPF_CORE_READ(d, d_name);
    if (pos + DPATH_LEN > size)
      return;
    long len = bpf_probe_read_kernel_str(buf + pos, DPATH_LEN, dname.name);
    if (len <= 2)
      return;
    pos += len;
    bpf_printk("len: %d pos: %d", len, pos);
    buf[(pos - 1) & (size - 1)] = '/';
    d = BPF_CORE_READ(d, d_parent);
  }
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count,
                       enum op op) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  int mode;
  struct file_id key = {};
  struct file_stat *valuep;

  if (target_pid && target_pid != pid)
    return 0;

  mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (regular_file_only && !S_ISREG(mode))
    return 0;

  key.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
  key.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
  key.inode = BPF_CORE_READ(file, f_inode, i_ino);
  key.pid = pid;
  key.tid = tid;
  valuep = bpf_map_lookup_elem(&entries, &key);
  if (!valuep) {
    bpf_map_update_elem(&entries, &key, &zero_value, BPF_ANY);
    valuep = bpf_map_lookup_elem(&entries, &key);
    if (!valuep)
      return 0;
    valuep->pid = pid;
    valuep->tid = tid;
    bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
    get_file_path(file, valuep->filename, sizeof(valuep->filename));
    if (S_ISREG(mode)) {
      valuep->_type = 'R';
    } else if (S_ISSOCK(mode)) {
      valuep->_type = 'S';
    } else {
      valuep->_type = 'O';
    }
  }
  if (op == READ) {
    valuep->reads++;
    valuep->read_bytes += count;
  } else { /* op == WRITE */
    valuep->writes++;
    valuep->write_bytes += count;
  }
  return 0;
};

SEC("fentry/vfs_read")
int BPF_PROG(vfs_read_entry, struct file *file, char *buf, size_t count,
             loff_t *pos) {
  return probe_entry(ctx, file, count, READ);
}

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write_entry, struct file *file, const char *buf, size_t count,
             loff_t *pos) {
  return probe_entry(ctx, file, count, WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
