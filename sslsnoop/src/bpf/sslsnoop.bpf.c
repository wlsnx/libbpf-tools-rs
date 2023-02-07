#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 128 << 10);
} events SEC(".maps");

#define COMM_MAX_LEN 16
#define DATA_MAX_LEN (4 << 10)

struct event {
  u64 pid_tgid;
  int len;
  bool is_read;
  u8 comm[COMM_MAX_LEN];
  u8 data[DATA_MAX_LEN];
};

const struct event _e = {0};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct event);
  __uint(max_entries, 1);
} event_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, const char **);
  __uint(max_entries, 102400);
} ssl_buffers SEC(".maps");

static __always_inline int update_buf(const char *buf) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&ssl_buffers, &pid_tgid, &buf, 0);
  return 0;
}

static __always_inline int output(int len, bool is_read) {
  if (len <= 0)
    return 0;
  int zero = 0;
  struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
  if (event == NULL) {
    return 0;
  }
  bpf_get_current_comm(event->comm, COMM_MAX_LEN);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  const char **buf = bpf_map_lookup_elem(&ssl_buffers, &pid_tgid);
  if (buf == NULL) {
    return 0;
  }
  event->pid_tgid = pid_tgid;
  event->is_read = is_read;
  event->len = len;
  len = (len >= DATA_MAX_LEN ? DATA_MAX_LEN : len & (DATA_MAX_LEN - 1));
  bpf_probe_read_user(event->data, len, *buf);
  bpf_ringbuf_output(&events, event, sizeof(struct event) - DATA_MAX_LEN + len,
                     0);
  bpf_map_delete_elem(&ssl_buffers, &pid_tgid);
  return 0;
}

SEC("uprobe//usr/lib64/libnspr4.so:PR_Read")
int BPF_KPROBE(probe_func, void *s, const char *buf, int num) {
  return update_buf(buf);
}

SEC("uretprobe//usr/lib64/libnspr4.so:PR_Read")
int BPF_KRETPROBE(retprobe_read, int retval) { return output(retval, true); }

SEC("uretprobe//usr/lib64/libnspr4.so:PR_Read")
int BPF_KRETPROBE(retprobe_write, int retval) { return output(retval, false); }

char LICENSE[] SEC("license") = "GPL";
