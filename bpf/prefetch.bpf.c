
// bpf/prefetch.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct prefetch_evt {
    __u32 tgid;
    __u32 pid;
    __u64 ts_ns;
    __u64 sb_dev;   // superblock device (dev_t expanded)
    __u64 ino;      // inode number
    __u64 pgoff;    // page index within file
};


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} PREFETCH_EVENTS SEC(".maps");


SEC("fentry/filemap_fault") int BPF_PROG(on_filemap_fault_fentry, struct vm_fault *vmf) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    if (!is_target_tgid(tgid)) return 0;

    struct file *f = BPF_CORE_READ(vmf, vma, vm_file);
    if (!f) return 0;

    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode) return 0;

    struct prefetch_evt *e = bpf_ringbuf_reserve(&PREFETCH_EVENTS, sizeof(*e), 0);
    if (!e) return 0;

    e->tgid  = tgid;
    e->pid   = (__u32)pidtgid;
    e->ts_ns = bpf_ktime_get_ns();
    e->ino   = BPF_CORE_READ(inode, i_ino);
    e->sb_dev= (__u64)BPF_CORE_READ(inode, i_sb, s_dev);
    e->pgoff = BPF_CORE_READ(vmf, pgoff);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("kprobe/filemap_fault")
int BPF_KPROBE(on_filemap_fault, struct vm_fault *vmf)
{
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    if (!is_target_tgid(tgid)) return 0;

    struct file *f = BPF_CORE_READ(vmf, vma, vm_file);
    if (!f) return 0;

    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode) return 0;

    struct prefetch_evt *e = bpf_ringbuf_reserve(&PREFETCH_EVENTS, sizeof(*e), 0);
    if (!e) return 0;

    e->tgid  = tgid;
    e->pid   = (__u32)pidtgid;
    e->ts_ns = bpf_ktime_get_ns();
    e->ino   = BPF_CORE_READ(inode, i_ino);
    e->sb_dev= (__u64)BPF_CORE_READ(inode, i_sb, s_dev);
    e->pgoff = BPF_CORE_READ(vmf, pgoff);

    bpf_ringbuf_submit(e, 0);
    return 0;
}