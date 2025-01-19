package main

import (
    "github.com/iovisor/gobpf/bcc"
    "os"
    "os/signal"
    "fmt"
    "C"
    "unsafe"
)

const bpfProgram = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    char comm[16];
    char fname[256];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.ppid = bpf_get_current_task()->parent->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
`

type eventT struct {
    Pid     uint32
    Tid     uint32
    Ppid    uint32
    Comm    [16]byte
    Fname   [256]byte
}

type ProcessTracer struct {
    module  *bcc.Module
    perfMap *bcc.PerfMap
}

func NewTracer() (*ProcessTracer, error) {
    module := bcc.NewModule(bpfProgram, []string{})
    if module == nil {
        return nil, fmt.Errorf("BPF not supported")
    }

    fnName := "trace_exec"
    kprobe, err := module.LoadKprobe(fnName)
    if err != nil {
        return nil, fmt.Errorf("failed to load kprobe: %v", err)
    }

    err = module.AttachKprobe("do_execve", kprobe, -1)
    if err != nil {
        return nil, fmt.Errorf("failed to attach kprobe: %v", err)
    }

    table := bcc.NewTable(module.TableId("events"), module)
    
    tracer := &ProcessTracer{
        module: module,
    }

    perfMap, err := bcc.InitPerfMap(table, tracer.handleEvent)
    if err != nil {
        return nil, fmt.Errorf("failed to init perf map: %v", err)
    }
    
    tracer.perfMap = perfMap
    return tracer, nil
}

func (t *ProcessTracer) handleEvent(cpu int, data []byte, size int) {
    event := (*eventT)(unsafe.Pointer(&data[0]))
    fmt.Printf("PID: %d, TID: %d, PPID: %d, Command: %s\n",
        event.Pid, event.Tid, event.Ppid, event.Comm)
}

func (t *ProcessTracer) Start() {
    t.perfMap.Start()
}

func (t *ProcessTracer) Stop() {
    t.perfMap.Stop()
    t.module.Close()
}

func main() {
    tracer, err := NewTracer()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create tracer: %v\n", err)
        os.Exit(1)
    }
    defer tracer.Stop()

    tracer.Start()
    fmt.Println("Tracing... Press Ctrl+C to exit")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)

    <-sig
}
