package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

const (
    progFile = "packet_filter.o"
)

func loadBPFObject() (*ebpf.CollectionSpec, error) {
    spec, err := ebpf.LoadCollectionSpec(progFile)
    if err != nil {
        return nil, err
    }
    return spec, nil
}

func main() {
    // Allow the current process to lock memory for eBPF maps
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock limit: %v", err)
    }

    // Load the precompiled BPF program
    spec, err := loadBPFObject()
    if err != nil {
        log.Fatalf("Failed to load BPF object: %v", err)
    }

    // Create a new BPF collection from the compiled spec
    objs := struct {
        Prog *ebpf.Program `ebpf:"packet_filter"`
    }{}
    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        log.Fatalf("Failed to load and assign BPF program: %v", err)
    }
    defer objs.Prog.Close()

    // Attach the BPF program to the XDP hook
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.Prog,
        Interface: 1, // Change this to the correct network interface index
    })
    if err != nil {
        log.Fatalf("Failed to attach XDP program: %v", err)
    }
    defer link.Close()

    log.Println("BPF program successfully attached. Press Ctrl+C to exit.")

    // Listen for termination signals
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    <-sigs

    log.Println("Received termination signal, exiting...")
}
