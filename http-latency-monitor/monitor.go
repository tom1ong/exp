//go:build amd64 && linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf latency.c -- -I/home/ubuntu/ebpf/examples/headers

// latencyEvent must match the struct latency_event in latency.c
type latencyEvent struct {
	PidTgid   uint64
	LatencyNs uint64
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Find the path to our server binary
	serverPath, err := filepath.Abs("./server")
	if err != nil {
		log.Fatalf("getting server path: %v", err)
	}

	// Check if server binary exists
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		log.Fatalf("server binary not found at %s. Please build it first with: go build server.go", serverPath)
	}

	// Open the server executable
	ex, err := link.OpenExecutable(serverPath)
	if err != nil {
		log.Fatalf("opening executable: %v", err)
	}

	// Attach uprobe to function entry
	up, err := ex.Uprobe("main.handleRequest", objs.UprobeHandleRequest, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %v", err)
	}
	defer up.Close()

	// Attach uretprobe to function exit
	uret, err := ex.Uretprobe("main.handleRequest", objs.UretprobeHandleRequest, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %v", err)
	}
	defer uret.Close()

	// Open a perf event reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting...")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %v", err)
		}
	}()

	log.Println("Monitoring HTTP handler latency...")
	log.Println("Make requests to http://localhost:8080 to see latency measurements")

	// Read latency events
	var event latencyEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %v", err)
			continue
		}

		// Convert nanoseconds to milliseconds
		latencyMs := float64(event.LatencyNs) / 1000000.0
		pid := uint32(event.PidTgid >> 32)
		tid := uint32(event.PidTgid & 0xFFFFFFFF)
		
		fmt.Printf("Handler latency: %.3f ms (PID: %d, TID: %d)\n", latencyMs, pid, tid)
	}
} 