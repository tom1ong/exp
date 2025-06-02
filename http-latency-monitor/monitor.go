//go:build monitor && amd64 && linux
// +build monitor,amd64,linux

package main

import (
	"bytes"
	"debug/elf"
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

	// Attach uprobe to function entry (offset 0)
	up, err := ex.Uprobe("main.handleRequest", objs.UprobeHandleRequest, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %v", err)
	}
	defer up.Close()

	// Enumerate RET instructions and attach uprobes at each as synthetic "return" probes.
	retOffsets, err := getRetOffsets(serverPath, "main.handleRequest")
	if err != nil {
		log.Fatalf("finding RET offsets: %v", err)
	}

	var retLinks []link.Link
	for _, off := range retOffsets {
		// Skip offset 0 (already attached above)
		if off == 0 {
			continue
		}
		l, err := ex.Uprobe("main.handleRequest", objs.UprobeRetHandleRequest, &link.UprobeOptions{Offset: off})
		if err != nil {
			log.Fatalf("creating return uprobe at offset %d: %v", off, err)
		}
		retLinks = append(retLinks, l)
	}
	defer func() {
		for _, l := range retLinks {
			l.Close()
		}
	}()

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

// getRetOffsets opens the ELF binary located at path and returns the list of
// byte offsets (relative to symbol start) of RET instructions (0xC3 or 0xC2)
// inside the given symbol. The symbol name must match exactly the value in the
// symbol table, e.g. "main.handleRequest" for Go binaries.
func getRetOffsets(path, symbol string) ([]uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read symbols: %w", err)
	}

	var sym elf.Symbol
	found := false
	for _, s := range syms {
		if s.Name == symbol {
			sym = s
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("symbol %s not found", symbol)
	}

	// Locate containing section to compute file offset.
	if int(sym.Section) >= len(f.Sections) {
		return nil, fmt.Errorf("invalid section index for symbol")
	}
	sec := f.Sections[sym.Section]

	secData, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read section data: %w", err)
	}

	// Compute slice of bytes for the symbol.
	start := sym.Value - sec.Addr
	if start >= uint64(len(secData)) {
		return nil, fmt.Errorf("symbol start outside section data")
	}

	var size uint64 = sym.Size
	if size == 0 {
		// If size not set, read until end of section.
		size = uint64(len(secData)) - start
	}
	if start+size > uint64(len(secData)) {
		size = uint64(len(secData)) - start
	}

	code := secData[start : start+size]

	var offs []uint64
	for i := 0; i < len(code); i++ {
		b := code[i]
		if b == 0xC3 {
			offs = append(offs, uint64(i))
		} else if b == 0xC2 {
			// RET imm16 – length 3 bytes, account but still mark offset.
			offs = append(offs, uint64(i))
			i += 2 // skip immediate
		}
	}
	return offs, nil
}
