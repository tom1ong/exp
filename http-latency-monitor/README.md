# HTTP Service Latency Monitor with eBPF

This project demonstrates how to use eBPF to monitor the latency of HTTP request handlers in a Go service.

## Components

1. **server.go** - A simple HTTP server with a handler that simulates work with random delays
2. **latency.c** - An eBPF program that measures handler latency using uprobe/uretprobe
3. **monitor.go** - A Go program that loads the eBPF program and displays latency measurements

## How it works

The eBPF program attaches probes to the entry and exit points of the `handleRequest` function:
- **uprobe** records the timestamp when the function is entered
- **uretprobe** calculates the latency when the function exits
- Latency data is sent to userspace via a perf event array

## Prerequisites

- Linux kernel with eBPF support (>= 4.14)
- Go 1.20 or higher
- clang and llvm for compiling eBPF programs
- Root/sudo privileges to load eBPF programs

## Build and Run

1. Install dependencies:
```bash
cd http-latency-monitor
go mod download
```

2. Build everything:
```bash
make all
make build-monitor
```

3. Run the HTTP server (in one terminal):
```bash
./server
# or
make run-server
```

4. Run the latency monitor (in another terminal, requires sudo):
```bash
sudo ./monitor
# or
make run-monitor
```

5. Make HTTP requests to see latency measurements:
```bash
curl http://localhost:8080
# or
make test-request
```

## Troubleshooting

If you get "sudo: go: command not found", use one of these approaches:
- Build the monitor first: `make build-monitor` then `sudo ./monitor`
- Use full path: `sudo /usr/local/go/bin/go run monitor.go bpf_bpfel_x86.go`
- Preserve PATH: `sudo -E env "PATH=$PATH" go run monitor.go bpf_bpfel_x86.go`

## Example Output

Server output:
```
2024/01/15 10:30:45 Starting HTTP server on :8080
```

Monitor output:
```
2024/01/15 10:31:02 Monitoring HTTP handler latency...
2024/01/15 10:31:02 Make requests to http://localhost:8080 to see latency measurements
Handler latency: 45.123 ms (PID: 1234, TID: 1234)
Handler latency: 12.456 ms (PID: 1234, TID: 1235)
Handler latency: 78.901 ms (PID: 1234, TID: 1236)
```

## Notes

- The monitor must be run with sudo/root privileges to load eBPF programs
- The server binary must be built before running the monitor
- The uprobe/uretprobe attach to the specific function symbol in the binary 