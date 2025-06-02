.PHONY: all generate build clean run-server run-monitor build-monitor

all: generate build

generate:
	go generate monitor.go

build: generate
	go build -o server server.go

build-monitor: generate
	go build -o monitor monitor.go bpf_bpfel_x86.go

clean:
	rm -f server monitor bpf_bpfel_x86.go bpf_bpfel_x86.o

run-server: build
	./server

run-monitor: build-monitor
	sudo ./monitor

# Alternative: run with go using preserved PATH
run-monitor-dev: generate
	sudo -E env "PATH=$$PATH" go run monitor.go bpf_bpfel_x86.go

test-request:
	curl http://localhost:8080 