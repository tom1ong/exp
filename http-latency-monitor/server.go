package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// handleRequest is the HTTP handler we'll monitor with eBPF
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Simulate some work with random delay
	delay := time.Duration(rand.Intn(100)) * time.Millisecond
	time.Sleep(delay)
	
	fmt.Fprintf(w, "Hello! Request processed in %v\n", delay)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	
	http.HandleFunc("/", handleRequest)
	
	log.Println("Starting HTTP server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
} 