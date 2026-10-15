package main

import (
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --cc clang socketrace tracepoint.c -- -I

func main() {
	if err := readEvents(); err != nil {
		log.Fatal(err)
	}
}
