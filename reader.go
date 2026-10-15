package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type sockStateEvent struct {
	PID      uint32
	Oldstate uint32
	Newstate uint32
}

func readEvents() error {
	spec, err := loadSocketrace()
	if err != nil {
		return fmt.Errorf("load eBPF spec: %w", err)
	}

	var objs socketraceObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	defer objs.Close()

	link, err := link.Tracepoint(
		"sock",
		"inet_sock_set_state",
		objs.TraceTcpState,
		nil,
	)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer link.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	defer reader.Close()

	log.Println("socktrace running: waiting for TCP state events...")

	for {
		record, err := reader.Read()
		if err != nil {
			return fmt.Errorf("read ring buffer: %w", err)
		}

		var event sockStateEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		fmt.Printf(
			"pid=%d TCP state: %d -> %d\n",
			event.PID,
			event.Oldstate,
			event.Newstate,
		)
	}

}
