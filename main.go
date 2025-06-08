package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Pid  uint32
	Comm [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs trace_execObjects
	if err := loadTrace_execObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("Listening for exec events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

loop:
	for {
		select {
		case <-sig:
			break loop
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					break loop
				}
				log.Printf("reading from ringbuf: %s", err)
				continue
			}

			var e event
			data := record.RawSample
			if len(data) < binary.Size(e) {
				log.Printf("short read: expected %d bytes, got %d", binary.Size(e), len(data))
				continue
			}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
				log.Printf("parsing event: %s", err)
				continue
			}

			fmt.Printf("PID %d executed %s\n", e.Pid, string(bytes.Trim(e.Comm[:], "\x00")))
		}
	}
}
