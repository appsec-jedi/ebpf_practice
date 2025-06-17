// main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Pid  uint32
	Argv [96]byte
}

func openLogFile(path string) *os.File {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	return file
}

func main() {
	logFilePath := "app/logs/output.txt"
	logFile := openLogFile(logFilePath)
	defer logFile.Close()

	writer := bufio.NewWriter(logFile)
	defer writer.Flush()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			writer.Flush()
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs trace_execObjects
	if err := loadTrace_execObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("__arm64_sys_execve", objs.HandleExecKprobe, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %s", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("\nListening for exec events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		log.Println("Interrupt received, exiting...")
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading from ringbuf: %s", err)
			continue
		}

		var e event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing event: %s", err)
			continue
		}

		argv := string(bytes.Trim(e.Argv[:], "\x00"))
		logLine := fmt.Sprintf("PID %d executed %s\n", e.Pid, argv)
		fmt.Print(logLine)

		if _, err := writer.WriteString(logLine); err != nil {
			log.Printf("error writing to log: %v", err)
		}
		writer.Flush()
	}
}
