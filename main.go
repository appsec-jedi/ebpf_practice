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
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/appsec-jedi/ebpf_practice/pkg/rules"
)

type event struct {
	Timestamp uint64
	Pid       uint32
	Comm      [16]byte
}

func openLogFile(path string) *os.File {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	return file
}

func main() {
	ruleSet, err := rules.LoadRulesFromFile("rules.yaml")

	if err != nil {
		log.Println("Failed to load rules")
	}

	logFile := openLogFile("logs/output.txt")
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

	var ruleArray []string

	for _, rule := range ruleSet.Rules {
		fmt.Printf("→ [%s] %s: %s (match: '%s')\n",
			rule.Severity, rule.ID, rule.Description, rule.MatchCommand)
		ruleArray = append(ruleArray, rule.MatchCommand)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs trace_execObjects
	if err := loadTrace_execObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attaching to tracepoint: %s", err)
	}
	defer tp.Close()

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

		timestamp := time.Unix(0, int64(e.Timestamp)).Format("2006-01-02 15:04:05")
		comm := string(bytes.Trim(e.Comm[:], "\x00"))

		commandString := fmt.Sprintf("[%s] PID %d executed %s\n", timestamp, e.Pid, comm)

		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", e.Pid))
		if err == nil {
			cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
			if slices.Contains(ruleArray, comm) {
				fmt.Printf("⚠️  \tBlacklisted command: %s\n", cmdStr)
				commandString = commandString + fmt.Sprintf("⚠️  \tBlacklisted command: %s\n", cmdStr)
			}
		}

		_, err = writer.WriteString(commandString)
		if err != nil {
			log.Printf("error writing to buffered log: %v", err)
		}
	}
}
