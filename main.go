package main

import (
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

func main() {
	ruleSet, err := rules.LoadRulesFromFile("rules.yaml")

	if err != nil {
		log.Println("Failed to load rules")
	}
	log.Println("\nLoaded rules", ruleSet)

	var ruleArray []string

	for _, rule := range ruleSet.Rules {
		fmt.Printf("→ [%s] %s: %s (match: '%s')\n",
			rule.Severity, rule.ID, rule.Description, rule.MatchCommand)
		ruleArray = append(ruleArray, rule.MatchCommand)
	}

	log.Println("\nRule array:", ruleArray)

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

		fmt.Printf("[%s] PID %d executed %s\n", timestamp, e.Pid, comm)

		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", e.Pid))
		if err == nil {
			cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
			if slices.Contains(ruleArray, comm) {
				fmt.Printf("⚠️  Blacklisted command: %s\n", cmdStr)
			}
		}

	}
}
