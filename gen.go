package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-target bpf -D__TARGET_ARCH_arm64 -I/usr/include -I/usr/local/include/linux-headers/include -I/usr/include/asm -I/usr/src/linux-headers-6.14.0-15/include -I/usr/src/linux-headers-6.14.0-15/arch/arm64/include" -tags linux trace_exec trace_exec.c
