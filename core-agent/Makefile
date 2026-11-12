CLANG ?= clang
CFLAGS := -g -Wall -O2
LDFLAGS := -lbpf -lelf -lz

all: loader

probe.skel.h: probe.bpf.c vmlinux.h probe.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c probe.bpf.c -o probe.bpf.o
	bpftool gen skeleton probe.bpf.o > probe.skel.h

loader: loader.c probe.skel.h probe.h
	gcc $(CFLAGS) loader.c -o loader $(LDFLAGS)

clean:
	rm -f loader probe.bpf.o probe.skel.h
