#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <bpf/libbpf.h>
#include "probe.skel.h"
#include "probe.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct crypto_event_t *e = data;
    const char *action = "Context Created";
    if (e->event_type == 1) action = "Keygen Started";
    else if (e->event_type == 2) action = "Keygen Success";
    else if (e->event_type == 3) action = "Keygen Failed";

    printf("[%s] PID: %d (%s), Cgroup: %llu, Algo: %s\n", 
           action, e->pid, e->comm, e->cgroup_id, e->algo_name);
	
    fflush(stdout);

    return 0;
}

// Helper function to find the exact offset of a function in a .so file
size_t get_symbol_offset(const char *binary_path, const char *symbol_name) {
    if (elf_version(EV_CURRENT) == EV_NONE) return 0;
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) return 0;
    
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return 0; }
    
    size_t offset = 0;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (name && strcmp(name, symbol_name) == 0) {
                    offset = sym.st_value;
                    goto done;
                }
            }
        }
    }
done:
    elf_end(elf);
    close(fd);
    return offset;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    struct probe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    // Initialize pointers to NULL to fix compiler warnings
    struct bpf_link *link_ctx = NULL;
    struct bpf_link *link_entry = NULL;
    struct bpf_link *link_ret = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = probe_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "Failed to open and load BPF skeleton\n"); return 1; }

    const char *lib_path = "/host/lib/x86_64-linux-gnu/libcrypto.so.3";

    size_t off_ctx = get_symbol_offset(lib_path, "EVP_PKEY_CTX_new_from_name");
    size_t off_keygen = get_symbol_offset(lib_path, "EVP_PKEY_generate");

    if (off_ctx == 0 || off_keygen == 0) {
        fprintf(stderr, "Failed to find symbols in %s\n", lib_path);
        goto cleanup;
    }

    printf("[*] Found EVP_PKEY_CTX_new_from_name at offset: 0x%lx\n", off_ctx);
    printf("[*] Found EVP_PKEY_generate at offset: 0x%lx\n", off_keygen);

    link_ctx = bpf_program__attach_uprobe(skel->progs.probe_evp_context, false, -1, lib_path, off_ctx);
    link_entry = bpf_program__attach_uprobe(skel->progs.probe_evp_keygen_entry, false, -1, lib_path, off_keygen);
    link_ret = bpf_program__attach_uprobe(skel->progs.probe_evp_keygen_return, true, -1, lib_path, off_keygen);

    if (!link_ctx || !link_entry || !link_ret) {
        fprintf(stderr, "Failed to manually attach uprobes.\n");
        goto cleanup;
    }
    printf("[*] eBPF uprobes manually attached successfully using offsets!\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { err = -1; fprintf(stderr, "Failed to create ring buffer\n"); goto cleanup; }

    printf("QFense CO-RE Agent running. Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { printf("Error polling ring buffer: %d\n", err); break; }
    }

cleanup:
    if (link_ctx) bpf_link__destroy(link_ctx);
    if (link_entry) bpf_link__destroy(link_entry);
    if (link_ret) bpf_link__destroy(link_ret);
    if (rb) ring_buffer__free(rb);
    if (skel) probe_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
