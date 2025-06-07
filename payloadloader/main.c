// based on: https://github.com/ps5-payload-dev/kstuff/blob/3962120d6dd5064a92bd9d9180f31074c5510f12/ps5-kstuff-ldr/main.c

/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <elf.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <machine/param.h>
#include <sys/mman.h>

#include <ps5/payload.h>

#define PAYLOAD_BUFFER_SIZE (16 * 1024 * 1024) // 16MB
#define PORT 9010

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x) ((((x) & PF_R) ? PROT_READ : 0) |  \
                   (((x) & PF_W) ? PROT_WRITE : 0) | \
                   (((x) & PF_X) ? PROT_EXEC : 0))

static void
pt_load(const void *image, void *base, Elf64_Phdr *phdr) {
    if (phdr->p_memsz && phdr->p_filesz) {
        memcpy(base + phdr->p_vaddr, image + phdr->p_offset, phdr->p_filesz);
    }
}

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

void notify(const char *fmt, ...) {
    notify_request_t req;
    va_list args;

    bzero(&req, sizeof req);
    va_start(args, fmt);
    vsnprintf(req.message, sizeof req.message, fmt, args);
    va_end(args);

    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
    puts(req.message);
}

int execute_payload(const char *payload_bin) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(payload_bin + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr *)(payload_bin + ehdr->e_shoff);
    void *base = (void *)0x0000000926100000;
    uintptr_t min_vaddr = -1;
    uintptr_t max_vaddr = 0;
    size_t base_size;

    // Compute size of virtual memory region.
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_vaddr < min_vaddr) {
            min_vaddr = phdr[i].p_vaddr;
        }

        if (max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    // allocate memory.
    if ((base = mmap(base, base_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Parse program headers.
    for (int i = 0; i < ehdr->e_phnum; i++) {
        switch (phdr[i].p_type) {
        case PT_LOAD:
            pt_load(payload_bin, base, &phdr[i]);
            break;
        }
    }

    // Set protection bits on mapped segments.
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
            continue;
        }
        if (mprotect(base + phdr[i].p_vaddr, ROUND_PG(phdr[i].p_memsz),
                     PFLAGS(phdr[i].p_flags))) {
            perror("mprotect");
            return EXIT_FAILURE;
        }
    }

    void (*entry)(payload_args_t *) = base + ehdr->e_entry;
    payload_args_t *args = payload_get_args();

    entry(args);

    return *args->payloadout;
}

int main() {
    void *payload_buf = malloc(PAYLOAD_BUFFER_SIZE);
    if (!payload_buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = 0},
        .sin_port = __builtin_bswap16(PORT),
    };

    if (bind(sock, (void *)&sin, sizeof(sin))) {
        notify("Error binding socket to port %d (errno %d)", PORT, errno);
        return EXIT_FAILURE;
    }

    listen(sock, 1);

    notify("Payload loader listening on port %d", PORT);

    while (1) {
        memset(payload_buf, 0, PAYLOAD_BUFFER_SIZE);

        int sock2 = accept(sock, 0, 0);
        if (sock2 < 0) {
            notify("Error accepting connection, skipping...");
            continue;
        }

        size_t payload_size = 0;
        while (1) {
            ssize_t n = read(sock2, payload_buf + payload_size, PAYLOAD_BUFFER_SIZE - payload_size);
            if (n < 0) {
                notify("Error reading from socket, skipping...");
                payload_size = 0;
                break;
            }
            if (n == 0) {
                break;
            }
            payload_size += n;
        }

        if (payload_size == 0) {
            close(sock2);
            continue;
        }

        close(sock2);

        notify("Received payload of size %zu bytes, calling entry point...", payload_size);

        int res = execute_payload(payload_buf);

        notify("Payload exited with code 0x%X", res);
    }

    return EXIT_FAILURE;
}
