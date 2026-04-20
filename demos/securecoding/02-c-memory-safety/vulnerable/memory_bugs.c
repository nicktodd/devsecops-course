/*
 * C Memory Safety — Three Classic Vulnerability Classes
 *
 * Demonstrates buffer overflow, use-after-free, and double-free in a
 * single program. Each is runnable as an independent sub-demo via command-line
 * argument.
 *
 * Compile (no hardening — bugs may be silent without a sanitiser):
 *   make      (uses the Makefile in this directory)
 *   OR:
 *   gcc -o memory_bugs memory_bugs.c
 *
 * Run:
 *   ./memory_bugs overflow "AAAAAAAAAAAAAAAAAAA"   # buffer overflow
 *   ./memory_bugs uaf                               # use-after-free
 *   ./memory_bugs doublefree                        # double-free
 *
 * TIP: Compile the fixed/ version with AddressSanitizer (see fixed/Makefile)
 *      to see each bug caught with a precise diagnosis and stack trace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * 1. BUFFER OVERFLOW
 *    A fixed-size stack buffer is written without checking the input length.
 *    Input longer than 15 characters overwrites adjacent stack memory, which
 *    can corrupt the return address and redirect execution.
 * ---------------------------------------------------------------------- */
void demo_buffer_overflow(const char *input) {
    char buf[16]; /* 16-byte stack buffer */

    /* VULNERABILITY: strcpy does not check the destination buffer size.
     * If strlen(input) >= 16 the function writes past the end of buf,
     * overwriting adjacent stack frames — return address, saved registers,
     * local variables of callers. On some platforms this enables RCE. */
    strcpy(buf, input); /* VULNERABLE: no length check */

    printf("[overflow] Copied into buf[16]: \"%s\"\n", buf);
}

/* -------------------------------------------------------------------------
 * 2. USE-AFTER-FREE
 *    A heap pointer is dereferenced after the memory it points to has been
 *    released. The allocator may hand that memory to a subsequent allocation,
 *    so the stale pointer may read or write attacker-influenced data.
 * ---------------------------------------------------------------------- */
void demo_use_after_free(void) {
    char *data = malloc(32);
    strcpy(data, "TELEMETRY_PACKET_v1");
    printf("[uaf] Allocated and wrote: \"%s\"\n", data);

    free(data); /* data is now returned to the allocator */

    /* VULNERABILITY: data still holds the old address.
     * The memory may be reused by another allocation; reading it may
     * return attacker-influenced bytes. Writing to it corrupts the heap.
     * Behaviour is undefined — crashes, silent data corruption, or worse. */
    printf("[uaf] After free (undefined behaviour): \"%s\"\n", data); /* VULNERABLE */
}

/* -------------------------------------------------------------------------
 * 3. DOUBLE-FREE
 *    The same pointer is passed to free() twice. The second call corrupts
 *    the allocator's internal metadata, which can be exploited to write an
 *    attacker-controlled value to an attacker-controlled address (write-what-
 *    where primitive), enabling arbitrary code execution.
 * ---------------------------------------------------------------------- */
void demo_double_free(void) {
    char *buf = malloc(64);
    strcpy(buf, "mission_critical_data");
    printf("[doublefree] Allocated: \"%s\"\n", buf);

    free(buf); /* first free — correct */

    /* VULNERABILITY: buf is freed a second time.
     * The allocator's free-list metadata is corrupted.
     * On glibc, this aborts with "free(): double free detected".
     * On other allocators it may silently corrupt the heap for later exploit. */
    free(buf); /* VULNERABLE: double-free */

    printf("[doublefree] Reached after double-free (undefined behaviour)\n");
}

/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s overflow <input> | uaf | doublefree\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "overflow") == 0) {
        const char *input = (argc >= 3) ? argv[2] : "short";
        demo_buffer_overflow(input);
    } else if (strcmp(argv[1], "uaf") == 0) {
        demo_use_after_free();
    } else if (strcmp(argv[1], "doublefree") == 0) {
        demo_double_free();
    } else {
        fprintf(stderr, "Unknown demo: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
