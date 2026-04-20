/*
 * C Memory Safety — Fixed Versions
 *
 * Each function from vulnerable/memory_bugs.c is corrected:
 *   1. Buffer overflow  — strncpy with explicit NUL termination
 *   2. Use-after-free   — pointer set to NULL immediately after free()
 *   3. Double-free      — pointer set to NULL; free(NULL) is a safe no-op
 *
 * Compile with AddressSanitizer enabled (see fixed/Makefile) to confirm
 * all three bugs are absent:
 *   make
 *   ./memory_bugs overflow "AAAAAAAAAAAAAAAAAAA"
 *   ./memory_bugs uaf
 *   ./memory_bugs doublefree
 *
 * Expected: all three complete cleanly. ASan reports no errors.
 * Contrast with the vulnerable/ version where ASan aborts with a detailed
 * stack trace for each bug.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * 1. BUFFER OVERFLOW — FIXED
 * ---------------------------------------------------------------------- */
void demo_buffer_overflow(const char *input) {
    char buf[16];

    /* FIX: strncpy copies at most sizeof(buf)-1 bytes, preventing overrun.
     * The explicit NUL assignment guarantees the buffer is always terminated
     * even if input is exactly 15 characters long. */
    strncpy(buf, input, sizeof(buf) - 1); /* FIX: bounded copy */
    buf[sizeof(buf) - 1] = '\0';          /* FIX: explicit NUL terminator */

    printf("[overflow] Safely copied into buf[16]: \"%s\"\n", buf);
    if (strlen(input) >= sizeof(buf)) {
        printf("[overflow] Input was truncated to %zu characters — no overflow.\n",
               sizeof(buf) - 1);
    }
}

/* -------------------------------------------------------------------------
 * 2. USE-AFTER-FREE — FIXED
 * ---------------------------------------------------------------------- */
void demo_use_after_free(void) {
    char *data = malloc(32);

    /* FIX: always check the return value of malloc. */
    if (!data) { perror("malloc"); return; } /* FIX: NULL check */

    strcpy(data, "TELEMETRY_PACKET_v1");
    printf("[uaf] Allocated and wrote: \"%s\"\n", data);

    free(data);
    data = NULL; /* FIX: zero the pointer immediately after free().
                  * Any subsequent dereference produces a clean NULL-pointer
                  * crash at the use site rather than silent heap corruption. */

    /* FIX: guard every subsequent use with a NULL check. */
    if (data != NULL) {
        printf("[uaf] data: \"%s\"\n", data); /* never reached */
    } else {
        printf("[uaf] Pointer is NULL after free — safe.\n");
    }
}

/* -------------------------------------------------------------------------
 * 3. DOUBLE-FREE — FIXED
 * ---------------------------------------------------------------------- */
void demo_double_free(void) {
    char *buf = malloc(64);

    /* FIX: check allocation result. */
    if (!buf) { perror("malloc"); return; } /* FIX: NULL check */

    strcpy(buf, "mission_critical_data");
    printf("[doublefree] Allocated: \"%s\"\n", buf);

    free(buf);
    buf = NULL; /* FIX: setting to NULL makes the second free() a safe no-op.
                 * The C standard guarantees free(NULL) has no effect. */

    free(buf); /* safe: free(NULL) is a defined no-op per ISO C §7.22.3.3 */

    printf("[doublefree] Second free(NULL) — no heap corruption.\n");
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
