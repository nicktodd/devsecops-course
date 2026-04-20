# Hardened build — compiler and runtime protections enabled.
#
# -fsanitize=address,undefined
#     AddressSanitizer (ASan): detects heap/stack buffer overflows,
#     use-after-free, and double-free at runtime with precise stack traces.
#     UBSan: detects undefined behaviour (signed overflow, null deref, etc.).
#
# -fstack-protector-all
#     Inserts stack canaries around every function's stack frame.
#     A corrupted canary aborts the process before a return-address overwrite.
#
# -D_FORTIFY_SOURCE=2
#     Enables glibc's compile-time and runtime buffer-overflow checks for
#     standard library functions (strcpy, memcpy, etc.) when sizes are known.
#
# -Wall -Wextra -Werror
#     Treat all warnings as errors — common sources of memory bugs
#     (implicit conversions, signed/unsigned comparisons) are caught at build time.

CC     = gcc
CFLAGS = -g \
         -Wall -Wextra -Werror \
         -fstack-protector-all \
         -D_FORTIFY_SOURCE=2 \
         -fsanitize=address,undefined

.PHONY: all clean

all: memory_bugs heartbleed_sim

memory_bugs: memory_bugs.c
	$(CC) $(CFLAGS) -o memory_bugs memory_bugs.c

heartbleed_sim: heartbleed_sim.c
	$(CC) $(CFLAGS) -o heartbleed_sim heartbleed_sim.c

clean:
	rm -f memory_bugs heartbleed_sim
