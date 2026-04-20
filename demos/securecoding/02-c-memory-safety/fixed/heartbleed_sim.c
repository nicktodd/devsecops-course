/*
 * Heartbleed Fix — CVE-2014-0160
 *
 * The single missing bounds check is added before memcpy.
 * claimed_length is validated against actual_payload_length; requests that
 * claim more data than was received are rejected unconditionally.
 *
 * This mirrors the two-line patch applied in OpenSSL 1.0.1g (7 April 2014):
 *   if (1 + 2 + payload + 16 > s->s3->rrec.length) return 0; // silently discard
 *
 * Compile (with AddressSanitizer — see fixed/Makefile):
 *   make
 *   ./heartbleed_sim
 *
 * Expected output: the over-read request is rejected; no secrets are disclosed.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HEAP_SIZE 256
static uint8_t simulated_heap[HEAP_SIZE];
static uint16_t actual_payload_length;

static void init_heap(void) {
    memset(simulated_heap, 0, HEAP_SIZE);

    const char *payload      = "PING";
    const char *session_tok  = "SESSION_TOKEN=esa-orbit-key-a1b2c3d4";
    const char *key_fragment = "PRIVATE_KEY_FRAGMENT=MIIEpAIBAAKCAQ==";

    actual_payload_length = (uint16_t)strlen(payload);
    memcpy(simulated_heap,      payload,      actual_payload_length);
    memcpy(simulated_heap +  4, session_tok,  strlen(session_tok));
    memcpy(simulated_heap + 40, key_fragment, strlen(key_fragment));
}

static void print_ascii(const uint8_t *buf, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        putchar((buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.');
    }
}

/*
 * FIXED heartbeat handler.
 *
 * claimed_length is validated against actual_payload_length before memcpy.
 * Requests that over-claim are rejected — the attacker receives nothing.
 */
static void heartbeat_handler_fixed(uint16_t claimed_length) {
    /* FIX: Validate claimed_length against the actual received payload size.
     * This is exactly the bounds check that was missing in CVE-2014-0160.
     * A discrepancy indicates either a buggy client or an active attack;
     * in both cases the request must be silently discarded. */
    if (claimed_length > actual_payload_length) { /* FIX: bounds check */
        fprintf(stderr,
            "  [HEARTBEAT] REJECTED: claimed_length=%u > actual_length=%u"
            " (potential over-read of %u bytes — request discarded)\n",
            claimed_length, actual_payload_length,
            claimed_length - actual_payload_length);
        return;
    }

    uint8_t *response = malloc(claimed_length);
    if (!response) { perror("malloc"); return; } /* FIX: NULL check */

    memcpy(response, simulated_heap, claimed_length); /* SAFE: within bounds */

    printf("  Sending %u bytes (within bounds):\n", claimed_length);
    printf("  [");
    print_ascii(response, claimed_length);
    printf("]\n");

    free(response);
}

int main(void) {
    init_heap();

    printf("=== Heartbleed Fix Demo (CVE-2014-0160) — FIXED ===\n\n");
    printf("Heap layout:\n");
    printf("  offset  0: payload = \"PING\" (actual_length = %u bytes)\n", actual_payload_length);
    printf("  offset  4: SESSION_TOKEN=esa-orbit-key-a1b2c3d4\n");
    printf("  offset 40: PRIVATE_KEY_FRAGMENT=MIIEpAIBAAKCAQ==\n\n");

    printf("--- Attacker sends heartbeat with claimed_length=200, actual=4 ---\n");
    heartbeat_handler_fixed(200);
    printf("  No data returned. No secrets disclosed.\n");

    printf("\n--- Legitimate client sends heartbeat with claimed_length=4 ---\n");
    heartbeat_handler_fixed(4);

    return 0;
}
