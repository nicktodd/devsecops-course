/*
 * Heartbleed Simulation — CVE-2014-0160
 *
 * The real Heartbleed bug (OpenSSL ssl/d1_both.c, April 2014) trusted a
 * 2-byte length field from the attacker's TLS heartbeat request without
 * checking it against the actual number of payload bytes received.
 * The server then copied that many bytes from its heap into the response,
 * disclosing adjacent secrets (private keys, session tokens, passwords).
 *
 * Root cause (simplified from the original patch):
 *   uint16_t payload_length = n2s(p);     // read from attacker packet
 *   unsigned char *pl = p;                // pointer to received payload
 *   ...
 *   memcpy(bp, pl, payload_length);       // copies payload_length bytes
 *                                         // — no check that pl holds
 *                                         //   payload_length bytes
 *
 * This simulation reproduces that logic in isolation so the memory
 * disclosure can be observed directly.
 *
 * Compile:
 *   make      (uses the Makefile in this directory)
 *   OR:
 *   gcc -o heartbleed_sim heartbleed_sim.c
 *
 * Run:
 *   ./heartbleed_sim
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Simulate a flat heap region where the heartbeat payload and sensitive
 * server data are allocated consecutively — as they can be in a real heap. */
#define HEAP_SIZE 256
static uint8_t simulated_heap[HEAP_SIZE];
static uint16_t actual_payload_length;

/*
 * Initialise the simulated heap:
 *   offset  0  : heartbeat payload ("PING", 4 bytes) — sent by the client
 *   offset  4  : session token (36 bytes)             — adjacent allocation
 *   offset 40  : private key fragment (40 bytes)      — adjacent allocation
 */
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

/* Pretty-print a buffer as printable ASCII (dots for non-printable bytes). */
static void print_ascii(const uint8_t *buf, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        putchar((buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.');
    }
}

/*
 * VULNERABLE heartbeat handler.
 *
 * claimed_length comes directly from the attacker's packet.
 * It is never validated against actual_payload_length.
 * If claimed_length > actual_payload_length the memcpy over-reads
 * the payload allocation into the adjacent heap region, copying
 * session tokens and key material into the response.
 */
static void heartbeat_handler_vulnerable(uint16_t claimed_length) {
    uint8_t *response = malloc(claimed_length);
    if (!response) { perror("malloc"); return; }

    /* VULNERABILITY: memcpy trusts claimed_length from the attacker.
     * If the actual payload is 4 bytes but claimed_length is 200,
     * this copies 196 bytes beyond the intended payload boundary —
     * exactly the root cause of CVE-2014-0160. */
    memcpy(response, simulated_heap, claimed_length); /* VULNERABLE: no bounds check */

    printf("  Sending %u bytes (actual payload was %u bytes):\n",
           claimed_length, actual_payload_length);
    printf("  [");
    print_ascii(response, claimed_length);
    printf("]\n");

    if (claimed_length > actual_payload_length) {
        printf("  ^ %u bytes of LEAKED heap memory visible above the 'PING' payload\n",
               claimed_length - actual_payload_length);
    }

    free(response);
}

int main(void) {
    init_heap();

    printf("=== Heartbleed Simulation (CVE-2014-0160) — VULNERABLE ===\n\n");
    printf("Heap layout:\n");
    printf("  offset  0: payload = \"PING\" (actual_length = %u bytes)\n", actual_payload_length);
    printf("  offset  4: SESSION_TOKEN=esa-orbit-key-a1b2c3d4\n");
    printf("  offset 40: PRIVATE_KEY_FRAGMENT=MIIEpAIBAAKCAQ==\n\n");

    printf("--- Attacker sends heartbeat with claimed_length=200, actual=4 ---\n");
    heartbeat_handler_vulnerable(200);

    printf("\n--- Legitimate client sends heartbeat with claimed_length=4 ---\n");
    heartbeat_handler_vulnerable(4);

    return 0;
}
