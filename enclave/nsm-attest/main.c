/*
 * writ-attest: ask NSM for one attestation document bound to the caller's nonce.
 *
 *   writ-attest <nonce-hex> [user-data-hex]
 *
 * The nonce is hex, at least 64 characters (32 bytes) and at most 1024 (512 bytes, the NSM cap).
 * It goes to NSM as the nonce. public_key is always null.
 * user_data is optional. Without the second argument it is null, as before. With it, it must be
 * even-length hex of 1 to 1024 bytes and goes to NSM as user_data. src/host/enclave-tls.ts passes
 * the 32 byte sha256 that binds the TLS key and the ledger key to this image.
 *
 * On success stdout is exactly one line: standard base64 of the raw COSE_Sign1 bytes.
 * Exit 1 with nothing on stdout if an argument is missing or bad, nsm_lib_init fails, the
 * attestation call fails, or the document is empty. Nothing is printed until all checks pass.
 *
 * Built against libnsm from aws-nitro-enclaves-nsm-api at commit
 * 4b851f3006c6fa98f23dcffb2cba03b39de9b8af, the commit enclave/Dockerfile already builds.
 * ErrorCode is #[repr(C)] there and Success is 0. /dev/nsm exists only inside an enclave.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <nsm.h>

#define NONCE_MIN_BYTES 32
#define NONCE_MAX_BYTES 512
#define USER_DATA_MAX_BYTES 1024
#define DOC_BUF (48 * 1024)
#define OUT_BUF (((DOC_BUF + 2) / 3) * 4 + 2)

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t doc[DOC_BUF];
static char out[OUT_BUF];
static uint8_t user_data[USER_DATA_MAX_BYTES];

/* Decodes even-length hex into dst. Returns the byte count, or -1 for a bad length or a bad digit. */
static int decode_hex(const char *src, uint8_t *dst, size_t max_bytes) {
    size_t len = strlen(src);
    if (len == 0 || len % 2 != 0 || len / 2 > max_bytes) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_val(src[2 * i]);
        int lo = hex_val(src[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(len / 2);
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        fputs("writ-attest: expected the nonce as hex and optional user_data as hex\n", stderr);
        return 1;
    }
    uint32_t user_data_len = 0;
    if (argc == 3) {
        int n = decode_hex(argv[2], user_data, USER_DATA_MAX_BYTES);
        if (n < 1) {
            fputs("writ-attest: user_data must be 1 to 1024 bytes of hex\n", stderr);
            return 1;
        }
        user_data_len = (uint32_t)n;
    }
    const char *hex = argv[1];
    size_t hex_len = strlen(hex);
    if (hex_len < NONCE_MIN_BYTES * 2 || hex_len > NONCE_MAX_BYTES * 2 || hex_len % 2 != 0) {
        fputs("writ-attest: nonce must be 32 to 512 bytes of hex\n", stderr);
        return 1;
    }
    uint8_t nonce[NONCE_MAX_BYTES];
    uint32_t nonce_len = (uint32_t)(hex_len / 2);
    for (uint32_t i = 0; i < nonce_len; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fputs("writ-attest: nonce is not hex\n", stderr);
            return 1;
        }
        nonce[i] = (uint8_t)((hi << 4) | lo);
    }

    int fd = nsm_lib_init();
    if (fd < 0) {
        fputs("writ-attest: nsm_lib_init failed\n", stderr);
        return 1;
    }
    uint32_t doc_len = DOC_BUF;
    int failed;
    if (user_data_len == 0) {
        failed = nsm_get_attestation_doc(fd, NULL, 0, nonce, nonce_len, NULL, 0, doc, &doc_len) != 0;
    } else {
        failed = nsm_get_attestation_doc(fd, user_data, user_data_len, nonce, nonce_len, NULL, 0, doc, &doc_len) != 0;
    }
    if (failed) {
        fputs("writ-attest: nsm_get_attestation_doc failed\n", stderr);
        nsm_lib_exit(fd);
        return 1;
    }
    nsm_lib_exit(fd);
    if (doc_len == 0 || doc_len > DOC_BUF) {
        fputs("writ-attest: attestation document is empty or too long\n", stderr);
        return 1;
    }

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    uint32_t i = 0;
    for (; i + 3 <= doc_len; i += 3) {
        uint32_t v = ((uint32_t)doc[i] << 16) | ((uint32_t)doc[i + 1] << 8) | doc[i + 2];
        out[n++] = b64[(v >> 18) & 0x3f];
        out[n++] = b64[(v >> 12) & 0x3f];
        out[n++] = b64[(v >> 6) & 0x3f];
        out[n++] = b64[v & 0x3f];
    }
    if (doc_len - i == 1) {
        uint32_t v = (uint32_t)doc[i] << 16;
        out[n++] = b64[(v >> 18) & 0x3f];
        out[n++] = b64[(v >> 12) & 0x3f];
        out[n++] = '=';
        out[n++] = '=';
    } else if (doc_len - i == 2) {
        uint32_t v = ((uint32_t)doc[i] << 16) | ((uint32_t)doc[i + 1] << 8);
        out[n++] = b64[(v >> 18) & 0x3f];
        out[n++] = b64[(v >> 12) & 0x3f];
        out[n++] = b64[(v >> 6) & 0x3f];
        out[n++] = '=';
    }
    out[n++] = '\n';
    out[n] = '\0';

    if (fputs(out, stdout) == EOF || fflush(stdout) != 0) return 1;
    return 0;
}
