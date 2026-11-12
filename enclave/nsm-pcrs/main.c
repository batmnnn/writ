/*
 * writ-nsm-pcrs: print PCR0, PCR1 and PCR2 of the running enclave.
 *
 * On success stdout is exactly three lines, lowercase hex, 96 characters each:
 *
 *   <PCR0>
 *   <PCR1>
 *   <PCR2>
 *
 * Exit 1 with nothing on stdout if nsm_lib_init fails, a describe call fails, a PCR is not 48 bytes
 * (SHA-384) or any PCR is all zeros (debug mode or a missing measurement). Nothing is printed until
 * all three PCRs have been read and checked.
 *
 * Built against libnsm from aws-nitro-enclaves-nsm-api at commit
 * 4b851f3006c6fa98f23dcffb2cba03b39de9b8af, the commit enclave/Dockerfile already builds.
 * ErrorCode is #[repr(C)] there and Success is 0. /dev/nsm exists only inside an enclave.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <nsm.h>

#define PCR_COUNT 3
#define PCR_BYTES 48
#define PCR_BUF 64

int main(void) {
    uint8_t pcrs[PCR_COUNT][PCR_BYTES];
    int fd = nsm_lib_init();
    if (fd < 0) {
        fputs("writ-nsm-pcrs: nsm_lib_init failed\n", stderr);
        return 1;
    }

    for (uint16_t i = 0; i < PCR_COUNT; i++) {
        uint8_t data[PCR_BUF] = {0};
        uint32_t len = PCR_BUF;
        bool lock = false;
        if (nsm_describe_pcr(fd, i, &lock, data, &len) != 0) {
            fputs("writ-nsm-pcrs: nsm_describe_pcr failed\n", stderr);
            nsm_lib_exit(fd);
            return 1;
        }
        if (len != PCR_BYTES) {
            fputs("writ-nsm-pcrs: PCR is not 48 bytes\n", stderr);
            nsm_lib_exit(fd);
            return 1;
        }
        uint8_t any = 0;
        for (uint32_t b = 0; b < PCR_BYTES; b++) {
            pcrs[i][b] = data[b];
            any |= data[b];
        }
        if (any == 0) {
            fputs("writ-nsm-pcrs: PCR is all zeros\n", stderr);
            nsm_lib_exit(fd);
            return 1;
        }
    }
    nsm_lib_exit(fd);

    char out[PCR_COUNT * (PCR_BYTES * 2 + 1) + 1];
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    for (int i = 0; i < PCR_COUNT; i++) {
        for (int b = 0; b < PCR_BYTES; b++) {
            out[n++] = hex[pcrs[i][b] >> 4];
            out[n++] = hex[pcrs[i][b] & 0x0f];
        }
        out[n++] = '\n';
    }
    out[n] = '\0';

    if (fputs(out, stdout) == EOF || fflush(stdout) != 0) return 1;
    return 0;
}
