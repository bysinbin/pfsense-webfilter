#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "../include/poseafilter.h"

int parse_tls_sni(const uint8_t *data, size_t len, char *sni_out, size_t max_len) {
    if (!data || len < 44 || !sni_out || max_len == 0) return -1;
    sni_out[0] = '\0';

    /* TLS Record Type: 0x16 (Handshake) */
    if (data[0] != 0x16) return -1;

    /* Handshake Type: 0x01 (Client Hello) */
    if (data[5] != 0x01) return -1;

    size_t pos = 5 + 4 + 2 + 32; /* Record hdr (5) + Handshake hdr (4) + Version (2) + Random (32) */
    if (pos >= len) return -1;

    /* Session ID */
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    if (pos + 2 > len) return -1;

    /* Cipher Suites */
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_suites_len;
    if (pos + 1 > len) return -1;

    /* Compression Methods */
    uint8_t comp_len = data[pos++];
    pos += comp_len;
    if (pos + 2 > len) return -1;

    /* Extensions Length */
    uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    size_t ext_end = pos + extensions_len;
    if (ext_end > len) ext_end = len;

    /* Iterate through TLS extensions */
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (pos + ext_len > ext_end) break;

        /* Extension 0x0000: Server Name Indication (SNI) */
        if (ext_type == 0x0000) {
            if (ext_len < 5) return -1;
            /* server_name_list_length (2) + name_type (1) + name_length (2) */
            uint8_t name_type = data[pos + 2];
            uint16_t name_len = (data[pos + 3] << 8) | data[pos + 4];
            if (name_type == 0 && name_len > 0) { /* 0 = host_name */
                if (pos + 5 + name_len <= ext_end) {
                    size_t copy_len = (name_len < max_len - 1) ? name_len : (max_len - 1);
                    memcpy(sni_out, &data[pos + 5], copy_len);
                    sni_out[copy_len] = '\0';
                    /* Convert extracted SNI to lowercase */
                    for (size_t i = 0; i < copy_len; i++) {
                        sni_out[i] = tolower((unsigned char)sni_out[i]);
                    }
                    return 0; /* Success */
                }
            }
        }
        pos += ext_len;
    }

    return -1; /* SNI not present or invalid */
}
