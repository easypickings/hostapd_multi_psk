#ifndef WPA_AUTH_MULTI_H
#define WPA_AUTH_MULTI_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t pmk[32];
    uint32_t seq;
    uint32_t time;
    uint64_t reserved;
} multi_psk_line_t;

void multi_psk_init(const uint8_t *pre_psk, size_t pre_psk_len, const uint8_t *ssid, size_t ssid_len);

multi_psk_line_t *multi_psk_enum(const uint8_t mic[16], const uint8_t ANonce[128], const uint8_t SNonce[128],
                                 const uint8_t AA[6], const uint8_t SPA[6]);

void multi_psk_fill_block(multi_psk_line_t *block, size_t num_lines, uint32_t block_id,
                          const uint8_t *pre_psk, size_t pre_psk_len, const uint8_t *ssid, size_t ssid_len);
// For Mode A, the block_id is constant 0, this function only register the block pointer and reture immediately.
// For Mode B, the block_id indicate the day of expire, this function will generate the whole block and then return.

#endif // WPA_AUTH_MULTI_H
