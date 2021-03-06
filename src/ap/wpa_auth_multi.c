#include <time.h>
#include "utils/includes.h"
#include "utils/common.h"
#include "ap/wpa_auth_multi.h"
#include "common/wpa_common.h"
#include "common/eapol_common.h"
#include "utils/common.h"

#define NUM_LINE 256
#define NUM_BLOCK 20

static multi_psk_line_t blocks[NUM_BLOCK][NUM_LINE];

void multi_psk_init(const uint8_t *pre_psk, size_t pre_psk_len,
                    const uint8_t *ssid, size_t ssid_len)
{
    multi_psk_fill_block(blocks[0], NUM_LINE, 0, pre_psk, pre_psk_len, ssid, ssid_len);
    uint32_t block_id = time(0) / (24 * 60 * 60);
    printf("Multi PSK: Fill block begin ");
    fflush(stdout);
    for(int i = 0; i < NUM_BLOCK - 1; i++) {
        multi_psk_fill_block(blocks[i + 1], NUM_LINE, block_id + i, pre_psk, pre_psk_len, ssid, ssid_len);
        printf(".");
        fflush(stdout);
    }
    printf(" done\n");
}

void multi_psk_visit_block(multi_psk_visit_block_handler handler, void *data)
{
    handler(0, blocks[0], NUM_LINE, data);
}

multi_psk_line_t *multi_psk_enum(const uint8_t *const_data, size_t data_len,
                                 const uint8_t ANonce[128], const uint8_t SNonce[128],
                                 const uint8_t AA[6], const uint8_t SPA[6], int akmp, int cipher)
{
    struct ieee802_1x_hdr *hdr;
    struct wpa_eapol_key *key;
    uint16_t key_info;
    uint8_t mic[WPA_EAPOL_KEY_MIC_MAX_LEN], data[data_len], *mic_pos;
    memcpy(data, const_data, data_len);
    size_t mic_len = wpa_mic_len(akmp, 32);
    if (data_len < sizeof(*hdr) + sizeof(*key))
        return NULL;
    hdr = (struct ieee802_1x_hdr *) data;
    key = (struct wpa_eapol_key *) (hdr + 1);
    mic_pos = (uint8_t *) (key + 1);
    key_info = WPA_GET_BE16(key->key_info);
    memcpy(mic, mic_pos, mic_len);
    uint32_t now = time(0) / (60 * 60);
    for(uint32_t block_id = 0; block_id < NUM_BLOCK; block_id++) {
        for(multi_psk_line_t *line = blocks[block_id]; line < blocks[block_id] + NUM_LINE; line++) {
            if(!line->is_valid || line->time <= now) continue;
            struct wpa_ptk PTK;
            wpa_pmk_to_ptk(line->pmk, 32, "Pairwise key expansion",
                           AA, SPA, ANonce, SNonce,
                           &PTK, akmp, cipher, NULL, 0);
            memset(mic_pos, 0, mic_len);
            if(wpa_eapol_key_mic(PTK.kck, PTK.kck_len, akmp,
                          key_info & WPA_KEY_INFO_TYPE_MASK,
                          data, data_len, mic_pos))
                continue;
            if(memcmp(mic, mic_pos, mic_len) != 0)
                continue;
            return line;
        }
    }
    return NULL;
}
