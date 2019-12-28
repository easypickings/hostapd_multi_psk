#include "wpa_auth_multi.h"
#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/sha1.h"
#include "ap/ap_config.h"
#include <openssl/sha.h>
#include <assert.h>

static const char *generate_psk(const uint8_t *data)
{
    static char psk[11];
    uint64_t val = ((uint64_t *)data)[0];
    char *i;
    for(i = psk; i < psk + 10; i++) {
        *i = '0' + val % 36;
        if(*i > '9') *i += 'a' - '9' - 1;
        val /= 36;
    }
    *i = 0;
    return psk;
}

void multi_psk_fill_block(multi_psk_line_t *block, size_t num_lines, uint32_t block_id,
                          const uint8_t *pre_psk, size_t pre_psk_len, const uint8_t *ssid, size_t ssid_len)
{
    if(block_id == 0) {
        // TODO: Mode A not implemented!
    } else {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        char psk[pre_psk_len + 40];
        for(uint32_t seq = 0; seq < num_lines; seq++) {
            uint32_t time = block_id * 24 + (seq * 24 / num_lines);
            sprintf(psk, "%s#%010u#%010u", pre_psk, seq, time);
            assert(SHA256_Init(&sha256));
            assert(SHA256_Update(&sha256, pre_psk, strlen(psk)));
            assert(SHA256_Final(hash, &sha256));
            pbkdf2_sha1(generate_psk(hash), ssid, ssid_len, 4096, block[seq].pmk, PMK_LEN);
            block[seq].seq = seq;
            block[seq].time = time;
        }
    }
}
