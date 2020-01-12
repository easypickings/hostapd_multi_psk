#include "wpa_auth_multi.h"
#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/sha1.h"
#include "ap/ap_config.h"
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
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

typedef struct{
    multi_psk_line_t *block;
    size_t num_lines;
    const uint8_t *pre_psk;
    size_t pre_psk_len;
    const uint8_t *ssid;
    size_t ssid_len;
    SSL_CTX *ctx;
    uint8_t pre_psk_hash[SHA256_DIGEST_LENGTH];
} server_ctx_t;
server_ctx_t server_ctx_list[128];
unsigned int server_ctx_cnt = 0;

unsigned int psk_callback(SSL *ssl, const char *identity,
        unsigned char *psk, unsigned int max_psk_len)
{
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    server_ctx_t *server_ctx = server_ctx_list;
    while(server_ctx != server_ctx_list + server_ctx_cnt && ctx != server_ctx->ctx);
    if(server_ctx == server_ctx_list + server_ctx_cnt) {
        printf("identity: %s, no match\n", identity);
        return 0;
    }
    printf("identity: %s, ctx: %ld\n", identity, server_ctx - server_ctx_list);
    memcpy(psk, server_ctx->pre_psk_hash, SHA256_DIGEST_LENGTH);
    return SHA256_DIGEST_LENGTH;
}

struct mode_a_handler_data {
    server_ctx_t *server_ctx;
    uint8_t pmk[32];
    uint32_t time;
};

static bool mode_a_handler(uint32_t block_id, multi_psk_line_t *block, size_t num_lines, void *_data)
{
    struct mode_a_handler_data *data = _data;
    multi_psk_line_t *i;
    for(i = block; i < block + num_lines; i++) {
        if(memcmp(i->pmk, data->pmk, 32) == 0) {
            i->is_valid = true;
            i->time = data->time;
            wpa_printf(MSG_INFO, "Multi PSK: Mode_A Update PMK, expire time: %u", i->time);
            return false;
        }
    }
    for(i = block; i < block + num_lines; i++) {
        if(!i->is_valid) break;
    }
    if(i == block + num_lines) {
        wpa_printf(MSG_ERROR, "Multi PSK: Mode A too many entries!");
        return false;
    }
    i->is_valid = true;
    i->time = data->time;
    memcpy(i->pmk, data->pmk, 32);
    wpa_printf(MSG_INFO, "Multi PSK: Mode_A Add PMK, expire time: %u", i->time);
    return false;
}

static void *mode_a_server(void *arg)
{
    server_ctx_t *server_ctx = arg;
    SHA256_CTX sha256;
    assert(SHA256_Init(&sha256));
    assert(SHA256_Update(&sha256, server_ctx->pre_psk, server_ctx->pre_psk_len));
    assert(SHA256_Final(server_ctx->pre_psk_hash, &sha256));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9090);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(server_fd >= 0);
    assert(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(server_fd, 1) == 0);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD *method = TLS_server_method();
    server_ctx->ctx = SSL_CTX_new(method);
    assert(server_ctx->ctx);
    SSL_CTX_set_psk_server_callback(server_ctx->ctx, &psk_callback);
    int client_fd;
    socklen_t len;
    while((client_fd = accept(server_fd, (struct sockaddr*)&addr, &len)) >= 0) {
        SSL *ssl = SSL_new(server_ctx->ctx);
        SSL_set_fd(ssl, client_fd);
        if(SSL_accept(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        char buf[100];
        assert(SSL_read(ssl, buf, 100) > 0);
        struct mode_a_handler_data data;
        char passphrase[100];
        sscanf(buf, "%u %s", &data.time, passphrase);
        pbkdf2_sha1(passphrase, server_ctx->ssid, server_ctx->ssid_len, 4096, data.pmk, PMK_LEN);
        multi_psk_visit_block(&mode_a_handler, &data);
        sprintf(buf, "Done\n");
        assert(SSL_write(ssl, buf, 100) > 0);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    close(server_fd);
    SSL_CTX_free(server_ctx->ctx);
    EVP_cleanup();
    free(arg);
    return NULL;
}

void multi_psk_fill_block(multi_psk_line_t *block, size_t num_lines, uint32_t block_id,
                          const uint8_t *pre_psk, size_t pre_psk_len, const uint8_t *ssid, size_t ssid_len)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    if(block_id == 0) {
        server_ctx_t *server_ctx = server_ctx_list + (server_ctx_cnt++);
        server_ctx->block = block;
        server_ctx->num_lines = num_lines;
        server_ctx->pre_psk = pre_psk;
        server_ctx->pre_psk_len = pre_psk_len;
        server_ctx->ssid = ssid;
        server_ctx->ssid_len = ssid_len;
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, &mode_a_server, server_ctx);
        pthread_detach(thread_id);
    } else {
        char psk[pre_psk_len + 40];
        memset(psk, 0, sizeof(psk));
        for(uint32_t seq = 0; seq < num_lines; seq++) {
            uint32_t time = block_id * 24 + seq * 24 / num_lines;
            uint32_t curr_seq = seq - seq * 24 / num_lines * num_lines / 24;
            sprintf(psk + pre_psk_len, "#%010u#%010u", curr_seq, time);
            assert(SHA256_Init(&sha256));
            assert(SHA256_Update(&sha256, psk, sizeof(psk)));
            assert(SHA256_Final(hash, &sha256));
            const char *psk = generate_psk(hash);
            pbkdf2_sha1(psk, ssid, ssid_len, 4096, block[seq].pmk, PMK_LEN);
            block[seq].seq = seq;
            block[seq].time = time;
            block[seq].is_valid = true;
        }
    }
}
