#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const char ssl_identity[] = "WPA-MULTI-PSK-MODE-A";
static uint8_t pre_psk_hash[SHA256_DIGEST_LENGTH];

unsigned int psk_callback(SSL *ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len)
{
    strcpy(identity, ssl_identity);
    memcpy(psk, pre_psk_hash, SHA256_DIGEST_LENGTH);
    return SHA256_DIGEST_LENGTH;
}

void mode_A(struct sockaddr_in addr, char *pre_psk, char *passphrase, int hours)
{
    SHA256_CTX sha256;
    assert(SHA256_Init(&sha256));
    assert(SHA256_Update(&sha256, pre_psk, strlen(pre_psk)));
    assert(SHA256_Final(pre_psk_hash, &sha256));
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(client_fd >= 0);
    assert(connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    assert(ctx);
    SSL_CTX_set_psk_client_callback(ctx, &psk_callback);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if(SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    char buf[100];
    sprintf(buf, "%d %s", hours, passphrase);
    assert(SSL_write(ssl, buf, 100) > 0);
    assert(SSL_read(ssl, buf, 100) > 0);
    printf("%s", buf);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return;
}

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

void mode_B(char *pre_psk, int seq, int hours)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    int pre_psk_len = strlen(pre_psk);
    char psk[pre_psk_len + 40];
    memset(psk, 0, sizeof(psk));
    sprintf(psk + pre_psk_len, "#%010u#%010u", seq, hours);
    assert(SHA256_Init(&sha256));
    assert(SHA256_Update(&sha256, psk, sizeof(psk)));
    assert(SHA256_Final(hash, &sha256));
    printf("Passphrase: %s\n", generate_psk(hash));
}

const char usage_string[] =
"Usage: hostapd_wpa_multi_client -p pre_psk -m A/B [OPTIONS]\n"
"For Mode A, options are:\n"
"    -a ADDR        IP address of hostapd, default: 127.0.0.1\n"
"    -c PORT        PORT of control interface, default: 9090\n"
"    -s PASSPHRASE  The passphrase for user to use\n"
"    -t HOURS       Set the expire time, default: 24\n"
"\n"
"For Mode B, options are:\n"
"    -n SEQ_NUM     The sequence number for user, default: 0\n"
"    -t HOURS       Set the expire time, default: 24\n";

void usage()
{
    fprintf(stderr, usage_string);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int opt;
    char pre_psk[64] = "";
    int mode = 0, hours = 24, seq = 0;
    char passphrase[64] = "";
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9090);
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    while ((opt = getopt(argc, argv, "p:m:t:a:c:s:n:")) != -1) {
        switch (opt) {
        case 'p':
            if(strlen(optarg) < 8 || strlen(optarg) > 63) {
                fprintf(stderr, "The length of pre_psk should be 8~63\n");
                exit(EXIT_FAILURE);
            }
            strcpy(pre_psk, optarg);
            break;
        case 'm':
            if(strcmp(optarg, "A") == 0) {
                mode = 1;
            } else if(strcmp(optarg, "B") == 0) {
                mode = 2;
            } else {
                usage();
            }
            break;
        case 't':
            hours = atoi(optarg);
            break;
        case 'a':
            assert(inet_pton(AF_INET, optarg, &addr.sin_addr) == 1);
            break;
        case 'n':
            seq = atoi(optarg);
            break;
        case 'c':
            addr.sin_port = htons(atoi(optarg));
            break;
        case 's':
            if(strlen(optarg) < 8 || strlen(optarg) > 63) {
                fprintf(stderr, "The length of passphrase should be 8~63\n");
                exit(EXIT_FAILURE);
            }
            strcpy(passphrase, optarg);
            break;
        default:
            usage();
        }
    }
    if(!pre_psk[0] || hours < 0) usage();
    printf("Current Time (Hours): %ld\n", time(0) / (60 * 60));
    hours += time(0) / (60 * 60);
    printf("Expire Time (Hours): %d\n", hours);
    if(mode == 1) {
        mode_A(addr, pre_psk, passphrase, hours);
    } else if(mode == 2) {
        mode_B(pre_psk, seq, hours);
    } else {
        usage();
    }
    return 0;
}
