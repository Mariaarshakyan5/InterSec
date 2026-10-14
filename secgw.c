/*
 * secgw.c - inline AES-GCM "TCP payload" protection gateway
 *
 *   PC1 -> Device1 -> Device2 -> PC2
 *
 * Both devices run this same program.  One acts as handshake initiator
 * (Device1), the other as responder (Device2).  Selected TCP/IPv4 packets are
 * intercepted with iptables NFQUEUE:
 *
 *   queue E (encrypt): packets arriving from the local LAN side
 *   queue D (decrypt): packets arriving from the peer device
 *
 * Wire format of a protected packet (no UDP encapsulation, no new header):
 *
 *   [ original IPv4 header ][ original TCP header (+options) ]
 *   [ AES-256-GCM ciphertext (same length as plaintext payload) ]
 *   [ 8-byte big-endian packet counter (explicit nonce part) ]
 *   [ 16-byte GCM tag ]
 *
 * Only IPv4 total-length and the IPv4/TCP checksums change.
 *
 * Key establishment: finite-field Diffie-Hellman (RFC 7919 ffdhe2048) over a
 * separate control TCP connection, then HKDF-SHA256.  Optional pre-shared key
 * is mixed into the KDF to authenticate the handshake (strongly recommended).
 *
 * Nonce: 96 bit = 32-bit per-direction salt (from HKDF) || 64-bit counter.
 * Each direction has its own key AND salt, the counter is strictly increasing,
 * and the sender refuses to encrypt once the counter budget is exhausted.
 *
 * Build:  make            Self-test:  ./secgw -t
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/netfilter.h> /* NF_ACCEPT, NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

/* ------------------------------------------------------------------ */
/* constants                                                          */
/* ------------------------------------------------------------------ */
#define KEY_LEN      32
#define SALT_LEN     4
#define NONCE_LEN    12
#define CTR_LEN      8
#define TAG_LEN      16
#define OVERHEAD     (CTR_LEN + TAG_LEN)
#define AAD_LEN      21            /* see build_aad() */
#define MAX_IP       65535
#define CTR_LIMIT    (1ULL << 62)  /* far below 2^64: wrap is impossible */

#define DH_GROUP     "ffdhe2048"
#define DH_LEN       256
#define RAND_LEN     32
#define MAC_LEN      32
#define HS_TIMEOUT_S 10
#define OKM_LEN      (KEY_LEN * 3 + SALT_LEN * 2)
#define NFQ_BUFSZ    (MAX_IP + 8192)

/* ------------------------------------------------------------------ */
/* logging / statistics                                               */
/* ------------------------------------------------------------------ */
static int g_verbose;
static volatile sig_atomic_t g_stop;

static void logmsg(const char *lvl, const char *fmt, ...)
{
    char ts[32];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof ts, "%H:%M:%S", &tmv);
    fprintf(stderr, "%s [%s] ", ts, lvl);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
#define LOG(...)  logmsg("info", __VA_ARGS__)
#define WARN(...) logmsg("warn", __VA_ARGS__)
#define DBG(...)  do { if (g_verbose) logmsg("dbg", __VA_ARGS__); } while (0)

static uint64_t st_enc_ok, st_dec_ok, st_enc_drop, st_dec_drop, st_nosess;
#define STAT_INC(x) __atomic_fetch_add(&(x), 1, __ATOMIC_RELAXED)

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */
static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}
static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ------------------------------------------------------------------ */
/* session state                                                      */
/* ------------------------------------------------------------------ */
struct replay { int init; uint64_t top, bitmap; };

struct session {
    uint8_t  tx_key[KEY_LEN], rx_key[KEY_LEN];
    uint8_t  tx_salt[SALT_LEN], rx_salt[SALT_LEN];
    uint64_t tx_ctr;        /* next counter value to use (atomic)        */
    struct replay rx;       /* touched only by the decrypt thread        */
};

static struct session g_sess;
static int g_up;
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;

static int replay_ok(const struct replay *r, uint64_t c)
{
    if (!r->init || c > r->top) return 1;
    uint64_t d = r->top - c;
    if (d >= 64) return 0;                 /* too old */
    return !((r->bitmap >> d) & 1);        /* duplicate? */
}
static void replay_mark(struct replay *r, uint64_t c)
{
    if (!r->init) { r->init = 1; r->top = c; r->bitmap = 1; return; }
    if (c > r->top) {
        uint64_t sh = c - r->top;
        r->bitmap = sh >= 64 ? 0 : r->bitmap << sh;
        r->bitmap |= 1;
        r->top = c;
    } else {
        r->bitmap |= 1ULL << (r->top - c);
    }
}

typedef void (*install_fn)(const struct session *, void *);

static void install_global(const struct session *s, void *arg)
{
    (void)arg;
    pthread_rwlock_wrlock(&g_lock);
    g_sess = *s;
    g_up = 1;
    pthread_rwlock_unlock(&g_lock);
    LOG("secure session installed (protected traffic now flows)");
}
static void invalidate_global(void)
{
    pthread_rwlock_wrlock(&g_lock);
    int was = g_up;
    g_up = 0;
    OPENSSL_cleanse(&g_sess, sizeof g_sess);
    pthread_rwlock_unlock(&g_lock);
    if (was) WARN("session torn down; protected traffic is dropped (fail closed)");
}

/* ------------------------------------------------------------------ */
/* IPv4 / TCP parsing and checksums                                   */
/* ------------------------------------------------------------------ */
struct pkt { size_t iphl, tcphl, total, paylen; };

static int parse_pkt(const uint8_t *p, size_t len, struct pkt *k)
{
    if (len < 20 || (p[0] >> 4) != 4) return -1;
    size_t ihl = (size_t)(p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return -1;
    size_t tot = ((size_t)p[2] << 8) | p[3];
    if (tot > len || tot < ihl + 20) return -1;
    if (p[9] != IPPROTO_TCP) return -1;
    if ((((unsigned)p[6] << 8 | p[7]) & 0x3fff) != 0) return -1; /* fragment */
    size_t th = (size_t)(p[ihl + 12] >> 4) * 4;
    if (th < 20 || ihl + th > tot) return -1;
    k->iphl = ihl; k->tcphl = th; k->total = tot; k->paylen = tot - ihl - th;
    return 0;
}

static uint32_t csum_add(uint32_t sum, const uint8_t *d, size_t n)
{
    size_t i;
    for (i = 0; i + 1 < n; i += 2) sum += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) sum += (uint32_t)d[n - 1] << 8;
    return sum;
}
static uint16_t csum_fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static uint16_t tcp_csum(const uint8_t *p, size_t iphl, size_t total)
{
    size_t tl = total - iphl;
    uint32_t s = csum_add(0, p + 12, 8);       /* src + dst address */
    s += IPPROTO_TCP;
    s += (uint32_t)tl;
    s = csum_add(s, p + iphl, tl);
    return csum_fold(s);
}
static void fix_checksums(uint8_t *p, size_t iphl, size_t total)
{
    p[10] = p[11] = 0;
    uint16_t c = csum_fold(csum_add(0, p, iphl));
    p[10] = c >> 8; p[11] = (uint8_t)c;
    p[iphl + 16] = p[iphl + 17] = 0;
    c = tcp_csum(p, iphl, total);
    p[iphl + 16] = c >> 8; p[iphl + 17] = (uint8_t)c;
}

/*
 * AAD binds each ciphertext to the header fields no forwarder may change:
 *   IPv4 src, dst (8) | TCP sport, dport, seq, ack (12) | TCP flags byte (1)
 * so a packet cannot be replayed into a different flow/position and
 * SYN/FIN/RST/ACK flags are authenticated too.
 */
static void build_aad(const uint8_t *ip, const struct pkt *k, uint8_t aad[AAD_LEN])
{
    memcpy(aad, ip + 12, 8);
    memcpy(aad + 8, ip + k->iphl, 12);
    aad[20] = ip[k->iphl + 13];
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM                                                        */
/* ------------------------------------------------------------------ */
static int gcm_seal(EVP_CIPHER_CTX *c, const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aadl, const uint8_t *pt, size_t ptl,
                    uint8_t *ct, uint8_t *tag)
{
    int l, ok = -1;
    uint8_t fin[16];
    EVP_CIPHER_CTX_reset(c);
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto out;
    if (EVP_EncryptUpdate(c, NULL, &l, aad, (int)aadl) != 1) goto out;
    if (ptl && EVP_EncryptUpdate(c, ct, &l, pt, (int)ptl) != 1) goto out;
    if (EVP_EncryptFinal_ex(c, fin, &l) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto out;
    ok = 0;
out:
    return ok;
}

static int gcm_open(EVP_CIPHER_CTX *c, const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aadl, const uint8_t *ct, size_t ctl,
                    const uint8_t *tag, uint8_t *pt)
{
    int l, ok = -1;
    uint8_t fin[16];
    EVP_CIPHER_CTX_reset(c);
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto out;
    if (EVP_DecryptUpdate(c, NULL, &l, aad, (int)aadl) != 1) goto out;
    if (ctl && EVP_DecryptUpdate(c, pt, &l, ct, (int)ctl) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) goto out;
    if (EVP_DecryptFinal_ex(c, fin, &l) != 1) goto out;   /* tag verification */
    ok = 0;
out:
    return ok;
}

/* ------------------------------------------------------------------ */
/* per-packet protect / unprotect                                     */
/* ------------------------------------------------------------------ */
/* out must have room for MAX_IP + 1 bytes.  Returns 0 or -1 (drop). */
static int protect_packet(struct session *s, EVP_CIPHER_CTX *cx,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t *outlen)
{
    struct pkt k;
    if (parse_pkt(in, inlen, &k)) return -1;
    if (k.total + OVERHEAD > MAX_IP) return -1;

    /* unique nonce: unique counter, never reused, never wraps */
    uint64_t c = __atomic_fetch_add(&s->tx_ctr, 1, __ATOMIC_RELAXED);
    if (c >= CTR_LIMIT) return -1;

    size_t hl = k.iphl + k.tcphl;
    uint8_t nonce[NONCE_LEN], aad[AAD_LEN], tag[TAG_LEN];
    memcpy(nonce, s->tx_salt, SALT_LEN);
    put_be64(nonce + SALT_LEN, c);
    build_aad(in, &k, aad);

    memcpy(out, in, hl);
    if (gcm_seal(cx, s->tx_key, nonce, aad, AAD_LEN, in + hl, k.paylen, out + hl, tag))
        return -1;
    put_be64(out + hl + k.paylen, c);
    memcpy(out + hl + k.paylen + CTR_LEN, tag, TAG_LEN);

    size_t nt = k.total + OVERHEAD;
    out[2] = (uint8_t)(nt >> 8); out[3] = (uint8_t)nt;
    fix_checksums(out, k.iphl, nt);
    *outlen = nt;
    return 0;
}

static int unprotect_packet(struct session *s, EVP_CIPHER_CTX *cx,
                            const uint8_t *in, size_t inlen,
                            uint8_t *out, size_t *outlen)
{
    struct pkt k;
    if (parse_pkt(in, inlen, &k)) return -1;
    if (k.paylen < OVERHEAD) return -1;          /* cannot be a protected packet */

    size_t hl = k.iphl + k.tcphl, ctl = k.paylen - OVERHEAD;
    uint64_t c = get_be64(in + hl + ctl);
    const uint8_t *tag = in + hl + ctl + CTR_LEN;

    if (!replay_ok(&s->rx, c)) return -1;

    uint8_t nonce[NONCE_LEN], aad[AAD_LEN];
    memcpy(nonce, s->rx_salt, SALT_LEN);
    put_be64(nonce + SALT_LEN, c);
    build_aad(in, &k, aad);

    memcpy(out, in, hl);
    if (gcm_open(cx, s->rx_key, nonce, aad, AAD_LEN, in + hl, ctl, tag, out + hl))
        return -1;                                /* forged / corrupted */
    replay_mark(&s->rx, c);                       /* only after authentication */

    size_t nt = k.total - OVERHEAD;
    out[2] = (uint8_t)(nt >> 8); out[3] = (uint8_t)nt;
    fix_checksums(out, k.iphl, nt);
    *outlen = nt;
    return 0;
}

/* ------------------------------------------------------------------ */
/* crypto primitives for the handshake                                */
/* ------------------------------------------------------------------ */
static EVP_PKEY *dh_keygen(void)
{
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!c) return NULL;
    OSSL_PARAM par[2];
    par[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)DH_GROUP, 0);
    par[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_params(c, par) <= 0 ||
        EVP_PKEY_keygen(c, &pk) <= 0)
        pk = NULL;
    EVP_PKEY_CTX_free(c);
    return pk;
}

static int dh_export_pub(EVP_PKEY *k, uint8_t out[DH_LEN])
{
    BIGNUM *bn = NULL;
    if (!EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PUB_KEY, &bn)) return -1;
    int r = BN_bn2binpad(bn, out, DH_LEN);
    BN_free(bn);
    return r == DH_LEN ? 0 : -1;
}

/* import + validate peer public value (range and subgroup checks) */
static EVP_PKEY *dh_import_pub(const uint8_t in[DH_LEN])
{
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *b = NULL;
    OSSL_PARAM *par = NULL;
    EVP_PKEY_CTX *c = NULL, *v = NULL;
    BIGNUM *y = BN_bin2bn(in, DH_LEN, NULL);
    if (!y) return NULL;
    if (!(b = OSSL_PARAM_BLD_new())) goto out;
    if (!OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, DH_GROUP, 0) ||
        !OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, y)) goto out;
    if (!(par = OSSL_PARAM_BLD_to_param(b))) goto out;
    if (!(c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL))) goto out;
    if (EVP_PKEY_fromdata_init(c) <= 0 ||
        EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, par) <= 0) { pk = NULL; goto out; }
    v = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL);
    if (!v || EVP_PKEY_public_check(v) <= 0) { EVP_PKEY_free(pk); pk = NULL; }
out:
    EVP_PKEY_CTX_free(v); EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(par); OSSL_PARAM_BLD_free(b); BN_free(y);
    return pk;
}

static int dh_shared(EVP_PKEY *mine, EVP_PKEY *peer, uint8_t *secret, size_t *slen)
{
    int r = -1;
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    if (!d) return -1;
    size_t need = 0;
    if (EVP_PKEY_derive_init(d) > 0 && EVP_PKEY_derive_set_peer(d, peer) > 0 &&
        EVP_PKEY_derive(d, NULL, &need) > 0 && need <= *slen &&
        EVP_PKEY_derive(d, secret, &need) > 0) {
        *slen = need;
        r = 0;
    }
    EVP_PKEY_CTX_free(d);
    return r;
}

static int hkdf(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il,
                const char *info, uint8_t *out, size_t ol)
{
    int r = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kc = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (kc) {
        OSSL_PARAM p[5]; int n = 0;
        p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, sl);
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, il);
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
        p[n] = OSSL_PARAM_construct_end();
        r = EVP_KDF_derive(kc, out, ol, p) > 0 ? 0 : -1;
    }
    EVP_KDF_CTX_free(kc); EVP_KDF_free(kdf);
    return r;
}

static int mac_label(const uint8_t *key, const char *label, const uint8_t *th, uint8_t *out)
{
    uint8_t buf[64 + 32];
    size_t ll = strlen(label);
    if (ll > 64) return -1;
    memcpy(buf, label, ll);
    memcpy(buf + ll, th, 32);
    size_t ol = 0;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, KEY_LEN, buf, ll + 32,
                     out, MAC_LEN, &ol) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* control-channel framing                                            */
/* ------------------------------------------------------------------ */
enum { MSG_CH = 1, MSG_SH = 2, MSG_CF = 3, MSG_RDY = 4 };

static int io_write_all(int fd, const uint8_t *b, size_t n)
{
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        b += w; n -= (size_t)w;
    }
    return 0;
}
static int io_read_all(int fd, uint8_t *b, size_t n)
{
    while (n) {
        ssize_t r = recv(fd, b, n, 0);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        b += r; n -= (size_t)r;
    }
    return 0;
}
static int send_msg(int fd, uint8_t type, const uint8_t *body, size_t len)
{
    uint8_t h[7] = { 'S', 'G', 'W', '1', type, (uint8_t)(len >> 8), (uint8_t)len };
    if (io_write_all(fd, h, sizeof h)) return -1;
    return len ? io_write_all(fd, body, len) : 0;
}
static int recv_msg(int fd, uint8_t want, uint8_t *body, size_t len)
{
    uint8_t h[7];
    if (io_read_all(fd, h, sizeof h)) return -1;
    if (memcmp(h, "SGW1", 4) || h[4] != want || (((size_t)h[5] << 8) | h[6]) != len) return -1;
    return len ? io_read_all(fd, body, len) : 0;
}

/* ------------------------------------------------------------------ */
/* handshake                                                          */
/* ------------------------------------------------------------------ */
struct keys {
    uint8_t th[32];
    uint8_t k_i2r[KEY_LEN], k_r2i[KEY_LEN];
    uint8_t s_i2r[SALT_LEN], s_r2i[SALT_LEN];
    uint8_t confirm[KEY_LEN];
};

static int derive_keys(EVP_PKEY *mine, const uint8_t *peerpub,
                       const uint8_t *ch, const uint8_t *sh,
                       const uint8_t *psk, size_t psklen, struct keys *ks)
{
    int r = -1;
    EVP_PKEY *peer = dh_import_pub(peerpub);
    uint8_t secret[DH_LEN + 1], *ikm = NULL, okm[OKM_LEN], tr[2 * (DH_LEN + RAND_LEN)];
    size_t sl = sizeof secret;
    if (!peer) { WARN("peer DH public value rejected"); return -1; }
    if (dh_shared(mine, peer, secret, &sl)) goto out;

    memcpy(tr, ch, DH_LEN + RAND_LEN);
    memcpy(tr + DH_LEN + RAND_LEN, sh, DH_LEN + RAND_LEN);
    if (EVP_Digest(tr, sizeof tr, ks->th, NULL, EVP_sha256(), NULL) != 1) goto out;

    ikm = malloc(sl + psklen);
    if (!ikm) goto out;
    memcpy(ikm, secret, sl);
    if (psklen) memcpy(ikm + sl, psk, psklen);

    if (hkdf(ks->th, 32, ikm, sl + psklen, "SGW1 key schedule v1", okm, sizeof okm)) goto out;
    size_t o = 0;
    memcpy(ks->k_i2r, okm + o, KEY_LEN);  o += KEY_LEN;
    memcpy(ks->k_r2i, okm + o, KEY_LEN);  o += KEY_LEN;
    memcpy(ks->s_i2r, okm + o, SALT_LEN); o += SALT_LEN;
    memcpy(ks->s_r2i, okm + o, SALT_LEN); o += SALT_LEN;
    memcpy(ks->confirm, okm + o, KEY_LEN);
    r = 0;
out:
    if (ikm) { OPENSSL_cleanse(ikm, sl + psklen); free(ikm); }
    OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(okm, sizeof okm);
    EVP_PKEY_free(peer);
    return r;
}

static void fill_session(struct session *s, const struct keys *k, int initiator)
{
    memset(s, 0, sizeof *s);
    memcpy(s->tx_key, initiator ? k->k_i2r : k->k_r2i, KEY_LEN);
    memcpy(s->rx_key, initiator ? k->k_r2i : k->k_i2r, KEY_LEN);
    memcpy(s->tx_salt, initiator ? k->s_i2r : k->s_r2i, SALT_LEN);
    memcpy(s->rx_salt, initiator ? k->s_r2i : k->s_i2r, SALT_LEN);
}

/*
 * Flow:  I -> R : CH  = pub_i || rand_i
 *        R -> I : SH  = pub_r || rand_r || HMAC(confirm, "R-HELLO"||th)
 *        I -> R : CF  = HMAC(confirm, "I-FIN"||th)          (R installs)
 *        R -> I : RDY = HMAC(confirm, "R-RDY"||th)          (I installs)
 * Neither side starts using the session before the peer proved it derived
 * the same keys (key confirmation; with a PSK this also authenticates).
 */
static int do_handshake(int fd, int initiator, const uint8_t *psk, size_t psklen,
                        struct session *out, install_fn install, void *iarg)
{
    int rc = -1;
    struct timeval tv = { HS_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    EVP_PKEY *mine = dh_keygen();
    uint8_t ch[DH_LEN + RAND_LEN], sh[DH_LEN + RAND_LEN], shm[DH_LEN + RAND_LEN + MAC_LEN];
    uint8_t mac[MAC_LEN], exp[MAC_LEN];
    struct keys ks;
    memset(&ks, 0, sizeof ks);
    if (!mine) goto out;

    if (initiator) {
        if (dh_export_pub(mine, ch) || RAND_bytes(ch + DH_LEN, RAND_LEN) != 1) goto out;
        if (send_msg(fd, MSG_CH, ch, sizeof ch)) goto out;
        if (recv_msg(fd, MSG_SH, shm, sizeof shm)) goto out;
        memcpy(sh, shm, sizeof sh);
        if (derive_keys(mine, sh, ch, sh, psk, psklen, &ks)) goto out;
        if (mac_label(ks.confirm, "R-HELLO", ks.th, exp)) goto out;
        if (CRYPTO_memcmp(exp, shm + sizeof sh, MAC_LEN)) {
            WARN("handshake: responder key confirmation failed (PSK mismatch or MITM)");
            goto out;
        }
        if (mac_label(ks.confirm, "I-FIN", ks.th, mac) || send_msg(fd, MSG_CF, mac, MAC_LEN)) goto out;
        if (recv_msg(fd, MSG_RDY, mac, MAC_LEN)) goto out;
        if (mac_label(ks.confirm, "R-RDY", ks.th, exp) || CRYPTO_memcmp(exp, mac, MAC_LEN)) goto out;
        fill_session(out, &ks, 1);
        if (install) install(out, iarg);
    } else {
        if (recv_msg(fd, MSG_CH, ch, sizeof ch)) goto out;
        if (dh_export_pub(mine, sh) || RAND_bytes(sh + DH_LEN, RAND_LEN) != 1) goto out;
        if (derive_keys(mine, ch, ch, sh, psk, psklen, &ks)) goto out;
        memcpy(shm, sh, sizeof sh);
        if (mac_label(ks.confirm, "R-HELLO", ks.th, shm + sizeof sh)) goto out;
        if (send_msg(fd, MSG_SH, shm, sizeof shm)) goto out;
        if (recv_msg(fd, MSG_CF, mac, MAC_LEN)) goto out;
        if (mac_label(ks.confirm, "I-FIN", ks.th, exp) || CRYPTO_memcmp(exp, mac, MAC_LEN)) {
            WARN("handshake: initiator key confirmation failed (PSK mismatch or MITM)");
            goto out;
        }
        fill_session(out, &ks, 0);
        if (install) install(out, iarg);
        if (mac_label(ks.confirm, "R-RDY", ks.th, mac) || send_msg(fd, MSG_RDY, mac, MAC_LEN)) {
            goto out;
        }
    }
    rc = 0;
out:
    OPENSSL_cleanse(&ks, sizeof ks);
    EVP_PKEY_free(mine);
    if (rc) OPENSSL_cleanse(out, sizeof *out);
    struct timeval z = { 0, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &z, sizeof z);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &z, sizeof z);
    return rc;
}

/* ------------------------------------------------------------------ */
/* NFQUEUE workers                                                    */
/* ------------------------------------------------------------------ */
struct qarg {
    int qnum, is_encrypt;
    EVP_CIPHER_CTX *cctx;
    uint8_t *out;
};

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *data)
{
    (void)m;
    struct qarg *qa = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *pkt = NULL;
    int len = nfq_get_payload(nfa, &pkt);
    size_t outlen = 0;
    int rc = -1;

    if (len > 0) {
        pthread_rwlock_rdlock(&g_lock);
        if (!g_up) {
            STAT_INC(st_nosess);
        } else if (qa->is_encrypt) {
            rc = protect_packet(&g_sess, qa->cctx, pkt, (size_t)len, qa->out, &outlen);
            if (rc) STAT_INC(st_enc_drop); else STAT_INC(st_enc_ok);
        } else {
            rc = unprotect_packet(&g_sess, qa->cctx, pkt, (size_t)len, qa->out, &outlen);
            if (rc) STAT_INC(st_dec_drop); else STAT_INC(st_dec_ok);
        }
        pthread_rwlock_unlock(&g_lock);
    }
    if (rc == 0) {
        DBG("%s ok: %d -> %zu bytes", qa->is_encrypt ? "encrypt" : "decrypt", len, outlen);
        return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)outlen, qa->out);
    }
    DBG("%s DROP (len=%d)", qa->is_encrypt ? "encrypt" : "decrypt", len);
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void *queue_thread(void *arg)
{
    struct qarg *qa = arg;
    struct nfq_handle *h = nfq_open();
    struct nfq_q_handle *qh = NULL;
    uint8_t *buf = malloc(NFQ_BUFSZ);
    qa->out = malloc(MAX_IP + 64);
    qa->cctx = EVP_CIPHER_CTX_new();
    if (!h || !buf || !qa->out || !qa->cctx) {
        WARN("queue %d: setup failed (need CAP_NET_ADMIN / root?)", qa->qnum);
        g_stop = 1; goto done;
    }
    if (!(qh = nfq_create_queue(h, (uint16_t)qa->qnum, nfq_cb, qa))) {
        WARN("queue %d: nfq_create_queue failed (already in use?)", qa->qnum);
        g_stop = 1; goto done;
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(qh, 4096);
    int fd = nfq_fd(h), rb = 8 << 20;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof rb))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    LOG("queue %d (%s) ready", qa->qnum, qa->is_encrypt ? "encrypt" : "decrypt");

    while (!g_stop) {
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 500) <= 0) continue;
        ssize_t n = recv(fd, buf, NFQ_BUFSZ, 0);
        if (n < 0) {
            if (errno == ENOBUFS) { WARN("queue %d: kernel queue overflow", qa->qnum); continue; }
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        nfq_handle_packet(h, (char *)buf, (int)n);
    }
done:
    if (qh) nfq_destroy_queue(qh);
    if (h) nfq_close(h);
    EVP_CIPHER_CTX_free(qa->cctx);
    free(qa->out); free(buf);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* control thread (handshake + session supervision)                   */
/* ------------------------------------------------------------------ */
struct cfg {
    int initiator;
    struct in_addr peer, bind_addr;
    int have_peer;
    uint16_t port;
    int enc_q, dec_q;
    uint8_t *psk; size_t psklen;
    unsigned rekey_s;
};
static struct cfg g_cfg;

static void tune_sock(int fd)
{
    int one = 1, idle = 10, intvl = 5, cnt = 3;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static int tcp_connect(struct in_addr ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = ip };
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa)) { close(fd); return -1; }
    tune_sock(fd);
    return fd;
}

/* returns 1 if control connection died */
static int conn_dead(int fd)
{
    struct pollfd p = { fd, POLLIN, 0 };
    if (poll(&p, 1, 0) <= 0) return 0;
    uint8_t b[64];
    ssize_t n = recv(fd, b, sizeof b, MSG_DONTWAIT);
    if (n == 0) return 1;
    if (n < 0) return !(errno == EAGAIN || errno == EINTR);
    return 0;  /* unsolicited data: ignored */
}

static void *control_thread(void *arg)
{
    (void)arg;
    struct cfg *c = &g_cfg;
    struct session tmp;
    int cur = -1;
    time_t last = 0;

    if (c->initiator) {
        while (!g_stop) {
            int want = cur < 0 || (c->rekey_s && time(NULL) - last >= (time_t)c->rekey_s);
            if (want) {
                int nfd = tcp_connect(c->peer, c->port);
                if (nfd < 0) { DBG("control connect failed"); sleep(2); continue; }
                if (do_handshake(nfd, 1, c->psk, c->psklen, &tmp, install_global, NULL) == 0) {
                    if (cur >= 0) close(cur);
                    cur = nfd; last = time(NULL);
                } else {
                    WARN("handshake failed; retrying");
                    close(nfd); sleep(2); continue;
                }
                OPENSSL_cleanse(&tmp, sizeof tmp);
            }
            struct pollfd p = { cur, POLLIN, 0 };
            poll(&p, 1, 1000);
            if (cur >= 0 && conn_dead(cur)) {
                WARN("control connection lost");
                close(cur); cur = -1; invalidate_global();
            }
        }
        if (cur >= 0) close(cur);
    } else {
        int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(c->port),
                                  .sin_addr = c->bind_addr };
        if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 4)) {
            WARN("control listen failed: %s", strerror(errno));
            g_stop = 1; return NULL;
        }
        LOG("control channel listening on port %u", c->port);
        while (!g_stop) {
            struct pollfd p[2] = { { lfd, POLLIN, 0 }, { cur, POLLIN, 0 } };
            if (poll(p, cur >= 0 ? 2 : 1, 1000) < 0 && errno != EINTR) break;
            if (p[0].revents & POLLIN) {
                struct sockaddr_in ca; socklen_t cl = sizeof ca;
                int nfd = accept(lfd, (struct sockaddr *)&ca, &cl);
                if (nfd >= 0) {
                    if (c->have_peer && ca.sin_addr.s_addr != c->peer.s_addr) {
                        WARN("control connection from unexpected address rejected");
                        close(nfd);
                    } else {
                        tune_sock(nfd);
                        if (do_handshake(nfd, 0, c->psk, c->psklen, &tmp, install_global, NULL) == 0) {
                            if (cur >= 0) close(cur);
                            cur = nfd;
                        } else {
                            WARN("handshake failed; previous session (if any) kept");
                            close(nfd);
                        }
                        OPENSSL_cleanse(&tmp, sizeof tmp);
                    }
                }
            }
            if (cur >= 0 && conn_dead(cur)) {
                WARN("control connection lost");
                close(cur); cur = -1; invalidate_global();
            }
        }
        if (cur >= 0) close(cur);
        close(lfd);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* self-test (no root, no netfilter needed)                           */
/* ------------------------------------------------------------------ */
#include <sys/un.h>

static int t_fail;
#define CHECK(cond, msg) do { \
    if (cond) printf("  [PASS] %s\n", msg); \
    else { printf("  [FAIL] %s\n", msg); t_fail++; } } while (0)

static size_t build_test_pkt(uint8_t *p, uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp,
                             uint32_t seq, uint32_t ack, uint8_t flags,
                             const uint8_t *pl, size_t pll, size_t ipopt, size_t tcpopt)
{
    size_t ihl = 20 + ipopt, th = 20 + tcpopt, tot = ihl + th + pll;
    memset(p, 0, tot);
    p[0] = 0x40 | (uint8_t)(ihl / 4);
    p[2] = tot >> 8; p[3] = (uint8_t)tot;
    p[4] = 0x12; p[5] = 0x34; p[6] = 0x40;       /* id, DF */
    p[8] = 63; p[9] = IPPROTO_TCP;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    for (size_t i = 20; i < ihl; i++) p[i] = 1;  /* NOP options */
    uint8_t *t = p + ihl;
    t[0] = sp >> 8; t[1] = (uint8_t)sp; t[2] = dp >> 8; t[3] = (uint8_t)dp;
    for (int i = 0; i < 4; i++) { t[4 + i] = seq >> (24 - 8 * i); t[8 + i] = ack >> (24 - 8 * i); }
    t[12] = (uint8_t)((th / 4) << 4); t[13] = flags; t[14] = 0xff; t[15] = 0xff;
    for (size_t i = 20; i < th; i++) t[i] = 1;
    if (pll) memcpy(t + th, pl, pll);
    fix_checksums(p, ihl, tot);
    return tot;
}
static int csums_valid(const uint8_t *p)
{
    size_t ihl = (p[0] & 15) * 4, tot = ((size_t)p[2] << 8) | p[3];
    return csum_fold(csum_add(0, p, ihl)) == 0 && tcp_csum(p, ihl, tot) == 0;
}

struct hs_job { int fd; const uint8_t *psk; size_t pl; struct session *out; int rc; };
static void *hs_resp(void *a)
{
    struct hs_job *j = a;
    j->rc = do_handshake(j->fd, 0, j->psk, j->pl, j->out, NULL, NULL);
    close(j->fd);
    return NULL;
}
static void run_hs(const uint8_t *pi, size_t li, const uint8_t *pr, size_t lr,
                   struct session *A, struct session *B, int *rcA, int *rcB)
{
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct hs_job j = { sv[1], pr, lr, B, -1 };
    pthread_t th;
    pthread_create(&th, NULL, hs_resp, &j);
    *rcA = do_handshake(sv[0], 1, pi, li, A, NULL, NULL);
    close(sv[0]);
    pthread_join(th, NULL);
    *rcB = j.rc;
}

static int selftest(void)
{
    static uint8_t p1[70000], enc[70000], dec[70000], tmp[70000];
    struct session A, B;
    int ra, rb;
    EVP_CIPHER_CTX *ca = EVP_CIPHER_CTX_new(), *cb = EVP_CIPHER_CTX_new();
    const uint8_t psk[] = "0123456789abcdef0123456789abcdef";
    const char *msg = "GET /secret HTTP/1.1\r\nHost: pc2\r\nX-Token: TOP-SECRET-PAYLOAD\r\n\r\n";
    uint32_t ip1 = htonl(0x0a000102), ip2 = htonl(0x0a000202);
    size_t n, m, o;

    printf("== handshake ==\n");
    run_hs(psk, sizeof psk, psk, sizeof psk, &A, &B, &ra, &rb);
    CHECK(ra == 0 && rb == 0, "DH handshake with matching PSK succeeds on both sides");
    CHECK(!memcmp(A.tx_key, B.rx_key, 32) && !memcmp(A.rx_key, B.tx_key, 32), "keys agree (A.tx==B.rx, A.rx==B.tx)");
    CHECK(memcmp(A.tx_key, A.rx_key, 32) != 0 && memcmp(A.tx_salt, A.rx_salt, 4) != 0, "per-direction keys and salts differ");
    struct session A2, B2;
    run_hs(psk, sizeof psk, psk, sizeof psk, &A2, &B2, &ra, &rb);
    CHECK(memcmp(A.tx_key, A2.tx_key, 32) != 0, "fresh handshake yields fresh keys (ephemeral DH)");
    const uint8_t bad[] = "wrong-psk-wrong-psk-wrong-psk-00";
    struct session X, Y;
    run_hs(psk, sizeof psk, bad, sizeof bad, &X, &Y, &ra, &rb);
    CHECK(ra != 0 && rb != 0, "PSK mismatch is detected, no session installed");

    printf("== packet protection ==\n");
    n = build_test_pkt(p1, ip1, ip2, 40000, 8080, 1000, 77, 0x18, (const uint8_t *)msg, strlen(msg), 0, 12);
    CHECK(csums_valid(p1), "test packet has valid IP/TCP checksums");
    CHECK(protect_packet(&A, ca, p1, n, enc, &o) == 0, "encrypt ok");
    CHECK(o == n + OVERHEAD, "length grew by exactly 8-byte counter + 16-byte tag");
    size_t hl = 20 + 32;
    CHECK(!memcmp(enc + 12, p1 + 12, 8) && !memcmp(enc + 20, p1 + 20, 12) && enc[9] == 6,
          "IPv4 addresses/proto and TCP ports/seq/ack unchanged");
    CHECK(!memmem(enc, o, "TOP-SECRET", 10), "plaintext not visible on the wire");
    CHECK(!memcmp(enc + 20 + 20, p1 + 20 + 20, 12), "TCP options preserved");
    CHECK(csums_valid(enc), "encrypted packet carries valid IP and TCP checksums");
    CHECK(get_be64(enc + hl + strlen(msg)) == 0, "explicit counter field present (first packet = 0)");
    CHECK(unprotect_packet(&B, cb, enc, o, dec, &m) == 0, "peer verifies tag and decrypts");
    CHECK(m == n && !memcmp(dec, p1, n), "restored packet is byte-identical to the original");
    CHECK(csums_valid(dec), "restored packet has valid checksums");

    printf("== attacks ==\n");
    CHECK(unprotect_packet(&B, cb, enc, o, dec, &m) != 0, "replay of the same packet is rejected");
    struct session B3 = B; memset(&B3.rx, 0, sizeof B3.rx);
    memcpy(tmp, enc, o); tmp[hl + 3] ^= 1;
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "flipped ciphertext bit rejected");
    memcpy(tmp, enc, o); tmp[o - 1] ^= 1;
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "flipped tag bit rejected");
    memcpy(tmp, enc, o); tmp[hl + strlen(msg) + 7] ^= 1;
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "tampered counter (nonce) rejected");
    memcpy(tmp, enc, o); tmp[20 + 7] ^= 1; fix_checksums(tmp, 20, o);
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "tampered TCP seq (AAD) rejected");
    memcpy(tmp, enc, o); tmp[20 + 13] ^= 0x04; fix_checksums(tmp, 20, o);
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "tampered TCP flags (RST) rejected");
    memcpy(tmp, enc, o); tmp[16] ^= 1; fix_checksums(tmp, 20, o);
    CHECK(unprotect_packet(&B3, cb, tmp, o, dec, &m) != 0, "tampered destination IP rejected");
    CHECK(unprotect_packet(&B3, cb, p1, n, dec, &m) != 0, "plaintext packet injected on the protected link rejected");
    CHECK(unprotect_packet(&A, ca, enc, o, dec, &m) != 0, "reflection (packet fed back to sender) rejected");
    CHECK(unprotect_packet(&B2, cb, enc, o, dec, &m) != 0, "packet from a different session rejected");
    CHECK(unprotect_packet(&B3, cb, enc, o, dec, &m) == 0, "untampered packet still accepted afterwards");

    printf("== nonce uniqueness / ordering ==\n");
    struct session S = A; S.tx_ctr = 0;
    uint64_t prev = 0; int uniq = 1;
    for (int i = 0; i < 5000; i++) {
        protect_packet(&S, ca, p1, n, enc, &o);
        uint64_t c = get_be64(enc + hl + strlen(msg));
        if (i && c != prev + 1) uniq = 0;
        prev = c;
    }
    CHECK(uniq && prev == 4999, "5000 packets used 5000 distinct, strictly increasing counters");
    struct session T = A; T.tx_ctr = CTR_LIMIT;
    CHECK(protect_packet(&T, ca, p1, n, enc, &o) != 0, "sender refuses to encrypt when counter budget is exhausted");
    {
        struct session Sx = A, Rx = B; Sx.tx_ctr = 100; memset(&Rx.rx, 0, sizeof Rx.rx);
        uint8_t e1[2000], e2[2000], e3[2000]; size_t l1, l2, l3;
        protect_packet(&Sx, ca, p1, n, e1, &l1); protect_packet(&Sx, ca, p1, n, e2, &l2);
        protect_packet(&Sx, ca, p1, n, e3, &l3);
        CHECK(unprotect_packet(&Rx, cb, e3, l3, dec, &m) == 0 && unprotect_packet(&Rx, cb, e1, l1, dec, &m) == 0 &&
              unprotect_packet(&Rx, cb, e2, l2, dec, &m) == 0, "reordered delivery within the window is accepted");
        CHECK(unprotect_packet(&Rx, cb, e1, l1, dec, &m) != 0, "...and duplicates of reordered packets are rejected");
    }

    printf("== edge cases ==\n");
    n = build_test_pkt(p1, ip1, ip2, 40000, 8080, 5, 0, 0x02, NULL, 0, 4, 12); /* SYN w/ IP options */
    CHECK(protect_packet(&B2, cb, p1, n, enc, &o) == 0 && o == n + OVERHEAD, "empty-payload segment (SYN) is protected/authenticated too");
    CHECK(unprotect_packet(&A2, ca, enc, o, dec, &m) == 0 && m == n && !memcmp(dec, p1, n),
          "empty segment + IP options round-trips (reverse direction)");
    {
        static uint8_t big[2000];
        memset(big, 'A', sizeof big);
        n = build_test_pkt(p1, ip2, ip1, 8080, 40000, 9, 9, 0x10, big, 1400, 0, 0);
        CHECK(protect_packet(&A, ca, p1, n, enc, &o) == 0 && unprotect_packet(&B, cb, enc, o, dec, &m) == 0 &&
              m == n && !memcmp(dec, p1, n), "1400-byte payload round-trips");
        p1[6] |= 0x20; /* MF flag */
        CHECK(protect_packet(&A, ca, p1, n, enc, &o) != 0, "IP fragments are refused (dropped)");
    }
    EVP_CIPHER_CTX_free(ca); EVP_CIPHER_CTX_free(cb);
    printf("\n%s (%d failure%s)\n", t_fail ? "SELFTEST FAILED" : "SELFTEST OK", t_fail, t_fail == 1 ? "" : "s");
    return t_fail ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
static void on_sig(int s) { (void)s; g_stop = 1; }

static void usage(const char *a)
{
    fprintf(stderr,
        "usage: %s -m initiator|responder [options]\n"
        "  -m ROLE     initiator (Device1: connects) or responder (Device2: listens)\n"
        "  -p IP       peer device address on the control network (required for initiator;\n"
        "              for responder it restricts who may connect)\n"
        "  -b IP       responder: address to bind control listener (default 0.0.0.0)\n"
        "  -c PORT     control TCP port (default 5555)\n"
        "  -e N        NFQUEUE number for ENCRYPT path (default 0)\n"
        "  -d N        NFQUEUE number for DECRYPT path (default 1)\n"
        "  -k FILE     pre-shared key file (raw bytes) authenticating the handshake\n"
        "  -r SECS     initiator: renegotiate keys every SECS seconds (default off)\n"
        "  -v          verbose per-packet logging\n"
        "  -t          run built-in self-test and exit\n", a);
}

int main(int argc, char **argv)
{
    struct cfg *c = &g_cfg;
    c->port = 5555; c->enc_q = 0; c->dec_q = 1;
    c->bind_addr.s_addr = htonl(INADDR_ANY);
    const char *role = NULL, *pskfile = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "m:p:b:c:e:d:k:r:vth")) != -1) {
        switch (opt) {
        case 'm': role = optarg; break;
        case 'p': if (inet_pton(AF_INET, optarg, &c->peer) != 1) { usage(argv[0]); return 2; } c->have_peer = 1; break;
        case 'b': if (inet_pton(AF_INET, optarg, &c->bind_addr) != 1) { usage(argv[0]); return 2; } break;
        case 'c': c->port = (uint16_t)atoi(optarg); break;
        case 'e': c->enc_q = atoi(optarg); break;
        case 'd': c->dec_q = atoi(optarg); break;
        case 'k': pskfile = optarg; break;
        case 'r': c->rekey_s = (unsigned)atoi(optarg); break;
        case 'v': g_verbose = 1; break;
        case 't': return selftest();
        default: usage(argv[0]); return 2;
        }
    }
    if (!role || (strcmp(role, "initiator") && strcmp(role, "responder"))) { usage(argv[0]); return 2; }
    c->initiator = !strcmp(role, "initiator");
    if (c->initiator && !c->have_peer) { fprintf(stderr, "initiator needs -p\n"); return 2; }
    if (c->enc_q == c->dec_q) { fprintf(stderr, "-e and -d must differ\n"); return 2; }

    if (pskfile) {
        FILE *f = fopen(pskfile, "rb");
        if (!f) { perror(pskfile); return 1; }
        c->psk = malloc(4096);
        c->psklen = fread(c->psk, 1, 4096, f);
        fclose(f);
        if (c->psklen < 16) { fprintf(stderr, "PSK must be at least 16 bytes\n"); return 1; }
    } else {
        WARN("no PSK: handshake is unauthenticated and vulnerable to an active MITM on the control path");
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct qarg qe = { .qnum = c->enc_q, .is_encrypt = 1 }, qd = { .qnum = c->dec_q, .is_encrypt = 0 };
    pthread_t te, td, tc;
    LOG("starting as %s", role);
    pthread_create(&te, NULL, queue_thread, &qe);
    pthread_create(&td, NULL, queue_thread, &qd);
    pthread_create(&tc, NULL, control_thread, NULL);
    pthread_join(tc, NULL);
    g_stop = 1;
    pthread_join(te, NULL); pthread_join(td, NULL);

    LOG("stats: encrypted=%lu decrypted=%lu enc_drop=%lu dec_drop=%lu dropped_no_session=%lu",
        (unsigned long)st_enc_ok, (unsigned long)st_dec_ok, (unsigned long)st_enc_drop,
        (unsigned long)st_dec_drop, (unsigned long)st_nosess);
    invalidate_global();
    if (c->psk) { OPENSSL_cleanse(c->psk, 4096); free(c->psk); }
    return 0;
}
