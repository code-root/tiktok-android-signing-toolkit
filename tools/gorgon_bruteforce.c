/*
 * gorgon_bruteforce.c — X-Gorgon hex_str key discovery
 *
 * الفكرة: عندنا input معروف (url_md5, stub, cookie_md5, ts)
 *         وعندنا X-Gorgon المطلوب من traffic حقيقي
 *         نجرب كل قيم hex_str[8] حتى نجد التي تنتج نفس الـ X-Gorgon
 *
 * البحث:
 *   - نثبّت 4 bytes ونبحث في الـ 4 الأخرى = 256^4 ≈ 4.29 billion محاولة
 *   - أو نبحث في bytes محددة إذا عرفنا بعضها
 *
 * تجميع:
 *   gcc -O3 -march=native -o gorgon_bf gorgon_bruteforce.c -lpthread
 *
 * استخدام:
 *   ./gorgon_bf --url-md5 a3f2b1c4 --stub A3F2B1C4 \
 *               --cookie-md5 d7e3f100 --ts 1711111111 \
 *               --target "840400000000<40 hex chars>" \
 *               --threads 8 --fixed "1e,40,e0,d9,xx,xx,xx,xx"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

/* ══════════════════════════════════════════════════════════════
   نسخة C من خوارزمية X-Gorgon
   ══════════════════════════════════════════════════════════════ */

static void gorgon_ksa(const uint8_t hex_str[8], uint8_t table[256]) {
    for (int i = 0; i < 256; i++) table[i] = (uint8_t)i;
    int tmp = -1; /* -1 = ''  */
    for (int i = 0; i < 256; i++) {
        int A;
        if (i == 0) {
            A = 0;
        } else if (tmp >= 0) {
            A = tmp;
        } else {
            A = table[i - 1];
        }
        int B = hex_str[i % 8];
        if (A == 85 && i != 1 && tmp != 85) A = 0;
        int C = (A + i + B) % 256;
        tmp = (C < i) ? C : -1;
        table[i] = table[C];
    }
}

static void gorgon_prga(uint8_t inp[20], const uint8_t table_in[256]) {
    uint8_t tmp_copy[256];
    memcpy(tmp_copy, table_in, 256);
    int last_c = -1; /* -1 = list empty → B=0 */
    for (int i = 0; i < 20; i++) {
        int B = (last_c < 0) ? 0 : last_c;
        int C = ((int)table_in[i + 1] + B) % 256;
        last_c = C;
        int D = tmp_copy[C];
        tmp_copy[i + 1] = (uint8_t)D;
        int E = (D + D) % 256;
        int F = tmp_copy[E];
        inp[i] ^= (uint8_t)F;
    }
}

static void gorgon_handle(uint8_t inp[20]) {
    for (int i = 0; i < 20; i++) {
        uint8_t A = inp[i];
        uint8_t B = (uint8_t)(((A & 0x0F) << 4) | ((A & 0xF0) >> 4));
        uint8_t C = inp[(i + 1) % 20];
        uint8_t D = B ^ C;
        /* reverse bits */
        uint8_t E = 0;
        for (int b = 0; b < 8; b++)
            E |= ((D >> b) & 1) << (7 - b);
        uint8_t F = E ^ 20;
        inp[i] = (~F) & 0xFF;
    }
}

/* يحسب 40-char hex result فقط (بدون version prefix) */
static void compute_gorgon_sig(
    const uint8_t hex_str[8],
    const uint8_t inp_in[20],
    uint8_t result[20])
{
    uint8_t inp[20];
    memcpy(inp, inp_in, 20);
    uint8_t table[256];
    gorgon_ksa(hex_str, table);
    gorgon_prga(inp, table);
    gorgon_handle(inp);
    memcpy(result, inp, 20);
}

/* ══════════════════════════════════════════════════════════════
   بناء inp[20] من المدخلات
   ══════════════════════════════════════════════════════════════ */

static void hex4_to_bytes(const char *hex8, uint8_t out[4]) {
    for (int i = 0; i < 4; i++) {
        char tmp[3] = {hex8[i*2], hex8[i*2+1], 0};
        out[i] = (uint8_t)strtol(tmp, NULL, 16);
    }
}

static void build_inp(
    const char *url_md5_hex,   /* 32 hex chars */
    const char *stub_hex,      /* 32 hex chars أو "" */
    const char *cookie_md5_hex,/* 32 hex chars أو "" */
    uint32_t    ts,
    uint8_t     inp[20])
{
    memset(inp, 0, 20);
    /* [0:4] url md5 */
    hex4_to_bytes(url_md5_hex, inp);
    /* [4:8] stub */
    if (stub_hex && stub_hex[0])
        hex4_to_bytes(stub_hex, inp + 4);
    /* [8:12] cookie md5 */
    if (cookie_md5_hex && cookie_md5_hex[0])
        hex4_to_bytes(cookie_md5_hex, inp + 8);
    /* [12:16] zeros */
    /* [16:20] timestamp */
    char ts_hex[9];
    snprintf(ts_hex, sizeof(ts_hex), "%08x", ts);
    hex4_to_bytes(ts_hex, inp + 16);
}

/* ══════════════════════════════════════════════════════════════
   قراءة target sig (20 bytes) من X-Gorgon string
   X-Gorgon = version(4) + key_bytes(8) + sig(40) = 52 chars
   ══════════════════════════════════════════════════════════════ */

static int parse_target(const char *xgorgon, uint8_t target[20]) {
    size_t len = strlen(xgorgon);
    if (len < 52) {
        fprintf(stderr, "[!] X-Gorgon يجب أن يكون 52 حرف على الأقل\n");
        return -1;
    }
    /* sig يبدأ من موقع 12 */
    const char *sig = xgorgon + 12;
    for (int i = 0; i < 20; i++) {
        char tmp[3] = {sig[i*2], sig[i*2+1], 0};
        target[i] = (uint8_t)strtol(tmp, NULL, 16);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
   Multi-threaded brute force
   ══════════════════════════════════════════════════════════════ */

#define MAX_THREADS 64

typedef struct {
    int          thread_id;
    int          num_threads;
    uint8_t      inp[20];
    uint8_t      target[20];
    /* bytes الثابتة: -1 = free */
    int          fixed[8];
    /* النتيجة */
    int          found;
    uint8_t      found_key[8];
    uint64_t     attempts;
} ThreadArgs;

static volatile int g_found = 0;
static uint8_t      g_found_key[8];
static uint64_t     g_total_attempts = 0;

static void *brute_thread(void *arg) {
    ThreadArgs *a = (ThreadArgs *)arg;
    uint8_t hex_str[8];
    uint8_t result[20];
    uint64_t cnt = 0;

    /* حدد الـ bytes الحرة */
    int free_pos[8];
    int n_free = 0;
    for (int i = 0; i < 8; i++) {
        if (a->fixed[i] < 0)
            free_pos[n_free++] = i;
        else
            hex_str[i] = (uint8_t)a->fixed[i];
    }

    if (n_free == 0) {
        /* كل القيم ثابتة — جرب مرة واحدة */
        compute_gorgon_sig(hex_str, a->inp, result);
        cnt++;
        if (memcmp(result, a->target, 20) == 0) {
            a->found = 1;
            memcpy(a->found_key, hex_str, 8);
        }
        a->attempts = cnt;
        return NULL;
    }

    /* Space الكلي = 256^n_free */
    uint64_t total = 1;
    for (int i = 0; i < n_free; i++) total *= 256;

    uint64_t chunk = total / a->num_threads;
    uint64_t start = (uint64_t)a->thread_id * chunk;
    uint64_t end   = (a->thread_id == a->num_threads - 1) ? total : start + chunk;

    for (uint64_t idx = start; idx < end && !g_found; idx++) {
        /* تحويل idx إلى قيم للـ bytes الحرة */
        uint64_t tmp = idx;
        for (int j = 0; j < n_free; j++) {
            hex_str[free_pos[j]] = (uint8_t)(tmp % 256);
            tmp /= 256;
        }

        compute_gorgon_sig(hex_str, a->inp, result);
        cnt++;

        if (memcmp(result, a->target, 20) == 0) {
            if (!g_found) {
                g_found = 1;
                memcpy(g_found_key, hex_str, 8);
                a->found = 1;
                memcpy(a->found_key, hex_str, 8);
            }
            break;
        }
    }

    a->attempts = cnt;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
   Progress reporter
   ══════════════════════════════════════════════════════════════ */

static ThreadArgs *g_threads_arr = NULL;
static int         g_n_threads   = 0;

static void *progress_thread(void *arg) {
    (void)arg;
    while (!g_found) {
        sleep(5);
        if (g_found) break;
        uint64_t total = 0;
        for (int i = 0; i < g_n_threads; i++)
            total += g_threads_arr[i].attempts;
        fprintf(stderr, "\r[~] محاولات: %'llu  ...", (unsigned long long)total);
        fflush(stderr);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
   main
   ══════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog) {
    printf(
        "الاستخدام:\n"
        "  %s --url-md5 <32hex> --ts <unix>\n"
        "     [--stub <32hex>] [--cookie-md5 <32hex>]\n"
        "     --target <X-Gorgon-value>\n"
        "     [--fixed \"b0,b1,xx,b3,xx,xx,xx,b7\"]  (xx = free)\n"
        "     [--threads N]\n\n"
        "مثال (إصدار 8404 all-zeros):\n"
        "  %s --url-md5 a3f2b1c418e90000 --ts 1711111111 \\\n"
        "     --target 840400000000aabbccdd... \\\n"
        "     --fixed \"0,0,0,0,0,0,0,0\"\n\n"
        "مثال بحث في 4 bytes:\n"
        "  %s --url-md5 ... --ts ... --target ... \\\n"
        "     --fixed \"1e,40,e0,d9,xx,xx,xx,xx\" --threads 8\n\n",
        prog, prog, prog
    );
}

int main(int argc, char *argv[]) {
    /* defaults */
    char url_md5[33]    = "00000000000000000000000000000000";
    char stub[33]       = "";
    char cookie_md5[33] = "";
    uint32_t ts         = (uint32_t)time(NULL);
    char target_str[64] = "";
    int  n_threads      = 4;
    int  fixed[8]       = {-1,-1,-1,-1,-1,-1,-1,-1};

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--url-md5") && i+1 < argc) {
            strncpy(url_md5, argv[++i], 32);
        } else if (!strcmp(argv[i], "--stub") && i+1 < argc) {
            strncpy(stub, argv[++i], 32);
        } else if (!strcmp(argv[i], "--cookie-md5") && i+1 < argc) {
            strncpy(cookie_md5, argv[++i], 32);
        } else if (!strcmp(argv[i], "--ts") && i+1 < argc) {
            ts = (uint32_t)atol(argv[++i]);
        } else if (!strcmp(argv[i], "--target") && i+1 < argc) {
            strncpy(target_str, argv[++i], 63);
        } else if (!strcmp(argv[i], "--threads") && i+1 < argc) {
            n_threads = atoi(argv[++i]);
            if (n_threads < 1) n_threads = 1;
            if (n_threads > MAX_THREADS) n_threads = MAX_THREADS;
        } else if (!strcmp(argv[i], "--fixed") && i+1 < argc) {
            char *s = argv[++i];
            char *tok = strtok(s, ",");
            for (int j = 0; j < 8 && tok; j++) {
                if (strcmp(tok, "xx") == 0 || strcmp(tok, "?") == 0)
                    fixed[j] = -1;
                else
                    fixed[j] = (int)strtol(tok, NULL, 0);
                tok = strtok(NULL, ",");
            }
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!target_str[0]) {
        print_usage(argv[0]);
        fprintf(stderr, "[!] يجب توفير --target\n");
        return 1;
    }

    /* بناء inp */
    uint8_t inp[20];
    build_inp(url_md5, stub[0] ? stub : NULL,
              cookie_md5[0] ? cookie_md5 : NULL, ts, inp);

    /* parse target */
    uint8_t target[20];
    if (parse_target(target_str, target) < 0) return 1;

    /* عدد الـ bytes الحرة */
    int n_free = 0;
    for (int i = 0; i < 8; i++) if (fixed[i] < 0) n_free++;
    uint64_t search_space = 1;
    for (int i = 0; i < n_free; i++) search_space *= 256;

    printf("[+] بدء البحث:\n");
    printf("    url_md5    = %.32s\n", url_md5);
    printf("    ts         = %u\n", ts);
    printf("    target_sig = %.40s\n", target_str + 12);
    printf("    bytes حرة  = %d  →  فضاء البحث = %llu\n",
           n_free, (unsigned long long)search_space);
    printf("    threads    = %d\n\n", n_threads);
    fflush(stdout);

    /* إعداد threads */
    ThreadArgs *targs = calloc(n_threads, sizeof(ThreadArgs));
    pthread_t  *tids  = calloc(n_threads, sizeof(pthread_t));
    g_threads_arr = targs;
    g_n_threads   = n_threads;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < n_threads; i++) {
        targs[i].thread_id   = i;
        targs[i].num_threads = n_threads;
        memcpy(targs[i].inp,    inp,    20);
        memcpy(targs[i].target, target, 20);
        memcpy(targs[i].fixed,  fixed,  8 * sizeof(int));
        targs[i].found    = 0;
        targs[i].attempts = 0;
    }

    /* thread للـ progress */
    pthread_t prog_tid;
    pthread_create(&prog_tid, NULL, progress_thread, NULL);

    for (int i = 0; i < n_threads; i++)
        pthread_create(&tids[i], NULL, brute_thread, &targs[i]);

    for (int i = 0; i < n_threads; i++)
        pthread_join(tids[i], NULL);

    g_found = 2; /* إيقاف progress thread */
    pthread_join(prog_tid, NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    uint64_t total_att = 0;
    for (int i = 0; i < n_threads; i++) total_att += targs[i].attempts;

    printf("\n[+] انتهى في %.2f ثانية  (%.1f M/s)\n",
           elapsed, (double)total_att / elapsed / 1e6);
    printf("[+] إجمالي المحاولات: %llu\n", (unsigned long long)total_att);

    if (g_found == 2 && !memcmp(g_found_key, (uint8_t[8]){0}, 0)) {
        /* تحقق من وجود نتيجة */
        int any_found = 0;
        for (int i = 0; i < n_threads; i++) {
            if (targs[i].found) { any_found = 1; break; }
        }
        if (!any_found) {
            printf("\n❌ لم يُعثر على hex_str مطابق.\n");
            printf("   → التوقيع في native library (.so) وليس في Java layer\n");
            printf("   → جرب تعديل --fixed لتوسيع نطاق البحث\n");
        }
    } else if (g_found) {
        printf("\n✅ hex_str وُجد!\n");
        printf("   [");
        for (int i = 0; i < 8; i++)
            printf("%d%s", g_found_key[i], i < 7 ? ", " : "");
        printf("]\n");
        printf("   hex: ");
        for (int i = 0; i < 8; i++)
            printf("%02x ", g_found_key[i]);
        printf("\n");
    }

    free(targs);
    free(tids);
    return g_found ? 0 : 2;
}
