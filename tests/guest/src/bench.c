/* Deterministic CPU benchmarks. Output must be identical on every platform. */
typedef unsigned long size_t;
typedef unsigned int u32;
typedef unsigned long long u64;
int printf(const char *, ...);
int sprintf(char *, const char *, ...);
int atoi(const char *);
void *malloc(size_t);
void free(void *);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
size_t strlen(const char *);
int strcmp(const char *, const char *);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));

static u32 sieve(u32 n) {
    char *c = malloc(n + 1);
    memset(c, 1, n + 1);
    u32 count = 0;
    for (u32 i = 2; i <= n; i++) {
        if (!c[i]) continue;
        count++;
        for (u64 j = (u64)i * i; j <= n; j += i) c[j] = 0;
    }
    free(c);
    return count;
}

static u32 crc_table[256];
static u32 crc32(const unsigned char *p, size_t n, int rounds) {
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
    u32 crc = 0;
    for (int r = 0; r < rounds; r++) {
        crc = ~crc;
        for (size_t i = 0; i < n; i++) crc = crc_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
        crc = ~crc;
    }
    return crc;
}

static u32 fib(u32 n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static u64 rng = 88172645463325252ull;
static u64 xorshift(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}
static int cmp_u64(const void *a, const void *b) {
    u64 x = *(const u64 *)a, y = *(const u64 *)b;
    return x < y ? -1 : x > y;
}
static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static u64 sort_bench(int n) {
    u64 *v = malloc(n * sizeof *v);
    for (int i = 0; i < n; i++) v[i] = xorshift();
    qsort(v, n, sizeof *v, cmp_u64);
    u64 h = 0;
    for (int i = 0; i < n; i++) h = h * 31 + (v[i] >> 40);
    free(v);
    return h;
}

static u64 string_bench(int n) {
    char **s = malloc(n * sizeof *s);
    char buf[64];
    for (int i = 0; i < n; i++) {
        int len = sprintf(buf, "item-%llx-%d", xorshift() & 0xffffff, i % 97);
        s[i] = malloc(len + 1);
        memcpy(s[i], buf, len + 1);
    }
    qsort(s, n, sizeof *s, cmp_str);
    u64 h = 0;
    for (int i = 0; i < n; i++) { h = h * 131 + strlen(s[i]) + (unsigned char)s[i][5]; free(s[i]); }
    free(s);
    return h;
}

static u64 matmul(int n) {
    long *a = malloc(n * n * sizeof(long)), *b = malloc(n * n * sizeof(long)), *c = malloc(n * n * sizeof(long));
    for (int i = 0; i < n * n; i++) { a[i] = i % 13 - 6; b[i] = i % 7 - 3; }
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            long s = 0;
            for (int k = 0; k < n; k++) s += a[i * n + k] * b[k * n + j];
            c[i * n + j] = s;
        }
    u64 h = 0;
    for (int i = 0; i < n * n; i++) h = h * 7 + (u64)c[i];
    free(a); free(b); free(c);
    return h;
}

static double fp_bench(int n) {
    double s = 0, x = 1.0;
    for (int i = 1; i <= n; i++) { x = x * 1.0000001 + 1.0 / i; s += x / (i + 0.5); }
    return s;
}

int main(int argc, char **argv) {
    int scale = argc > 1 ? atoi(argv[1]) : 1;
    printf("sieve: %u\n", sieve(200000 * scale));
    static unsigned char data[65536];
    for (int i = 0; i < (int)sizeof data; i++) data[i] = (unsigned char)(i * 7 + (i >> 8));
    printf("crc32: %08x\n", crc32(data, sizeof data, 4 * scale));
    printf("fib: %u\n", fib(20 + (scale > 1 ? 4 : 0)));
    printf("sort: %llx\n", sort_bench(20000 * scale));
    printf("strings: %llx\n", string_bench(5000 * scale));
    printf("matmul: %llx\n", matmul(40 + 20 * (scale > 1)));
    /* printf("%f") goes through x87 long double in musl (stage 2), so print the bits. */
    double f = fp_bench(100000 * scale);
    printf("fp: %llx\n", *(u64 *)&f >> 16);
    return 0;
}
