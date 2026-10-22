/*
 * Differential-testing oracle.
 *
 * Built as an x86-64 macOS binary and run under Rosetta 2, i.e. on an
 * independent, production-quality x86-64 implementation. For every
 * instruction in the table below it generates register/flag inputs, executes
 * the real instruction and prints inputs and outputs. The interpreter test
 * (crates/x86-cpu/tests/oracle.rs) replays every line and must agree on all
 * architecturally defined results.
 *
 *   tools/oracle/regen.sh
 *
 * Output line: hex mask | rax rbx rcx rdx rsi rdi rflags | rax' ... rflags'
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

struct state { uint64_t r[6]; uint64_t flags; }; /* rax rbx rcx rdx rsi rdi */

enum tag { T_NONE, T_DIV, T_IDIV, T_CMPXCHG };

struct op { char hex[48]; unsigned mask; enum tag tag; int size; };
static struct op ops[1024];
static int nops;

#define ALL 0x8d5   /* CF PF AF ZF SF OF */
#define NOAF 0x8c5
#define CF 0x1
#define ZF 0x40

static void add(const char *hex, unsigned mask, enum tag tag, int size) {
    struct op *o = &ops[nops++];
    snprintf(o->hex, sizeof o->hex, "%s", hex);
    o->mask = mask; o->tag = tag; o->size = size;
}

/* Operand-size prefix for 2/4/8 byte forms. */
static const char *pfx(int size) { return size == 2 ? "66 " : size == 8 ? "48 " : ""; }

static void table(void) {
    char b[64];
    static const int sizes[] = {1, 2, 4, 8};
    /* ALU r/m, reg: add or adc sbb and sub xor cmp  (rax <- rax op rbx) */
    for (int op = 0; op < 8; op++)
        for (int k = 0; k < 4; k++) {
            int s = sizes[k];
            snprintf(b, sizeof b, "%s%02x d8", s == 1 ? "" : pfx(s), op * 8 + (s != 1));
            add(b, (op == 1 || op == 4 || op == 6) ? NOAF : ALL, T_NONE, s);
        }
    /* ALU with sign-extended imm8 and imm32 */
    for (int op = 0; op < 8; op++) {
        snprintf(b, sizeof b, "48 83 %02x 80", 0xc0 | op << 3); add(b, (op == 1 || op == 4 || op == 6) ? NOAF : ALL, T_NONE, 8);
        snprintf(b, sizeof b, "81 %02x 78 56 34 92", 0xc0 | op << 3); add(b, (op == 1 || op == 4 || op == 6) ? NOAF : ALL, T_NONE, 4);
        snprintf(b, sizeof b, "80 %02x 7f", 0xc0 | op << 3); add(b, (op == 1 || op == 4 || op == 6) ? NOAF : ALL, T_NONE, 1);
    }
    add("00 fc", ALL, T_NONE, 1);       /* add ah, bh */
    add("28 fc", ALL, T_NONE, 1);       /* sub ah, bh */
    add("40 00 f0", ALL, T_NONE, 1);    /* add al, sil */
    add("88 f8", ALL, T_NONE, 1);       /* mov al, bh */
    add("84 c3", NOAF, T_NONE, 1);      /* test bl, al */
    add("48 85 d8", NOAF, T_NONE, 8);   /* test rax, rbx */
    add("a9 00 ff 00 80", NOAF, T_NONE, 4); /* test eax, imm32 */
    for (int k = 0; k < 4; k++) {
        int s = sizes[k];
        const char *p = s == 1 ? "" : pfx(s);
        int opc = s == 1 ? 0xfe : 0xff, un = s == 1 ? 0xf6 : 0xf7;
        snprintf(b, sizeof b, "%s%02x c0", p, opc); add(b, ALL, T_NONE, s);  /* inc */
        snprintf(b, sizeof b, "%s%02x c8", p, opc); add(b, ALL, T_NONE, s);  /* dec */
        snprintf(b, sizeof b, "%s%02x d8", p, un); add(b, ALL, T_NONE, s);   /* neg */
        snprintf(b, sizeof b, "%s%02x d0", p, un); add(b, ALL, T_NONE, s);   /* not */
        snprintf(b, sizeof b, "%s%02x e3", p, un); add(b, CF | 0x800, T_NONE, s); /* mul rbx */
        snprintf(b, sizeof b, "%s%02x eb", p, un); add(b, CF | 0x800, T_NONE, s); /* imul rbx */
        /* shifts/rotates by CL: rol ror rcl rcr shl shr sar */
        static const int sh[] = {0, 1, 2, 3, 4, 5, 7};
        for (int j = 0; j < 7; j++) {
            int n = sh[j], rot = n < 4;
            unsigned m = rot ? (ALL & ~0x800) : (s >= 4 ? 0xc5 : 0xc4);
            snprintf(b, sizeof b, "%s%02x %02x", p, s == 1 ? 0xd2 : 0xd3, 0xc0 | n << 3); add(b, m, T_NONE, s);
            snprintf(b, sizeof b, "%s%02x %02x", p, s == 1 ? 0xd0 : 0xd1, 0xc0 | n << 3); add(b, rot ? ALL : NOAF, T_NONE, s);
            snprintf(b, sizeof b, "%s%02x %02x 03", p, s == 1 ? 0xc0 : 0xc1, 0xc0 | n << 3); add(b, rot ? (ALL & ~0x800) : 0xc5, T_NONE, s);
        }
    }
    for (int k = 1; k < 4; k++) {
        int s = sizes[k];
        const char *p = pfx(s);
        snprintf(b, sizeof b, "%s0f af c3", p); add(b, CF | 0x800, T_NONE, s);        /* imul rax, rbx */
        snprintf(b, sizeof b, "%s6b c3 f9", p); add(b, CF | 0x800, T_NONE, s);        /* imul rax, rbx, -7 */
        snprintf(b, sizeof b, "%s0f a3 d8", p); add(b, CF, T_NONE, s);                /* bt  rax, rbx */
        snprintf(b, sizeof b, "%s0f ab d8", p); add(b, CF, T_NONE, s);                /* bts */
        snprintf(b, sizeof b, "%s0f b3 d8", p); add(b, CF, T_NONE, s);                /* btr */
        snprintf(b, sizeof b, "%s0f bb d8", p); add(b, CF, T_NONE, s);                /* btc */
        snprintf(b, sizeof b, "%s0f ba e0 05", p); add(b, CF, T_NONE, s);             /* bt rax, 5 */
        snprintf(b, sizeof b, "%s0f ba f8 23", p); add(b, CF, T_NONE, s);             /* btc rax, 35 */
        snprintf(b, sizeof b, "%s0f bc c3", p); add(b, ZF, T_NONE, s);                /* bsf */
        snprintf(b, sizeof b, "%s0f bd c3", p); add(b, ZF, T_NONE, s);                /* bsr */
        snprintf(b, sizeof b, "f3 %s0f b8 c3", p); add(b, ALL, T_NONE, s);            /* popcnt */
        snprintf(b, sizeof b, "f3 %s0f bd c3", p); add(b, CF | ZF, T_NONE, s);        /* lzcnt */
        snprintf(b, sizeof b, "%s87 d8", p); add(b, ALL, T_NONE, s);                  /* xchg rax, rbx */
        snprintf(b, sizeof b, "%s0f c1 d8", p); add(b, ALL, T_NONE, s);               /* xadd rax, rbx */
        /* cmpxchg rcx, rbx: only ZF is compared. Rosetta 2 sets CF/SF/AF/PF/OF from
         * dest - rax; the SDM ("as CMP accumulator, dest"), KVM and Bochs use rax - dest,
         * which is what we implement. See docs/decisions/stage1.md. */
        snprintf(b, sizeof b, "%s0f b1 d9", p); add(b, ZF, T_CMPXCHG, s);
        snprintf(b, sizeof b, "%s0f be c3", p); add(b, ALL, T_NONE, s);               /* movsx r, bl */
        snprintf(b, sizeof b, "%s0f b6 c3", p); add(b, ALL, T_NONE, s);               /* movzx r, bl */
        snprintf(b, sizeof b, "%s98", p); add(b, ALL, T_NONE, s);                     /* cbw/cwde/cdqe */
        snprintf(b, sizeof b, "%s99", p); add(b, ALL, T_NONE, s);                     /* cwd/cdq/cqo */
        snprintf(b, sizeof b, "%s8d 44 9e 10", p); add(b, ALL, T_NONE, s);            /* lea r, [rsi+rbx*4+16] */
        if (s >= 4) {
            snprintf(b, sizeof b, "%s0f a5 d8", p); add(b, 0xc5, T_NONE, s);          /* shld rax, rbx, cl */
            snprintf(b, sizeof b, "%s0f ad d8", p); add(b, 0xc5, T_NONE, s);          /* shrd rax, rbx, cl */
            snprintf(b, sizeof b, "%s0f a4 d8 07", p); add(b, 0xc5, T_NONE, s);       /* shld rax, rbx, 7 */
            snprintf(b, sizeof b, "%s0f ac d8 01", p); add(b, NOAF, T_NONE, s);       /* shrd rax, rbx, 1 */
            snprintf(b, sizeof b, "%s0f c8", p); add(b, ALL, T_NONE, s);              /* bswap */
            snprintf(b, sizeof b, "%sf7 f3", p); add(b, 0, T_DIV, s);                 /* div rbx */
            snprintf(b, sizeof b, "%sf7 fb", p); add(b, 0, T_IDIV, s);                /* idiv rbx */
        }
        for (int cc = 0; cc < 16; cc++) {
            snprintf(b, sizeof b, "%s0f %02x c3", p, 0x40 + cc); add(b, ALL, T_NONE, s); /* cmovcc */
        }
    }
    for (int cc = 0; cc < 16; cc++) {
        snprintf(b, sizeof b, "0f %02x c0", 0x90 + cc); add(b, ALL, T_NONE, 1);     /* setcc al */
    }
    add("48 63 c3", ALL, T_NONE, 8);          /* movsxd rax, ebx */
    add("48 0f bf c3", ALL, T_NONE, 8);       /* movsx rax, bx */
    add("67 48 8d 44 9e 10", ALL, T_NONE, 8); /* lea rax, [esi+ebx*4+16] */
    add("48 8d 04 5b", ALL, T_NONE, 8);       /* lea rax, [rbx+rbx*2] */
    add("f9", ALL, T_NONE, 8);                /* stc */
    add("f8", ALL, T_NONE, 8);                /* clc */
    add("f5", ALL, T_NONE, 8);                /* cmc */
    add("9e", ALL, T_NONE, 8);                /* sahf */
    add("9f", ALL, T_NONE, 8);                /* lahf */
}

static uint64_t rs = 0x2545F4914F6CDD1Dull;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static const uint64_t edges[] = {
    0, 1, 2, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff,
    0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull, 0x0123456789abcdefull,
};
#define NEDGE (sizeof edges / sizeof edges[0])

static uint64_t mask_of(int s) { return s == 8 ? ~0ull : (1ull << (8 * s)) - 1; }
static uint64_t sx(uint64_t v, int s) { int sh = 64 - 8 * s; return (uint64_t)((int64_t)(v << sh) >> sh); }

static const uint8_t pro[] = {
    0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x49, 0x89, 0xff,
    0x41, 0xff, 0x77, 0x30, 0x9d,
    0x49, 0x8b, 0x47, 0x00, 0x49, 0x8b, 0x5f, 0x08, 0x49, 0x8b, 0x4f, 0x10,
    0x49, 0x8b, 0x57, 0x18, 0x49, 0x8b, 0x77, 0x20, 0x49, 0x8b, 0x7f, 0x28,
};
static const uint8_t epi[] = {
    0x9c, 0x41, 0x8f, 0x47, 0x30,
    0x49, 0x89, 0x47, 0x00, 0x49, 0x89, 0x5f, 0x08, 0x49, 0x89, 0x4f, 0x10,
    0x49, 0x89, 0x57, 0x18, 0x49, 0x89, 0x77, 0x20, 0x49, 0x89, 0x7f, 0x28,
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3,
};

int main(int argc, char **argv) {
    int per_op = argc > 1 ? atoi(argv[1]) : 48;
    uint8_t *code = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED) { perror("mmap"); return 1; }
    table();
    for (int i = 0; i < nops; i++) {
        struct op *o = &ops[i];
        uint8_t insn[16]; int n = 0;
        for (char *p = o->hex; *p;) { insn[n++] = (uint8_t)strtoul(p, &p, 16); while (*p == ' ') p++; }
        size_t len = 0;
        memcpy(code, pro, sizeof pro); len += sizeof pro;
        memcpy(code + len, insn, n); len += n;
        memcpy(code + len, epi, sizeof epi);
        void (*fn)(struct state *) = (void (*)(struct state *))code;
        for (int c = 0; c < per_op; c++) {
            struct state st;
            for (int r = 0; r < 6; r++) st.r[r] = rnd();
            if (c < (int)(NEDGE * 2)) { st.r[0] = edges[c % NEDGE]; st.r[1] = edges[(c * 7 + c / NEDGE) % NEDGE]; }
            if (rnd() & 1) st.r[2] = rnd() % 70;            /* small shift counts in CL */
            if (c % 5 == 0) st.r[1] = st.r[0];             /* equal operands */
            st.flags = (rnd() & ALL) | 0x2;
            uint64_t m = mask_of(o->size);
            if (o->tag == T_CMPXCHG && c % 2) st.r[2] = st.r[0];
            if (o->tag == T_DIV) {
                st.r[1] = (st.r[1] & m) | 1;
                st.r[3] = (st.r[3] & m) % (st.r[1] & m);
            }
            if (o->tag == T_IDIV) {
                st.r[1] = sx(st.r[1] | 1, o->size);
                if ((st.r[1] & m) == m) st.r[1] = 3;
                st.r[3] = (st.r[0] & (1ull << (8 * o->size - 1))) ? m : 0;
            }
            struct state in = st;
            fn(&st);
            printf("%s|%x|", o->hex, o->mask);
            for (int r = 0; r < 6; r++) printf("%llx ", (unsigned long long)in.r[r]);
            printf("%llx|", (unsigned long long)in.flags);
            for (int r = 0; r < 6; r++) printf("%llx ", (unsigned long long)st.r[r]);
            printf("%llx\n", (unsigned long long)(st.flags & ALL));
        }
    }
    return 0;
}
