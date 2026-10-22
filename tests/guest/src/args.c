/* Checks the initial stack built by the loader: argc/argv/envp/auxv. */
int printf(const char *, ...);
char *getenv(const char *);
unsigned long getauxval(unsigned long);
int main(int argc, char **argv) {
    printf("argc=%d\n", argc);
    for (int i = 1; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    const char *v = getenv("XRUN_TEST");
    printf("XRUN_TEST=%s\n", v ? v : "(unset)");
    printf("pagesz=%lu\n", getauxval(6));
    printf("stack aligned=%d\n", ((unsigned long)__builtin_frame_address(0) & 15) == 0);
    return argc;
}
