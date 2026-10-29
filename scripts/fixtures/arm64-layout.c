#include <stdio.h>
volatile int rea_global = 9;
__attribute__((noinline)) int rea_layout_probe(const char *text) {
    char buffer[32];
    buffer[0] = text[0];
    puts("REA AArch64 layout probe");
    return rea_global + buffer[0];
}
int main(int argc, char **argv) {
    return rea_layout_probe(argc > 1 ? argv[1] : "probe");
}
