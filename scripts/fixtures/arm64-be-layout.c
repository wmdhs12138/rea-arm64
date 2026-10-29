extern int puts(const char *);
volatile int rea_be_global=7;
int rea_be_probe(const char *text) { puts(text); return rea_be_global+3; }
