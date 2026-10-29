extern int rea_be_probe(const char *);
int puts(const char *p) { return (unsigned char)*p; }
void _start(void) { volatile int result=rea_be_probe("REA"); (void)result; }
