// Run with:
// python run.py default glibc O2 bad va.c
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// This seems to be an incorrect use of va_list! vprintf will read from the second argument, which is absent
void custom_format(char *data, ...)
{
  va_list args;
  va_start(args, data);
  vprintf("%s\n", args);
  va_end(args);
}

int main(int argc, char * argv[])
{
    char *buf = malloc(100 * sizeof(char));
    fgets(buf, 100, stdin);
    printf("%s\n", buf);
    custom_format(buf);
    free(buf);
    return 0;
}
