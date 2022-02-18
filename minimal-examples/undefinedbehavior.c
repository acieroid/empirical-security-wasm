// Run with
// python run.py default glibc O2 bad undefinedbehavior.c
// Results
//   - WASM output: b'\n'
//   - Native output: b'out/undefinedbehavior.c.native\n'
#include "std_testcase.h"

void CWE758_Undefined_Behavior__char_pointer_alloca_use_01_bad()
{
    {
        char * * pointer = (char * *)ALLOCA(sizeof(char *));
        char * data = *pointer; /* FLAW: the value pointed to by pointer is undefined */
        printf("%s\n", data);
    }
}

int main(int argc, char * argv[])
{
    CWE758_Undefined_Behavior__char_pointer_alloca_use_01_bad();
}
