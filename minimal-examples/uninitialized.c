// Run with:
// python run.py default glibc O2 bad uninitialized.c
// Results:
//   - WASM output: b'\n'
//   - Native output: b'out/uninitialized.c.native\n'
#include <stdio.h>

void CWE457_Use_of_Uninitialized_Variable__char_pointer_01_bad()
{
    char * data;
    /* POTENTIAL FLAW: Don't initialize data */
    /* POTENTIAL FLAW: Use data without initializing it */
    printf("%s\n", data);
}


int main(int argc, char * argv[])
{
    CWE457_Use_of_Uninitialized_Variable__char_pointer_01_bad();
    return 0;
}
