// Run with:
// python run.py default glibc O2 bad stack.c
// Result:
//   - WebAssembly: prints 0 and returns successfully
//   - native: prints 0 and crashes (stack smashing detected)
#include "std_testcase.h"

void CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_09_bad()
{
    int * data;
    data = NULL;
    if(GLOBAL_CONST_TRUE) // Necessary, otherwise optimizations simplify the program too much and remove the cause of the divergence
    {
        /* FLAW: Allocate memory without using sizeof(int) */
        data = (int *)ALLOCA(10);
    }
    int source[10] = {0};
    size_t i;
    /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
    for (i = 0; i < 10; i++) {
      data[i] = source[i];
    }
    printIntLine(data[0]);
}

int main(int argc, char * argv[])
{
    CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_09_bad();
    return 0;
}
