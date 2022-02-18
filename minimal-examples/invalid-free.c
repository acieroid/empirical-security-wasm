// Run with:
// python run.py default glibc O2 bad invalid-free.c
// Results:
//   - WASM return code: 0
//    - Native return code: -6
#include "std_testcase.h"

void CWE590_Free_Memory_Not_on_Heap__free_char_alloca_09_bad()
{
    char * data;
    data = NULL; /* Initialize data */
    if(GLOBAL_CONST_TRUE)
    {
      /* FLAW: data is allocated on the stack and deallocated in the BadSink */
      char * dataBuffer = (char *)ALLOCA(100*sizeof(char));
      memset(dataBuffer, 'A', 100-1); /* fill with 'A's */
      dataBuffer[100-1] = '\0'; /* null terminate */
      data = dataBuffer;
    }
    /* POTENTIAL FLAW: Possibly deallocating memory allocated on the stack */
    free(data);
}

int main(int argc, char * argv[])
{
    CWE590_Free_Memory_Not_on_Heap__free_char_alloca_09_bad();
    return 0;
}
