// Run with:
// python run.py default glibc O2 bad free.c
// Results:
//   - WASM return code: 0
//   - Native return code: -6
#include "std_testcase.h"

void CWE415_Double_Free__malloc_free_char_11_bad()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(globalReturnsTrue())
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
        free(data);
    }
    /* POTENTIAL FLAW: Possibly freeing memory twice */
    free(data);
}

int main(int argc, char * argv[])
{
    CWE415_Double_Free__malloc_free_char_11_bad();
    return 0;
}
