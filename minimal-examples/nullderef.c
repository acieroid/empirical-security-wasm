// Run with:
// python run.py default glibc O2 bad nullderef.c
// Results:
//   - WASM return code: 1
//   - Native return code: 0
#include <stdio.h>

void CWE690_NULL_Deref_From_Return__fopen_01_bad()
{
    FILE * data;
    /* Initialize data */
    data = NULL;
    /* POTENTIAL FLAW: Open a file without checking the return value for NULL */
    data = fopen("file.txt", "w+");
    /* FLAW: if the fopen failed, data will be NULL here */
    fclose(data);
}

int main(int argc, char * argv[])
{
    CWE690_NULL_Deref_From_Return__fopen_01_bad();
    return 0;
}
