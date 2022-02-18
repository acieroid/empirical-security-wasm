// Run with:
// python run.py default glibc O2 bad freopen.c
// Results:
//   - WASM return code: 1
//   - Native return code: 0
#include <stdio.h>

void CWE675_Duplicate_Operations_on_Resource__freopen_01_bad()
{
    FILE * data;
    data = NULL; /* Initialize data */
    data = freopen("BadSource_freopen.txt","w+",stdin);
    /* POTENTIAL FLAW: Close the file in the source */
    fclose(data);
    /* POTENTIAL FLAW: Close the file in the sink (it may have been closed in the Source) */
    fclose(data);
}

int main(int argc, char * argv[])
{
    CWE675_Duplicate_Operations_on_Resource__freopen_01_bad();
    return 0;
}

