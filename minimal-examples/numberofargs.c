// Run with:
// python run.py default glibc O2 bad numberofargs.c
// Results:
//   - WASM return code: 0
//   - Native return code: -11
#include <stdio.h>

#define DEST_SIZE 100 /* maintenance note: ensure this is > 2*SOURCE_STRING to avoid buffer overflow issues */
#define SOURCE_STRING "AAA"

void CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_01_bad()
{
    char dest[DEST_SIZE];
    /* FLAW: Incorrect number of arguments */
    sprintf(dest, "%s %s", SOURCE_STRING);
    printf("%s\n", dest);
}


int main(int argc, char * argv[])
{
    CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_01_bad();
    printf("Finished bad()");
    return 0;
}
