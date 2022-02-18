// Run with:
// python run.py default glibc O2 bad fputs.c
// Results:
//   - WASM output: b'stringfputs failed!\n'
//   - Native output: b'string'
#include <stdio.h>

void CWE253_Incorrect_Check_of_Function_Return_Value__char_fputs_01_bad()
{
    /* FLAW: fputs() might fail, in which case the return value will be EOF (-1), but
     * we are checking to see if the return value is 0 */
    if (fputs("string", stdout) == 0)
    {
        printf("fputs failed!\n");
    }
}

int main(int argc, char * argv[])
{
    CWE253_Incorrect_Check_of_Function_Return_Value__char_fputs_01_bad();
    return 0;
}
