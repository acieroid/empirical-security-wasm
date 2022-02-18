// Run with:
// python run.py default glibc O2 bad pointer-subtract.c
// Results:
//   - WASM output: b'19\n'
//   - Native output: b'15\n'
#include "std_testcase.h" // Strangely, replacing this by <stdio.h> changes the WASM output!

#define SOURCE_STRING "abc/opqrstu"

void CWE469_Use_of_Pointer_Subtraction_to_Determine_Size__char_01_bad()
{
    {
        char string1[] = SOURCE_STRING;
        char string2[] = SOURCE_STRING;
        char * slashInString1;
        size_t indexOfSlashInString1;
        slashInString1 = strchr(string1, '/');
        if (slashInString1 == NULL)
        {
            exit(1);
        }
        /* FLAW: subtracting the slash pointer from a completely different string, should be slashInString1 - string1 */
        indexOfSlashInString1 = (size_t)(slashInString1 - string2);
        /* print the index of where the slash was found */
        printUnsignedLine(indexOfSlashInString1);
    }
}

int main(int argc, char * argv[])
{
    CWE469_Use_of_Pointer_Subtraction_to_Determine_Size__char_01_bad();
    return 0;
}
