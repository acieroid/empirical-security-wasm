// Run with:
// python run.py default glibc O2 bad pointer-not-at-start.c
// Results:
//   - WASM return code: 0
//   - Native return code: -6
#include <stdio.h>

#define BAD_SOURCE_FIXED_STRING "Fixed String" /* MAINTENANCE NOTE: This string must contain the SEARCH_CHAR */

#define SEARCH_CHAR 'S'

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_01_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    /* POTENTIAL FLAW: Initialize data to be a fixed string that contains the search character in the sinks */
    strcpy(data, BAD_SOURCE_FIXED_STRING);
    /* FLAW: We are incrementing the pointer in the loop - this will cause us to free the
     * memory block not at the start of the buffer */
    for (; *data != '\0'; data++)
    {
        if (*data == SEARCH_CHAR)
        {
            printf("We have a match!");
            break;
        }
    }
    free(data);
}

int main(int argc, char * argv[])
{
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_01_bad();
    return 0;
}
