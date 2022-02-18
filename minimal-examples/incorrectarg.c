// Run with:
// python run.py default glibc O2 bad incorrectarg.c
// Results:
//   - WASM return code: 0
//   - Native return code: -11
#include <stdio.h>

#define DEST_SIZE 100

void CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument__basic_01_bad()
{
  char dest[DEST_SIZE];
  int intFive = 5;
  /* FLAW: int argument passed, expecting string argument */
  sprintf(dest, "%s", intFive);
  printf("%s\n", dest);
}

int main(int argc, char * argv[])
{
    CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument__basic_01_bad();
    return 0;
}
