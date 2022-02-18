// Run with:
// python run.py default glibc O2 bad fopen.c
// Results:
//   - WASM return code: 1
//   - Native return code: 0
#include <stdio.h>

void CWE390_Error_Without_Action__fopen_01_bad()
{
  FILE * fileDesc = NULL;
  fileDesc = fopen("file.txt", "w+");
  /* FLAW: Check to see if fopen failed, but do nothing about it */
  if (fileDesc == NULL)
  {
    /* do nothing */
  }
  fclose(fileDesc);
}


int main(int argc, char * argv[])
{
    CWE390_Error_Without_Action__fopen_01_bad();
    return 0;
}

