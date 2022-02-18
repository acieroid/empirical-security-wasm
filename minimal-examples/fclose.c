// Run with:
// python run.py default glibc O2 bad fclose.c
// Results:
//  - WASM return code: 0
//  - Native return code: -11
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

void CWE404_Improper_Resource_Shutdown__open_fclose_01_bad()
{
    int data;
    /* Initialize data */
    data = -1;
    /* POTENTIAL FLAW: Open a file - need to make sure it is closed properly in the sink */
    data = open("BadSource_open.txt", O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
    if (data != -1)
    {
        /* FLAW: Attempt to close the file using fclose() instead of close() */
        fclose((FILE *)data);
    }
}

int main(int argc, char * argv[])
{
    CWE404_Improper_Resource_Shutdown__open_fclose_01_bad();
    return 0;
}
