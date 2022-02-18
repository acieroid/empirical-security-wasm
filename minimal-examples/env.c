// Run with:
// python run.py default glibc O2 bad env.c
// Results:
//   - WASM output: b'\n'
//   - Native output: b'/home/quentin/.opam/4.12.0/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl:/home/quentin/bin:/home/quentin/.cargo/bin:/home/quentin/.npm-global/bin:/home/quentin/.local/bin:/home/quentin/bin:/home/quentin/.cargo/bin:/home/quentin/.npm-global/bin:/home/quentin/.local/bin\n'
#include <stdio.h>
#include <stdlib.h>

void CWE526_Info_Exposure_Environment_Variables__basic_01_bad()
{
    /* FLAW: environment variable exposed */
    printf("%s\n", getenv("PATH"));
}

int main(int argc, char * argv[])
{
    CWE526_Info_Exposure_Environment_Variables__basic_01_bad();
    return 0;
}
