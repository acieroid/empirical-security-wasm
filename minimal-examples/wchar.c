// Run with:
// python run.py default glibc O2 bad wchar.c
// Result:
//   - WebAssembly: prints nothing
//   - Native: prints AAAAAAAAAA
#define SRC_STRING L"AAAAAAAAAA"

int main(int argc, char * argv[])
{
  wprintf(L"%ls\n", SRC_STRING);
}
