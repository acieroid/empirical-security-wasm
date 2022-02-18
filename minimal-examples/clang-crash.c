// Compile with:
// clang --target=wasm32-unknown-wasi --sysroot /opt/wasi-sdk/wasi-sysroot clang-crash.c -fsanitize=cfi -flto -fvisibility=hidden
// It will result in a compiler crash
void custom_function() { }

int main()
{
    void (*funcPtr) () = custom_function;
    funcPtr();
    return 0;
}
