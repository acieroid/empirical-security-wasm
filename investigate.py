import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
cursor = connection.cursor()

results = cursor.execute('''select path, category, cwe, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit from results where (native_exit != wasm_exit or native_output != wasm_output)''').fetchall();
number_of_programs = cursor.execute('''select count(*) from results''').fetchall()[0][0]
number_of_programs_compiled = cursor.execute('''select count(*) from results where failed = 0''').fetchall()[0][0]
number_of_programs_in_dataset = cursor.execute('''select count(*) from results where failed = 0 and nondeterministic = 0''').fetchall()[0][0]
number_of_differences = cursor.execute('''select count(*) from results where (native_exit != wasm_exit or native_output != wasm_output)''').fetchall()[0][0]

def empty():
    return {
        'programs': set(),
        'categories': set(),
        'CWEs': set(),
    }
root_causes = {
    # libc
    'wasm-file': empty(), # wasm/musl does not have the same behaviour with files
    'wchar': empty(), # wchars have different behaviours in musl (wasm)
    'free': empty(), # double free crashes in native, not in wasm; similarly for other "wrong" usages of free (free not at the start of a buffer for example)
    'puts_return_value': empty(), # fputs does not return the same value in native and in wasm/musl

    'strtol': empty(), # different strtol return value
    'printf-missing-arg': empty(), # printf has different behaviour in musl/glibc

    # security
    'stack-smashing': empty(), # stack smashing is detected in native
    'bounds': empty(), # writing out of bounds in wasm does not result in a crash, but sometimes does in native

    # platform
    'sizeof': empty(), # sizeof(void *) = 8 in native, 4 in wasm
    'number-semantics': empty(), # semantics of numbers sometimes differ
    'zero-initialized': empty(), # wasm memory is 0-initialized, native could not be, resulting in different output
    'environment': empty(), # the environment is empty in wasm, not in native
    'memory-layout': empty(), # dependence on memory layout such as sizes etc.

    'unknown-different-output': empty(),
    'only-wasm-crash': empty(),
    'only-native-crash': empty(),

    'undefined-behaviour': empty() # Different interpretation of undefined behaviour in C and in wasm
}
def mark(root_cause, path, category, cwe):
    root_causes[root_cause]['programs'].add(path)
    root_causes[root_cause]['categories'].add(category)
    root_causes[root_cause]['CWEs'].add(cwe)

results = sorted(results, key=lambda x: x[0])
ignored = 0
nondet = 0
nondiff = 0
different_error_code = 0
for (path, category, cwe, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit) in results:
    if 'CWE400_Resource_Exhaustion' in path or 'CWE511_Logic_Time' in path:
        ignored += 1
        continue # speed difference / timeout 
#    if 'C/testcases/CWE674_Uncontrolled_Recursion/CWE674_Uncontrolled_Recursion__infinite_recursive_call_01.c' in path:
#        ignored += 1
#        continue # speed difference / timeout
#    if 'C/testcases/CWE122_Heap_Based_Buffer_Overflow/s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand' in path:
#        nondiff += 1 
#        continue
    if 'CWE190_Integer_Overflow' and '_rand_' in path:
        nondiff += 1 # Call to rand was not replaced, after replacing it becomes stable and shows no diff
        continue
    if 'C/testcases/CWE122_Heap_Based_Buffer_Overflow/s06/CWE122_Heap_Based_Buffer_Overflow__CWE135_12' in path:
        nondet += 1
        continue
    if '_strtol_' in path:
        mark('strtol', path, category, cwe)
        continue
    if 'C/testcases/CWE789_Uncontrolled_Mem_Alloc/s01/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets' in path:
        mark('sizeof', path, category, cwe)
        continue
    if 'C/testcases/CWE121_Stack_Based_Buffer_Overflow/' in path:
        # All these cases are due to the stack smashing, although they exhibit different behaviour (non termination in wasm, crash in native, different output, ...)
        mark('stack-smashing', path, category, cwe)
        continue
    if 'C/testcases/CWE134_Uncontrolled_Format_String/s02/CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_44.c' in path:
        mark('printf-missing-arg', path, category, cwe)
        continue
    if 'C/testcases/CWE685_Function_Call_With_Incorrect_Number_of_Arguments/' in path:
        mark('printf-missing-arg', path, category, cwe)
        continue
    if 'C/testcases/CWE475_Undefined_Behavior_for_Input_to_API/' in path:
        mark('undefined-behaviour', path, category, cwe)
        continue
    if native_exit != wasm_exit:
        if wasm_exit == 0:
            # Only native crashed
            if 'stack smashing' in native_error.decode('utf-8'):
                mark('stack-smashing', path, category, cwe)
                continue
            if 'CWE124_Buffer_Underwrite' in path:
                mark('bounds', path, category, cwe)
                continue
            if 'C/testcases/CWE127_Buffer_Underread/s02/CWE127_Buffer_Underread__CWE839_rand' in path:
                mark('bounds', path, category, cwe)
                continue
            if 'C/testcases/CWE404_Improper_Resource_Shutdown/CWE404_Improper_Resource_Shutdown__open_fclose' in path:
                mark('wasm-file', path, category, cwe)
                continue
            if 'double free' in native_error.decode('utf-8'):
                mark('free', path, category, cwe)
                continue
            if 'CWE761_Free_Pointer_Not_at_Start_of_Buffer' in path:
                mark('free', path, category, cwe)
                continue
            if 'CWE590_Free_Memory_Not_on_Heap' in path:
                mark('free', path, category, cwe)
                continue
            if 'CWE476_NULL_Pointer_Dereference' in path:
                mark('zero-initialized', path, category, cwe)
                continue
            if 'CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument' in path:
                # printf("%s", some-int) touches unititialized memory in wasm, but crashes in native
                mark('zero-initialized', path, category, cwe)
                continue
            if 'CWE685_Function_Call_With_Incorrect_Number_of_Arguments' in path:
                # printf is called with a missing argument, it outputs garbage in native code, but prints (null) with wasm
                mark('printf-missing-arg', path, category, cwe)
                continue
            if 'C/testcases/CWE134_Uncontrolled_Format_String/s02/CWE134_Uncontrolled_Format_String__char_environment_vfprintf_44' in path:
                mark('printf-missing-arg', path, category, cwe)
                continue
            if 'C/testcases/CWE134_Uncontrolled_Format_String/s02/CWE134_Uncontrolled_Format_String__char_environment_vprintf_44.c' in path:
                mark('printf-missing-arg', path, category, cwe)
                continue
            if 'C/testcases/CWE758_Undefined_Behavior/' in path:
                mark('zero-initialized', path, category, cwe)
                continue
            print('ONLY NATIVE: %s' % path)
            mark('only-native-crash', path, category, cwe)
            continue
        elif native_exit == 0:
            if 'CWE390_Error_Without_Action__fopen' in path:
                mark('wasm-file', path, category, cwe)
                continue
            if 'CWE675_Duplicate_Operations_on_Resource' in path:
                # fclosing a file twice succeeds in native, but crashes in wasm
                mark('wasm-file', path, category, cwe)
                continue
            if 'CWE690_NULL_Deref_From_Return' in path:
                # fclosing a file that failed to open crashes in wasm
                mark('wasm-file', path, category, cwe)
                continue
            # Only wasm crashed
            print('ONLY WASM: %s' % path)
            mark('only-wasm-crash', path, category, cwe)
            continue
        else:
            # Both crashed but with different codes, that's ok
            different_error_code += 1
            continue
    elif native_output != wasm_output:
        if 'wchar' in path:
            mark('wchar', path, category, cwe)
            continue
        if 'CWE134_Uncontrolled_Format_String' in path:
            mark('printf-missing-arg', path, category, cwe)
            continue
        if 'CWE188_Reliance_on_Data_Memory_Layout' in path:
            mark('memory-layout', path, category, cwe)
            continue
        if 'C/testcases/CWE122_Heap_Based_Buffer_Overflow/s11/CWE122_Heap_Based_Buffer_Overflow__sizeof_struct' in path:
            mark('sizeof', path, category, cwe)
            continue
        if 'C/testcases/CWE122_Heap_Based_Buffer_Overflow/s06/CWE122_Heap_Based_Buffer_Overflow__CWE135' in path:
            mark('wchar', path, category, cwe)
            continue
        if 'C/testcases/CWE127_Buffer_Underread/s01/CWE127_Buffer_Underread__CWE839_fscanf' in path:
            mark('zero-initialized', path, category, cwe)
            continue
        if 'C/testcases/CWE127_Buffer_Underread/s02/CWE127_Buffer_Underread__CWE839_negative' in path:
            mark('zero-initialized', path, category, cwe)
            continue
        if 'C/testcases/CWE127_Buffer_Underread/s02/CWE127_Buffer_Underread__malloc_char' in path:
            mark('zero-initialized', path, category, cwe)
            continue
        if 'CWE253_Incorrect_Check_of_Function_Return_Value' in path:
            mark('puts_return_value', path, category, cwe)
            continue
        if 'CWE457_Use_of_Uninitialized_Variable' in path:
            mark('zero-initialized', path, category, cwe)
            continue
        if 'CWE526_Info_Exposure_Environment_Variables' in path:
            # environment variables are exposed in native, but they are not available in wasm by default
            mark('environment', path, category, cwe)
            continue
        if 'CWE665_Improper_Initialization' in path:
            # strcat(data, x) will append x to data, and data is zero-initialized in wasm, but may not be in native, hence resulting in a different string being printed
            mark('zero-initialized', path, category, cwe)
            continue
        if 'CWE758_Undefined_Behavior' in path:
            # strings that are zero-initialized are the empty string and result in different output than uninitialized native strings
            mark('zero-initialized', path, category, cwe)
            continue
        if 'CWE196_Unsigned_to_Signed_Conversion_Error' in path:
            # different number semantics results in different number after conversion
            mark('number-semantics', path, category, cwe)

        mark('unknown-different-output', path, category, cwe)
        print('OUTPUT: %s' % path)
        #print('Native output: %s' % native_output.decode('utf-8'))
        #print('Wasm output: %s' % wasm_output.decode('utf-8'))
print(root_causes)

print('Programs ignored: %d' % ignored)
print('Programs manually marked as nondeterministic: %d' % nondet)
print('Programs marked as not different even though they were detected as so: %d' % nondiff) # Due to manual investigation
print('Programs that crash with different error code: %d' % different_error_code)
print('JulietNumberOfPrograms: %d' % number_of_programs)
print('CompilablePrograms: %d' % number_of_programs_compiled)
print('DatasetPrograms: %d' % (number_of_programs_in_dataset - ignored - nondet))
kind = 'CWEs'
print('NumberOfDifferences: %d' % (number_of_differences - different_error_code))
libcdiffs = len(root_causes['wasm-file'][kind]) + len(root_causes['wchar'][kind]) + len(root_causes['free'][kind]) + len(root_causes['puts_return_value'][kind]) + len(root_causes['printf-missing-arg'][kind])
print('DifferencesLibc: %d' % libcdiffs)
securitydiffs = len(root_causes['stack-smashing'][kind]) + len(root_causes['bounds'][kind])
print('DifferencesSecurity: %d' % securitydiffs)
environmentdiffs = len(root_causes['sizeof'][kind]) + len(root_causes['number-semantics'][kind]) + len(root_causes['zero-initialized'][kind]) + len(root_causes['environment'][kind]) + len(root_causes['memory-layout'][kind])
print('DifferencesEnvironment: %d' % environmentdiffs)

print('DifferencesWchar: %d' % len(root_causes['wchar'][kind]))
print('DifferencesMalloc: %d' % len(root_causes['free'][kind]))
print('DifferencesPuts: %d' % len(root_causes['puts_return_value'][kind]))
print('DifferencesPrintf: %d' % len(root_causes['printf-missing-arg'][kind]))
print('DifferencesStackSmashing: %d' % len(root_causes['stack-smashing'][kind]))
print('DifferencesBounds: %d' % len(root_causes['bounds'][kind]))
print('DifferencesUninitialized: %d' % len(root_causes['zero-initialized'][kind]))
print('DifferencesSizeof: %d' % len(root_causes['sizeof'][kind]))
print('DifferencesNumberSemantics: %d' % len(root_causes['strtol'][kind]))
print('DifferencesOSEnv: %d' % len(root_causes['environment'][kind]))
print('DifferencesMemoryLayout: %d' % len(root_causes['memory-layout'][kind]))

compilation_time_wasm, compilation_time_native, execution_time_wasm, execution_time_native = cursor.execute('''select sum(wasm_compile), sum(native_compile), sum(wasm_run), sum(native_run) from timing''').fetchall()[0]
print('Compilation time (wasm): %d minutes' % (compilation_time_wasm / 1000 / 60))
print('Compilation time (native): %d minutes' % (compilation_time_native / 1000 / 60))
print('Execution time (wasm): %d minutes' % (execution_time_wasm / 1000 / 60))
print('Execution time (native): %d minutes' % (execution_time_native / 1000 / 60))

print('Programs with different behaviour for unknown reasons: %d' % len(root_causes['unknown-different-output'][kind]))
