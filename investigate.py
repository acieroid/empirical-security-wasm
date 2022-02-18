import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
cursor = connection.cursor()

results = cursor.execute('''select path, category, cwe, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit from results where (native_exit != wasm_exit or native_output != wasm_output)''').fetchall();
number_of_programs = cursor.execute('''select count(*) from results''').fetchall()[0][0]
number_of_programs_compiled = cursor.execute('''select count(*) from results where failed = 0''').fetchall()[0][0]
number_of_programs_in_dataset = cursor.execute('''select count(*) from results where failed = 0 and nondeterministic = 0''').fetchall()[0][0]
number_of_differences = cursor.execute('''select count(*) from results where (native_exit != wasm_exit or native_output != wasm_output)''').fetchall()[0][0]

results = sorted(results, key=lambda x: x[0])
differences = {}
total_differences = 0
for (path, category, cwe, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit) in results:
    if wasm_exit != 0 and native_exit != 0:
        # Both crashed, but with different error codes. That is definitely ok and so not counted as a difference
        continue
    if not (cwe in differences):
        differences[cwe] = []
    differences[cwe].append(path)
    total_differences += 1

print('There are {} differences in total, across {} CWEs'.format(total_differences, len(differences)))
for cwe in differences:
    print('CWE {} has {} differences. One example is {}'.format(cwe, len(differences[cwe]), differences[cwe][0]))

compilation_time_wasm, compilation_time_native, execution_time_wasm, execution_time_native = cursor.execute('''select sum(wasm_compile), sum(native_compile), sum(wasm_run), sum(native_run) from timing''').fetchall()[0]
print('Compilation time (wasm): %d minutes' % (compilation_time_wasm / 1000 / 60))
print('Compilation time (native): %d minutes' % (compilation_time_native / 1000 / 60))
print('Execution time (wasm): %d minutes' % (execution_time_wasm / 1000 / 60))
print('Execution time (native): %d minutes' % (execution_time_native / 1000 / 60))
