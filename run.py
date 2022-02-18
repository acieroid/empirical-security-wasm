#!/usr/bin/python3
import sqlite3
import sys
import os.path
import subprocess
import time

NRUNS = 10
TIMEOUT = '100s'
OUT = 'out'
SYSROOT = '/opt/wasi-sdk/wasi-sysroot'
OPTIMIZATIONS = '-O1'
TESTCASESUPPORTDIR = 'C/testcasesupport'
INCLUDE = '-I%s' % TESTCASESUPPORTDIR
INPUT = b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
# default
SECURITYFLAGS = []
SECURITYFLAGSWASM = []
# nonsecure
#SECURITYFLAGS = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
#SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
# secure
#SECURITYFLAGS = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fstack-protector', '-fsanitize=safe-stack,cfi', '-flto', '-fuse-ld=gold', '-Wl,-z,relro', '-fvisibility=hidden']
#SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fsanitize=cfi', '-flto', '-Wl,-z,relro', '-Wl,-z-now', '-fvisibility=hidden'] # less arguments because these are not supported by the wasm backend

full_path = sys.argv[1]

connection = None

success = False
while success == False:
    try:
        connection = sqlite3.connect('results.db')
        success = True
    except sqlite3.Error as error:
        print('Failed with exception: %s, will try again until it succeeds' % error)

cursor = connection.cursor()

def execute(query, args = None):
    while True:
        try:
            result = None
            if args:
                result = cursor.execute(query, args)
            else:
                result = cursor.execute(query)
            return result
        except sqlite3.Error as error:
            print('Failed with exception: %s, will try again until it succeeds' % error)

execute('''create table if not exists results(
path text, /* the full path to the file */
category text, /* the category this file belongs to */
cwe number, /* the CWE this file belongs to */
failed boolean, /* whether any compile step failed */
nondeterministic boolean, /* whether the program exhibits nondeterministic behaviour */
native_output string, /* the native output */
native_error string, /* the native crash reason (if any) */
native_exit integer, /* the native return code */
wasm_output string, /* the wasm outupt */
wasm_error string, /* the wasm crash reason (if any) */
wasm_exit integer /* the wasm return code */
)''')
# Timing table (times in ms)
execute('''create table if not exists timing(
        wasm_compile integer,
        native_compile integer,
        wasm_run integer,
        native_run integer)''')

def compute_category(full_path):
    return '_'.join(full_path.split('.')[0].split('_')[0:-1])
def compute_cwe(full_path):
    return full_path.split('/')[2]

def current_time():
    return round(time.time() * 1000)

def dump_time(wasm_compile, native_compile, wasm_run, native_run):
    execute('''insert into timing values (?, ?, ?, ?)''', (wasm_compile, native_compile, wasm_run, native_run))
    connection.commit()

def mark_compilation_failed(full_path):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)
    execute('''insert into results values (?, ?, ?, 1, 0, '', '', 0, '', '', 0)''', (full_path, category, cwe))
    connection.commit()

def mark_nondeterministic(full_path):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)
    execute('''insert into results values (?, ?, ?, 0, 1, '', '', 0, '', '', 0)''', (full_path, category, cwe))
    connection.commit()

def mark_divergent(full_path, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)
    execute('''insert into results values (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)''',
                   (full_path, category, cwe, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit))
    connection.commit()

def mark_success(full_path):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)
    execute('''insert into results values (?, ?, ?, 0, 0, '', '', 0, '', '', 0)''', (full_path, category, cwe))
    connection.commit()

def compile_wasm(full_path):
    basename = os.path.basename(full_path)
    cmd = ['clang', '-DOMITGOOD', '-DINCLUDEMAIN', '--target=wasm32-unknown-wasi', '--sysroot', SYSROOT, '-Wl,--demangle', '-Wl,--export-all', OPTIMIZATIONS, INCLUDE, '%s/io.c' % TESTCASESUPPORTDIR, full_path, '-o', '%s/%s.wasm' % (OUT, basename)]
    cmd.extend(SECURITYFLAGSWASM)
    print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = process.communicate()
    print(stderr)
    return process.returncode

def run_wasm(full_path):
    basename = os.path.basename(full_path)
    cmd = ['timeout', TIMEOUT, 'wasmer', '--disable-cache', '%s/%s.wasm' % (OUT, basename), '--dir', './']
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(input=INPUT)
    return output, error, process.returncode

def compile_native(full_path):
    basename = os.path.basename(full_path)
    cmd = ['musl-clang', '-DOMITGOOD', '-DINCLUDEMAIN', OPTIMIZATIONS, INCLUDE, '%s/io.c' % TESTCASESUPPORTDIR, full_path, '-o', '%s/%s.native' % (OUT, basename)]
    cmd.extend(SECURITYFLAGS)
    print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, _ = process.communicate()
    return process.returncode

def run_native(full_path):
    basename = os.path.basename(full_path)
    process = subprocess.Popen(['timeout', TIMEOUT, '%s/%s.native' % (OUT, basename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(input=INPUT)
    return output, error, process.returncode

current_status = execute('''select failed from results where path = '%s' ''' % full_path).fetchall()
# No need to run if we already ran it before and stored results
if current_status != []:
    print('Not running again because we already did it')
    quit()

t0 = current_time()
return_code = compile_wasm(full_path)
t1 = current_time()
wasm_compile_time = t1 - t0
if return_code != 0:
    # Compilation failed
    mark_compilation_failed(full_path)
    print('Wasm compilation failed with error code: %d' % return_code)
    quit()


t0 = current_time()
return_code = compile_native(full_path)
t1 = current_time()
native_compile_time = t1 - t0
if return_code != 0:
    # Native compilation failed
    mark_compilation_failed(full_path)
    print('Native compilation failed with error code: %d' % return_code)
    quit()

wasm_return_code = -1
wasm_output = None
wasm_error = None
wasm_time = 0
native_return_code = -1
native_output = None
native_error = None
native_time = 0
for i in range(NRUNS):
    t0 = current_time()
    output, error, return_code = run_wasm(full_path)
    t1 = current_time()
    wasm_time += t1 - t0

    if i == 0:
        wasm_output = output
        wasm_error = error
        wasm_return_code = return_code
    elif wasm_output != output or wasm_error != error or wasm_return_code != return_code:
        mark_nondeterministic(full_path)
        quit()
        print('Wasm program is non-deterministic')

    t0 = current_time()
    output, error, return_code = run_native(full_path)
    t1 = current_time()
    native_time += t1 - t0
    if i == 0:
        native_output = output
        native_error = error
        native_return_code = return_code
    elif native_output != output or native_error != error or native_return_code != return_code:
        mark_nondeterministic(full_path)
        print('Native program is non-deterministic')
        print('return code: %d vs. %d' % (native_return_code, return_code))
        quit()

# Check divergence (not for error message because that can differ, but if both adhere with the return code it is fine)
if wasm_return_code != native_return_code or wasm_output != native_output:
    print('Program is divergent')
    print('return codes: wasm is %d, native is %d' % (wasm_return_code, native_return_code))
    #print('output: wasm is %s, native is %s' % (wasm_output, native_output))
    mark_divergent(full_path, native_output, native_error, native_return_code, wasm_output, wasm_error, wasm_return_code)
    quit()

print('Success')
mark_success(full_path)
dump_time(wasm_compile_time, native_compile_time, wasm_time, native_time)
