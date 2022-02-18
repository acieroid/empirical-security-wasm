#!/usr/bin/python3
import sqlite3
import sys
import os.path
import subprocess
import time

NRUNS = 2
TIMEOUT = 100 # Timeout in seconds
OUT = 'out'
SYSROOT = '/opt/wasi-sdk/wasi-sysroot'
OPTIMIZATIONS = '-O2'
TESTCASESUPPORTDIR = 'C/testcasesupport'
INCLUDE = '-I%s' % TESTCASESUPPORTDIR
INPUT = b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
# default
SECURITYFLAGS = []
SECURITYFLAGSWASM = []
NATIVE_COMPILER = 'clang'
GOODBAD_FLAG = '-DOMITGOOD'

config_secflags = sys.argv[1]
config_libc = sys.argv[2]
config_opt = sys.argv[3]
config_goodbad = sys.argv[4]
if config_secflags == 'default':
    SECURITYFLAGS = []
    SECURITYFLAGSWASM = []
elif config_secflags == 'secure':
    SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fsanitize=cfi', '-flto', '-Wl,-z,relro', '-Wl,-z-now', '-fvisibility=hidden'] # less arguments because these are not supported by the wasm backend
    if config_libc == 'musl':
        SECURITYFLAGS = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fstack-protector', '-fsanitize=cfi', '-flto', '-fuse-ld=gold', '-Wl,-z,relro', '-fvisibility=hidden']
    elif config_libc == 'glibc':
        SECURITYFLAGS = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fstack-protector', '-fsanitize=safe-stack,cfi', '-flto', '-fuse-ld=gold', '-Wl,-z,relro', '-fvisibility=hidden']
    else:
        print('Unknown libc: ' + config_libc)
        quit()
elif config_secflags == 'nonsecure':
    SECURITYFLAGS = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
    SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
else:
    print('Unknown security flag: ' + config_secflags)
    quit()
if config_libc == 'musl':
    NATIVE_COMPILER = 'musl-clang'
elif config_libc == 'glibc':
    NATIVE_COMPILER = 'clang'
else:
    print('Unknown libc: ' + config_libc)
    quit()

if not config_opt in ['O0', 'O1', 'O2', 'O3', 'Os']:
    print('Unknown optimization level: ' + config_opt)
    quit()
OPTIMIZATIONS = '-' + config_opt

if config_goodbad == 'good':
    GOODBAD_FLAG = '-DOMITBAD'
elif config_goodbad == 'bad':
    GOODBAD_FLAG = '-DOMITGOOD'
else:
    print('Unknown goodbad config: ' + config_goodbad)
    quit()

full_path = sys.argv[5]

connection = None

success = False

def compute_category(full_path):
    return '_'.join(full_path.split('.')[0].split('_')[0:-1])
def compute_cwe(full_path):
    return full_path.split('/')[2]

def current_time():
    return round(time.time() * 1000)

def dump_time(wasm_compile, native_compile, wasm_run, native_run):
    pass

def mark_compilation_failed(full_path):
    print('Compilation failed')

def mark_nondeterministic(full_path):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)

def mark_divergent(full_path, native_output, native_error, native_exit, wasm_output, wasm_error, wasm_exit):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)

def mark_success(full_path):
    category = compute_category(full_path)
    cwe = compute_cwe(full_path)

def compile_wasm(full_path):
    basename = os.path.basename(full_path)
    cmd = ['clang', GOODBAD_FLAG, '-DINCLUDEMAIN', '--target=wasm32-unknown-wasi', '--sysroot', SYSROOT, '-Wl,--demangle', '-Wl,--export-all', OPTIMIZATIONS, INCLUDE, '%s/io.c' % TESTCASESUPPORTDIR, 
           full_path, '-o', '%s/%s.wasm' % (OUT, basename)]
    cmd.extend(SECURITYFLAGSWASM)
    print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = process.communicate()
    print(stderr)
    return process.returncode

def run_wasm(full_path):
    basename = os.path.basename(full_path)
    cmd = ['wasmer', '--disable-cache', '%s/%s.wasm' % (OUT, basename), '--dir', './']
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(input=INPUT, timeout=TIMEOUT)
    return output, error, process.returncode

def compile_native(full_path):
    basename = os.path.basename(full_path)
    cmd = [NATIVE_COMPILER, GOODBAD_FLAG, '-DINCLUDEMAIN', OPTIMIZATIONS, INCLUDE, '%s/io.c' % TESTCASESUPPORTDIR, '-m32',
            full_path, '-o', '%s/%s.native' % (OUT, basename)]
    cmd.extend(SECURITYFLAGS)
    print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, _ = process.communicate()
    return process.returncode

def run_native(full_path):
    basename = os.path.basename(full_path)
    process = subprocess.Popen(['%s/%s.native' % (OUT, basename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(input=INPUT, timeout=TIMEOUT)
    return output, error, process.returncode

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
    print('run %d' % i)
    t0 = current_time()
    try:
        output, error, return_code = run_wasm(full_path)
    except subprocess.TimeoutExpired:
        break
    t1 = current_time()
    wasm_time += t1 - t0

    if i == 0:
        wasm_output = output
        wasm_error = error
        wasm_return_code = return_code
        print('WASM output: %s' % wasm_output)
        print('WASM return code: %d' % wasm_return_code)
    elif wasm_output != output or wasm_error != error or wasm_return_code != return_code:
        mark_nondeterministic(full_path)
        quit()
        print('Wasm program is non-deterministic')

    t0 = current_time()
    try:
        output, error, return_code = run_native(full_path)
    except subprocess.TimeoutExpired:
        break
    t1 = current_time()
    native_time += t1 - t0
    if i == 0:
        native_output = output
        native_error = error
        native_return_code = return_code
        print('Native output: %s' % native_output)
        print('Native return code: %d' % native_return_code)
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
