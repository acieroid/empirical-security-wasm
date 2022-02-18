#!/usr/bin/python3
import sqlite3
import sys
import os.path
import subprocess
import time

OUT = 'out'
SYSROOT = '/opt/wasi-sdk/wasi-sysroot'
OPTIMIZATIONS = '-O2'
ARCHITECTURE = '-m32'
TESTCASESUPPORTDIR = 'C/testcasesupport'
INCLUDE = '-I%s' % TESTCASESUPPORTDIR
INPUT = b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
# default
SECURITYFLAGS = []
SECURITYFLAGSWASM = []
NATIVE_COMPILER = 'clang'
GOODBAD_FLAG = '-DOMITGOOD'

def apply_config(config):
    """Apply a compiler configuration"""
    global SECURITYFLAGS
    global SECURITYFLAGSWASM
    global NATIVE_COMPILER
    global OPTIMIZATIONS
    global GOODBAD_FLAG
    if config['sec'] == 'default':
        SECURITYFLAGS = []
        SECURITYFLAGSWASM = []
    elif config['sec'] == 'secure':
        SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fsanitize=cfi', '-flto', '-Wl,-z,relro', '-Wl,-z-now', '-fvisibility=hidden'] # less arguments because these are not supported by the wasm backend
        if config['libc'] == 'musl':
            SECURITYFLAGS = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fstack-protector', '-fsanitize=cfi', '-flto', '-fuse-ld=gold', '-Wl,-z,relro', '-fvisibility=hidden']
        elif config['libc'] == 'glibc':
            SECURITYFLAGS = ['-D_FORTIFY_SOURCE=2', '-fpie', '-pie', '-fstack-protector', '-fsanitize=safe-stack,cfi', '-flto', '-fuse-ld=gold', '-Wl,-z,relro', '-fvisibility=hidden']
        else:
            print('Unknown libc: ' + config['libc'])
            sys.exit()
    elif config['sec'] == 'nonsecure':
        SECURITYFLAGS = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
        SECURITYFLAGSWASM = ['-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie', '-fno-stack-protector', '-fno-sanitize=safe-stack,address,undefined,cfi', '-fno-lto']
    else:
        print('Unknown security flag: ' + config['sec'])
        sys.exit()
    if config['libc'] == 'musl':
        NATIVE_COMPILER = 'musl-clang'
    elif config['libc'] == 'glibc':
        NATIVE_COMPILER = 'clang'
    else:
        print('Unknown libc: ' + config['libc'])
        sys.exit()

    if not config['opt'] in ['O0', 'O1', 'O2', 'O3', 'Os']:
        print('Unknown optimization level: ' + config['opt'])
        sys.exit()
    OPTIMIZATIONS = '-' + config['opt']

    if config['goodbad'] == 'good':
        GOODBAD_FLAG = '-DOMITBAD'
    elif config['goodbad'] == 'bad':
        GOODBAD_FLAG = '-DOMITGOOD'
    else:
        print('Unknown goodbad config: ' + config['goodbad'])
        sys.exit()

full_path = sys.argv[1]
verbose = len(sys.argv) > 2 and sys.argv[2] == '-v'

def compile_wasm(path):
    """Compile a program with WebAssembly"""
    basename = os.path.basename(path)
    cmd = ['clang', GOODBAD_FLAG, '-DINCLUDEMAIN', '--target=wasm32-unknown-wasi', '--sysroot', SYSROOT, '-Wl,--demangle', '-Wl,--export-all', OPTIMIZATIONS, INCLUDE, f'%s/io.c' % TESTCASESUPPORTDIR, full_path, '-o', '%s/%s.wasm' % (OUT, basename)]
    cmd.extend(SECURITYFLAGSWASM)
    if verbose:
        print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = process.communicate()
    if verbose:
        print(stderr)
    return process.returncode

def compile_native(full_path):
    """Compile a program in native"""
    basename = os.path.basename(full_path)
    cmd = [NATIVE_COMPILER, GOODBAD_FLAG, '-DINCLUDEMAIN', OPTIMIZATIONS, INCLUDE, '%s/io.c' % TESTCASESUPPORTDIR, '-m32',
            full_path, '-o', '%s/%s.native' % (OUT, basename)]
    cmd.extend(SECURITYFLAGS)
    if verbose:
        print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = process.communicate()
    if verbose:
        print(stderr)
    return process.returncode

configurations = [
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O0', 'goodbad': 'good' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O1', 'goodbad': 'good' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O2', 'goodbad': 'good' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'Os', 'goodbad': 'good' },
    { 'sec': 'secure',    'libc': 'glibc', 'opt': 'O2', 'goodbad': 'good' },
    { 'sec': 'nonsecure', 'libc': 'glibc', 'opt': 'O2', 'goodbad': 'good' },
    { 'sec': 'default',   'libc': 'musl',  'opt': 'O2', 'goodbad': 'good' },
    { 'sec': 'secure',    'libc': 'musl',  'opt': 'O2', 'goodbad': 'good' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O0', 'goodbad': 'bad' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O1', 'goodbad': 'bad' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'O2', 'goodbad': 'bad' },
    { 'sec': 'default',   'libc': 'glibc', 'opt': 'Os', 'goodbad': 'bad' },
    { 'sec': 'secure',    'libc': 'glibc', 'opt': 'O2', 'goodbad': 'bad' },
    { 'sec': 'nonsecure', 'libc': 'glibc', 'opt': 'O2', 'goodbad': 'bad' },
    { 'sec': 'default',   'libc': 'musl',  'opt': 'O2', 'goodbad': 'bad' },
    { 'sec': 'secure',    'libc': 'musl',  'opt': 'O2', 'goodbad': 'bad' },
]

successes = 0
failures = 0
for configuration in configurations:
    apply_config(configuration)
    result = compile_wasm(full_path)
    if result == 0:
        if verbose:
            print('Success')
        successes += 1
    else:
        if verbose:
            print('Failure')
        failures += 1
    result = compile_native(full_path)
    if result == 0:
        if verbose:
            print('Native success')
        successes += 1
    else:
        if verbose:
            print('Native failure')
        failures += 1

if failures == 0:
    sys.exit(0) # All compilations succeed
elif successes == 0:
    sys.exit(1) # All compilations failed
else:
    sys.exit(2) # There is a mismatch in the compilation results
