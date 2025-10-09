import os
import lit.formats
import subprocess
from pathlib import Path

config.name = 'AutoJIT'
config.test_format = lit.formats.ShTest(True)

config.suffixes = ['.cpp', '.c', '.ll']
config.excludes = ["Inputs"]
config.test_source_root = os.path.dirname(__file__)

config.substitutions.append(('%autojit_plugin', config.autojit_plugin))
config.substitutions.append(('%autojit_runtime_dir', config.autojit_runtime_dir))

bin = Path(config.llvm_tools_dir)
config.substitutions.append(('%clang', str(bin / 'clang++')))
config.substitutions.append(('%ar', str(bin / 'llvm-ar')))
config.substitutions.append(('opt', str(bin / 'opt')))
config.substitutions.append(('FileCheck', str(bin / 'FileCheck')))

config.environment['PATH'] = config.llvm_tools_dir + ":/usr/bin"

if 'AUTOJIT_USE_TPDE' in os.environ:
    use_tpde = os.environ.get('AUTOJIT_USE_TPDE')
else:
    use_tpde = config.enable_tpde

config.environment['AUTOJIT_USE_TPDE'] = use_tpde
print("Running regression tests with TPDE:", use_tpde)

config.available_features.add('shell')
if hasattr(config, 'enable_plugins') and config.enable_plugins:
    config.available_features.add('plugins')

if config.build_type == "Debug":
    config.available_features.add('llvm-debug')

if config.enable_orc_rt == "On":
    config.available_features.add('orc-rt')

def check_output(cmd, libname: str) -> bool:
    o = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    for l in o.splitlines():
        if libname in l:
            return True
    return False

try:
    runtime = Path(config.autojit_runtime_dir) / "libautojit-runtime.so"
    if check_output(["ldd", str(runtime)], "libc++.so"):
        config.available_features.add('libcxx')
    else:
        config.available_features.add('libstdcxx')
except subprocess.CalledProcessError as ex:
    print(f"Failed to run ldd on {str(runtime)}: {ex}")
