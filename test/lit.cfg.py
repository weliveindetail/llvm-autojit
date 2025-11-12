import os
import lit.formats
import psutil
import subprocess
import textwrap
from pathlib import Path

config.name = 'AutoJIT'
config.test_format = lit.formats.ShTest(True)
config.filecheck_opts = '--dump-input=fail --dump-input-filter=all'

# timeout in seconds
supported, err = lit_config.maxIndividualTestTimeIsSupported
if supported:
    lit_config.maxIndividualTestTime = 60
else:
    lit_config.warning("Per-test timeout not supported: " + err)

config.suffixes = ['.cpp', '.c', '.ll']
config.excludes = ["Inputs"]
config.test_source_root = os.path.dirname(__file__)

config.substitutions.append(('%autojit_plugin', config.autojit_plugin))
config.substitutions.append(('%autojit_runtime_dir', config.autojit_runtime_dir))
config.substitutions.append(('%autojit_tools_dir', config.autojit_tools_dir))
config.substitutions.append(('%arch', config.host_arch))

if config.sanitize:
    config.substitutions.append(('%fsanitize', f"-fsanitize={config.sanitize}" ))
else:
    config.substitutions.append(('%fsanitize', ""))

bin = Path(config.llvm_tools_dir)
config.substitutions.append(('%clang_c', str(bin / 'clang')))
config.substitutions.append(('%clang', str(bin / 'clang++')))
config.substitutions.append(('%ar', str(bin / 'llvm-ar')))
config.substitutions.append(('%opt', str(bin / 'opt')))
config.substitutions.append(('FileCheck', str(bin / 'FileCheck')))

config.environment['PATH'] = config.llvm_tools_dir + ":/usr/bin"

if 'AUTOJIT_USE_TPDE' in os.environ:
    use_tpde = os.environ.get('AUTOJIT_USE_TPDE')
else:
    use_tpde = config.enable_tpde

config.environment['AUTOJIT_USE_TPDE'] = use_tpde
print("Running regression tests with TPDE:", use_tpde)

def is_set(var_name: str) -> bool:
    val = os.getenv(var_name)
    return val is not None and val.strip().lower() in {"1", "on", "yes", "true"}

# Forward for debugging if enabled on host
if is_set('AUTOJIT_DEBUG'):
    config.environment['AUTOJITD_DEBUG'] = 'On'

# Check for existing autojitd daemon process
daemon_running = False
daemon_bin = Path(config.autojit_tools_dir) / 'autojitd'
for proc in psutil.process_iter(['name', 'exe']):
    try:
        if 'autojitd' in proc.info['name'] and not proc.info['exe'] is None:
            daemon_bin = Path(proc.info['exe'])
            daemon_running = True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

# Honor mode as set by user and otherwise choose whether running or not
daemon_mode = None
if is_set('AUTOJITD_FORCE_SPAWN'):
    daemon_mode = False
elif is_set('AUTOJITD_FORCE_DAEMON'):
    if not daemon_running:
        raise RuntimeError("AUTOJITD_FORCE_DAEMON set, but no autojitd process found")
    daemon_mode = True
else:
    daemon_mode = daemon_running

# Force one mode for all tests
if daemon_mode:
    daemon_state_str = "is up and running"
    config.environment['AUTOJITD_FORCE_DAEMON'] = 'On'
    config.environment['XDG_RUNTIME_DIR'] = os.environ['XDG_RUNTIME_DIR']
    lit_config.warning("Running tests against external autojitd breaks test isolation")
else:
    daemon_state_str = "is spawned for each test"
    config.environment['AUTOJITD_FORCE_SPAWN'] = 'On'

config.environment['AUTOJIT_DAEMON_PATH'] = str(daemon_bin)
print(f"Daemon {daemon_state_str}: {str(daemon_bin)}")

config.environment['AUTOJIT_DISABLE_OBJECT_CACHE'] = 'On'

config.available_features.add('shell')
if hasattr(config, 'enable_plugins') and config.enable_plugins:
    config.available_features.add('plugins')

if config.build_type == "Debug":
    config.available_features.add('llvm-debug')

# We could provide a way to load it from disk instead
if config.orc_rt_embedded == "On":
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

print('Environment:')
for name in config.environment:
    print(f"  export {name}=\"{config.environment[name]}\"")
print('')

print('Features:')
features = ', '.join(config.available_features)
print(' ', '\n  '.join(textwrap.wrap(features, width=78)))
print('')
