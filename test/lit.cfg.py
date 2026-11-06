import inspect
import os
import lit.formats
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

config.name = 'AutoJIT'
# Tests use the external shell. Since LLVM 23 lit requires a flag for that.
# FIXME: Migrate to the internal shell
if 'force_execute_external' in inspect.signature(lit.formats.ShTest).parameters:
    config.test_format = lit.formats.ShTest(True, force_execute_external=True)
else:
    config.test_format = lit.formats.ShTest(True)
config.filecheck_opts = '--dump-input=fail --dump-input-filter=all'

# timeout in seconds
supported, err = lit_config.maxIndividualTestTimeIsSupported
if supported:
    # Since LLVM 23 the timeout is per test suite
    if hasattr(config, 'maxIndividualTestTime'):
        config.maxIndividualTestTime = 60
    else:
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
config.available_features.add(config.host_arch)
try:
    with open('/proc/cpuinfo') as cpuinfo:
        if ' avx ' in cpuinfo.read():
            config.available_features.add('avx')
except OSError:
    pass

if config.sanitize:
    config.substitutions.append(('%fsanitize', f"-fsanitize={config.sanitize}" ))
else:
    config.substitutions.append(('%fsanitize', ""))

bin = Path(config.llvm_tools_dir)
config.substitutions.append(('%clang_c', str(bin / 'clang')))
config.substitutions.append(('%clang', str(bin / 'clang++')))
config.substitutions.append(('%ar', str(bin / 'llvm-ar')))
config.substitutions.append(('%opt', str(bin / 'opt')))
config.substitutions.append(('%llc', str(bin / 'llc')))
config.substitutions.append(('%readelf', str(bin / 'llvm-readelf')))
config.substitutions.append(('FileCheck', str(bin / 'FileCheck')))

# Tests with IR for a specific target need its backend, e.g. x86-registered-target
targets = subprocess.check_output([str(bin / 'llvm-config'), '--targets-built'],
                                  text=True)
for target in targets.split():
    config.available_features.add(target.lower() + '-registered-target')

config.environment['PATH'] = config.llvm_tools_dir + ":/usr/bin"

if 'AUTOJIT_USE_TPDE' in os.environ:
    use_tpde = os.environ.get('AUTOJIT_USE_TPDE')
else:
    use_tpde = config.enable_tpde

config.environment['AUTOJIT_USE_TPDE'] = use_tpde
print("Running regression tests with TPDE:", use_tpde)
if use_tpde.strip().lower() in {"1", "on", "yes", "true"}:
    config.available_features.add('tpde')

def is_set(var_name: str) -> bool:
    val = os.getenv(var_name)
    return val is not None and val.strip().lower() in {"1", "on", "yes", "true"}

# Forward for debugging if enabled on host
if is_set('AUTOJIT_DEBUG'):
    config.environment['AUTOJITD_DEBUG'] = 'On'

# Tests spawn the daemon of this build. Other daemons on the machine may belong
# to another build, so only use one on request.
daemon_bin = Path(config.autojit_tools_dir) / 'autojitd'
config.environment['AUTOJIT_DAEMON_PATH'] = str(daemon_bin)

if is_set('AUTOJITD_FORCE_DAEMON') and not is_set('AUTOJITD_FORCE_SPAWN'):
    # Same order as in the stub
    if 'AUTOJIT_SOCKET_PATH' in os.environ:
        daemon_socket = Path(os.environ['AUTOJIT_SOCKET_PATH'])
    elif 'XDG_RUNTIME_DIR' in os.environ:
        daemon_socket = Path(os.environ['XDG_RUNTIME_DIR']) / 'autojitd.sock'
    else:
        daemon_socket = Path(f'/tmp/autojitd-{os.getuid()}.sock')
    if not daemon_socket.is_socket():
        raise RuntimeError(f"AUTOJITD_FORCE_DAEMON set, but no socket at {daemon_socket}")
    config.environment['AUTOJITD_FORCE_DAEMON'] = 'On'
    lit_config.warning("Running tests against external autojitd breaks test isolation")
    print(f"Daemon is up and running: {daemon_socket}")
else:
    # Nothing listens here, so tests that allow connecting fall back to spawning
    daemon_socket = Path(config.test_exec_root) / 'no-daemon.sock'
    config.environment['AUTOJITD_FORCE_SPAWN'] = 'On'
    print(f"Daemon is spawned for each test: {daemon_bin}")

config.environment['AUTOJIT_SOCKET_PATH'] = str(daemon_socket)

config.environment['AUTOJIT_DISABLE_OBJECT_CACHE'] = 'On'

config.available_features.add('shell')
if hasattr(config, 'enable_plugins') and config.enable_plugins:
    config.available_features.add('plugins')

# Debugger tests need GDB and permission to launch programs under it, which
# might be prohibited in CI (e.g. ptrace in containers)
def can_run_gdb(gdb: str) -> bool:
    try:
        o = subprocess.run([gdb, '-batch', '-nx', '-ex', 'run', '--args', 'true'],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return o.returncode == 0 and 'exited normally' in o.stdout

gdb = shutil.which('gdb')
if gdb and can_run_gdb(gdb):
    config.available_features.add('gdb')
    config.substitutions.append(('%gdb', f"{gdb} -batch -nx -iex 'set debuginfod enabled off'"))

# Same for LLDB. Prefer the one that matches our LLVM version. Debuginfod is
# off like for GDB: with DEBUGINFOD_URLS set, LLDB may download symbols for
# system libraries and stall for tens of seconds. Source listings at stops are
# off, because they would echo CHECK lines into the output.
lldb_init = ("-O 'settings clear plugin.symbol-locator.debuginfod.server-urls'"
             " -O 'settings set plugin.jit-loader.gdb.enable on'"
             " -O 'settings set stop-line-count-before 0'"
             " -O 'settings set stop-line-count-after 0'")

def can_run_lldb(lldb: str) -> bool:
    try:
        o = subprocess.run([lldb, '-b', '-x', '-O',
                            'settings clear plugin.symbol-locator.debuginfod.server-urls',
                            '-o', 'run', '--', 'true'],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return o.returncode == 0 and 'exited with status = 0' in o.stdout

lldb = shutil.which('lldb', path=config.llvm_tools_dir) or shutil.which('lldb')
if lldb and can_run_lldb(lldb):
    config.available_features.add('lldb')
    config.substitutions.append(('%lldb', f"{lldb} -b -x {lldb_init}"))

# The runtime works with both C++ standard libraries. Check which ones we can
# build programs with.
def can_link_cxx(stdlib: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "test.cpp"
        src.write_text("#include <string>\nint main() { return std::string().size(); }\n")
        cmd = [str(bin / 'clang++'), f"-stdlib={stdlib}", str(src), "-o", str(Path(tmp) / "test")]
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

if can_link_cxx("libc++"):
    config.available_features.add('libcxx')
if can_link_cxx("libstdc++"):
    config.available_features.add('libstdcxx')

print('Environment:')
for name in config.environment:
    print(f"  export {name}=\"{config.environment[name]}\"")
print('')

print('Features:')
features = ', '.join(config.available_features)
print(' ', '\n  '.join(textwrap.wrap(features, width=78)))
print('')
