import os
import lit.formats
from pathlib import Path

config.name = 'AutoJIT'
config.test_format = lit.formats.ShTest(True)

config.suffixes = ['.cpp', '.ll']
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
