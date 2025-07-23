import os
import lit.formats

config.name = 'AutoJIT'
config.test_format = lit.formats.ShTest(True)

# Describe test files
config.suffixes = ['.cpp']
config.excludes = ["Inputs"]

config.test_source_root = os.path.dirname(__file__)
config.test_exec_root = os.path.join(config.llvm_build_dir, "tools", "autojit", "test")

config.substitutions.append(('%autojit_plugin', config.autojit_plugin))
config.substitutions.append(('%autojit_runtime_dir', config.autojit_runtime_dir))
config.substitutions.append(('%clang', 'clang++'))
config.substitutions.append(('%ar', 'llvm-ar'))
config.substitutions.append(('%ranlib', 'llvm-ranlib'))

import os
config.environment['PATH'] = os.path.pathsep.join((config.llvm_tools_dir, config.environment.get('PATH', '')))

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
