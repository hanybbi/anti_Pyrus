import importlib
import aestest
import sys

def load(mod_name) :
    fp = open(mod_name + '.py', 'rb')
    buf = fp.read()
    fp.close()

    module = importlib.import_module(mod_name)
    exec(buf)
    sys.modules[mod_name] = module

    return module


