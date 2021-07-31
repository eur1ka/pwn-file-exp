import inspect
from pwn import *
def varname(var):
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
    return [var_name for var_name, var_val in callers_local_vars if var_val is var][0]

leak_addr = 0x100
print varname(leak_addr)

# log.info(varname(leak_addr)[0]+"=>{}".format(hex(leak_addr)))