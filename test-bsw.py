from ctypes import cdll

lib = cdll.LoadLibrary("target/release/librabe.so")
ctx = lib.bsw_context_create()
print(ctx)
print("done!")