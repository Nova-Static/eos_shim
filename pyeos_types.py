# pyeos_ctypes.py
# Python bindings to eos_shim via ctypes.

import ctypes as C
import os
import sys

if sys.platform.startswith("win"):
    _LIB = "eos_shim.dll"
elif sys.platform == "darwin":
    _LIB = "libeos_shim.dylib"
else:
    _LIB = "libeos_shim.so"

_dll = C.CDLL(os.path.abspath(_LIB))

# Prototypes
_dll.eos_initialize_basic.argtypes = [C.c_char_p, C.c_char_p]
_dll.eos_initialize_basic.restype  = C.c_int
_dll.eos_shutdown.argtypes = []
_dll.eos_shutdown.restype  = None

_dll.eos_platform_create_basic.argtypes = [
    C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p,
    C.c_char_p, C.c_char_p, C.c_int, C.c_int
]
_dll.eos_platform_create_basic.restype  = C.c_void_p
_dll.eos_platform_release.argtypes      = [C.c_void_p]
_dll.eos_platform_release.restype       = None
_dll.eos_platform_tick.argtypes         = [C.c_void_p]
_dll.eos_platform_tick.restype          = None
_dll.eos_platform_start_tick_thread.argtypes = [C.c_void_p, C.c_int]
_dll.eos_platform_start_tick_thread.restype  = C.c_int
_dll.eos_platform_stop_tick_thread.argtypes  = [C.c_void_p]
_dll.eos_platform_stop_tick_thread.restype   = None

_dll.eos_result_to_string.argtypes = [C.c_int]
_dll.eos_result_to_string.restype  = C.c_char_p

_dll.eos_auth_login_exchange_code.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_auth_login_exchange_code.restype  = C.c_int
_dll.eos_auth_login_password.argtypes      = [C.c_void_p, C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_auth_login_password.restype       = C.c_int
_dll.eos_auth_login_developer.argtypes     = [C.c_void_p, C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_auth_login_developer.restype      = C.c_int
_dll.eos_auth_logout.argtypes              = [C.c_void_p, C.c_char_p]
_dll.eos_auth_logout.restype               = C.c_int

_dll.eos_auth_copy_user_auth_token.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_auth_copy_user_auth_token.restype  = C.c_int
_dll.eos_auth_query_id_token.argtypes       = [C.c_void_p, C.c_char_p]
_dll.eos_auth_query_id_token.restype        = C.c_int
_dll.eos_auth_copy_id_token.argtypes        = [C.c_void_p, C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_auth_copy_id_token.restype         = C.c_int
_dll.eos_auth_get_login_status.argtypes     = [C.c_void_p, C.c_char_p]
_dll.eos_auth_get_login_status.restype      = C.c_int

EOS_Success = 0
EOS_LimitExceeded = 38  # buffer too small sentinel from EOS

def _result_to_str(rc: int) -> str:
    p = _dll.eos_result_to_string(int(rc))
    return p.decode("utf-8", "ignore") if p else ""

def _check(rc: int) -> None:
    if rc != EOS_Success:
        raise RuntimeError(f"EOS error {rc} ({_result_to_str(rc)})")

def initialize(product_name: str, product_version: str) -> None:
    _check(_dll.eos_initialize_basic(product_name.encode(), product_version.encode()))

def shutdown() -> None:
    _dll.eos_shutdown()

def platform_create_basic(product_id: str, sandbox_id: str, deployment_id: str,
                          client_id: str, client_secret: str,
                          encryption_key: str | None = None,
                          cache_dir: str | None = None,
                          is_server: bool = False,
                          tick_budget_ms: int = 0) -> int:
    h = _dll.eos_platform_create_basic(
        product_id.encode(), sandbox_id.encode(), deployment_id.encode(),
        client_id.encode(), client_secret.encode(),
        None if not encryption_key else encryption_key.encode(),
        None if not cache_dir else cache_dir.encode(),
        1 if is_server else 0,
        int(tick_budget_ms)
    )
    if not h:
        raise RuntimeError("EOS_Platform_Create failed")
    return h

def platform_release(handle: int) -> None:
    _dll.eos_platform_release(handle)

def platform_tick(handle: int) -> None:
    _dll.eos_platform_tick(handle)

def platform_start_tick_thread(handle: int, period_ms: int = 16) -> None:
    _check(_dll.eos_platform_start_tick_thread(handle, int(period_ms)))

def platform_stop_tick_thread(handle: int) -> None:
    _dll.eos_platform_stop_tick_thread(handle)

def _call_with_buffer(fn, *args) -> str:
    size = C.c_int32(256)
    buf = C.create_string_buffer(size.value)
    rc = fn(*args, buf, C.byref(size))
    if rc == EOS_LimitExceeded:
        buf = C.create_string_buffer(size.value)
        rc = fn(*args, buf, C.byref(size))
    _check(rc)
    return buf.value.decode()

def auth_login_exchange_code(handle: int, exchange_code: str, persist: bool = True) -> str:
    return _call_with_buffer(_dll.eos_auth_login_exchange_code, handle, exchange_code.encode(), 1 if persist else 0)

def auth_login_password(handle: int, user_id: str, secret: str, persist: bool = True) -> str:
    return _call_with_buffer(_dll.eos_auth_login_password, handle, user_id.encode(), secret.encode(), 1 if persist else 0)

def auth_login_developer(handle: int, tool_addr_port: str, dev_user_id: str, persist: bool = True) -> str:
    return _call_with_buffer(_dll.eos_auth_login_developer, handle, tool_addr_port.encode(), dev_user_id.encode(), 1 if persist else 0)

def auth_logout(handle: int, epic_account_id: str) -> None:
    _check(_dll.eos_auth_logout(handle, epic_account_id.encode()))

def auth_copy_user_auth_token(handle: int, epic_account_id: str) -> str:
    return _call_with_buffer(_dll.eos_auth_copy_user_auth_token, handle, epic_account_id.encode())

def auth_query_id_token(handle: int, epic_account_id: str) -> None:
    _check(_dll.eos_auth_query_id_token(handle, epic_account_id.encode()))

def auth_copy_id_token(handle: int, epic_account_id: str) -> str:
    return _call_with_buffer(_dll.eos_auth_copy_id_token, handle, epic_account_id.encode())

def auth_get_login_status(handle: int, epic_account_id: str) -> int:
    return int(_dll.eos_auth_get_login_status(handle, epic_account_id.encode()))

if __name__ == "__main__":
    initialize("MyProduct", "1.0")
    plat = platform_create_basic(
        "<product_id>", "<sandbox_id>", "<deployment_id>",
        "<client_id>", "<client_secret>"
    )
    platform_start_tick_thread(plat, 16)
    acct = auth_login_developer(plat, "127.0.0.1:7777", "dev_user", True)
    tok  = auth_copy_user_auth_token(plat, acct)
    auth_query_id_token(plat, acct)
    jwt  = auth_copy_id_token(plat, acct)
    _ = auth_get_login_status(plat, acct)
    auth_logout(plat, acct)
    platform_stop_tick_thread(plat)
    platform_release(plat)
    shutdown()
