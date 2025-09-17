# pyeos_ctypes.py
# Python bindings to eos_shim via ctypes.

import ctypes as C
import os
import sys
from typing import Dict

if sys.platform.startswith("win"):
    _LIB = "eos_shim.dll"
elif sys.platform == "darwin":
    _LIB = "libeos_shim.dylib"
else:
    _LIB = "libeos_shim.so"

_dll = C.CDLL(os.path.abspath(_LIB))

_PLATFORM_REFS: Dict[int, C.c_void_p] = {}


def _as_c_void_p(handle) -> C.c_void_p:
    if isinstance(handle, C.c_void_p):
        return handle
    if handle is None:
        return C.c_void_p(0)
    return C.c_void_p(int(handle))


def _retain_platform(handle) -> C.c_void_p:
    h = _as_c_void_p(handle)
    if h and h.value:
        _PLATFORM_REFS[h.value] = h
    return h


def _forget_platform(handle) -> None:
    h = _as_c_void_p(handle)
    if h and h.value:
        _PLATFORM_REFS.pop(h.value, None)

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

_init_product_name: bytes | None = None
_init_product_version: bytes | None = None

def _result_to_str(rc: int) -> str:
    p = _dll.eos_result_to_string(int(rc))
    return p.decode("utf-8", "ignore") if p else ""

def _check(rc: int) -> None:
    if rc != EOS_Success:
        raise RuntimeError(f"EOS error {rc} ({_result_to_str(rc)})")

def initialize(product_name: str, product_version: str) -> None:
    global _init_product_name, _init_product_version
    _init_product_name = product_name.encode()
    _init_product_version = product_version.encode()
    _check(_dll.eos_initialize_basic(_init_product_name, _init_product_version))

def shutdown() -> None:
    global _init_product_name, _init_product_version
    _dll.eos_shutdown()
    _init_product_name = None
    _init_product_version = None

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
    return _retain_platform(h)

def platform_release(handle: int) -> None:
    h = _as_c_void_p(handle)
    _dll.eos_platform_release(h)
    _forget_platform(h)

def platform_tick(handle: int) -> None:
    h = _as_c_void_p(handle)
    if h and h.value:
        _dll.eos_platform_tick(h)

def platform_start_tick_thread(handle: int, period_ms: int = 16) -> None:
    h = _as_c_void_p(handle)
    if h and h.value:
        _check(_dll.eos_platform_start_tick_thread(h, int(period_ms)))

def platform_stop_tick_thread(handle: int) -> None:
    h = _as_c_void_p(handle)
    if h and h.value:
        _dll.eos_platform_stop_tick_thread(h)

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
    h = _as_c_void_p(handle)
    return _call_with_buffer(_dll.eos_auth_login_exchange_code, h, exchange_code.encode(), 1 if persist else 0)

def auth_login_password(handle: int, user_id: str, secret: str, persist: bool = True) -> str:
    h = _as_c_void_p(handle)
    return _call_with_buffer(_dll.eos_auth_login_password, h, user_id.encode(), secret.encode(), 1 if persist else 0)

def auth_login_developer(handle: int, tool_addr_port: str, dev_user_id: str, persist: bool = True) -> str:
    h = _as_c_void_p(handle)
    return _call_with_buffer(_dll.eos_auth_login_developer, h, tool_addr_port.encode(), dev_user_id.encode(), 1 if persist else 0)

def auth_logout(handle: int, epic_account_id: str) -> None:
    h = _as_c_void_p(handle)
    _check(_dll.eos_auth_logout(h, epic_account_id.encode()))

def auth_copy_user_auth_token(handle: int, epic_account_id: str) -> str:
    h = _as_c_void_p(handle)
    return _call_with_buffer(_dll.eos_auth_copy_user_auth_token, h, epic_account_id.encode())

def auth_query_id_token(handle: int, epic_account_id: str) -> None:
    h = _as_c_void_p(handle)
    _check(_dll.eos_auth_query_id_token(h, epic_account_id.encode()))

def auth_copy_id_token(handle: int, epic_account_id: str) -> str:
    h = _as_c_void_p(handle)
    return _call_with_buffer(_dll.eos_auth_copy_id_token, h, epic_account_id.encode())

def auth_get_login_status(handle: int, epic_account_id: str) -> int:
    h = _as_c_void_p(handle)
    return int(_dll.eos_auth_get_login_status(h, epic_account_id.encode()))

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
