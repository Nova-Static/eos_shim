# pyeos_ctypes.py
# Python bindings to eos_shim via ctypes using the high-level bootstrap API.

import ctypes as C
import os
import sys
from typing import Optional

if sys.platform.startswith("win"):
    _LIB = "eos_shim.dll"
elif sys.platform == "darwin":
    _LIB = "libeos_shim.dylib"
else:
    _LIB = "libeos_shim.so"

_dll = C.CDLL(os.path.abspath(_LIB))

_dll.eos_hl_bootstrap.argtypes = [
    C.c_char_p, C.c_char_p,
    C.c_char_p, C.c_char_p, C.c_char_p,
    C.c_char_p, C.c_char_p,
    C.c_char_p, C.c_char_p,
    C.c_char_p, C.c_char_p,
    C.c_int, C.c_int, C.c_int, C.c_int
]
_dll.eos_hl_bootstrap.restype = C.c_int

_dll.eos_hl_shutdown.argtypes = []
_dll.eos_hl_shutdown.restype = None

_dll.eos_hl_tick.argtypes = []
_dll.eos_hl_tick.restype = None

_dll.eos_hl_start_tick_thread.argtypes = [C.c_int]
_dll.eos_hl_start_tick_thread.restype = C.c_int

_dll.eos_hl_stop_tick_thread.argtypes = []
_dll.eos_hl_stop_tick_thread.restype = None

_dll.eos_hl_result_to_string.argtypes = [C.c_int]
_dll.eos_hl_result_to_string.restype = C.c_char_p

_dll.eos_hl_login_developer.argtypes = [C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_login_developer.restype = C.c_int

_dll.eos_hl_login_password.argtypes = [C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_login_password.restype = C.c_int

_dll.eos_hl_login_exchange_code.argtypes = [C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_login_exchange_code.restype = C.c_int

_dll.eos_hl_logout.argtypes = [C.c_char_p]
_dll.eos_hl_logout.restype = C.c_int

_dll.eos_hl_copy_user_auth_token.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_copy_user_auth_token.restype = C.c_int

_dll.eos_hl_query_id_token.argtypes = [C.c_char_p]
_dll.eos_hl_query_id_token.restype = C.c_int

_dll.eos_hl_copy_id_token.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_copy_id_token.restype = C.c_int

_dll.eos_hl_get_login_status.argtypes = [C.c_char_p]
_dll.eos_hl_get_login_status.restype = C.c_int

_dll.eos_hl_get_last_epic_account_id.argtypes = [C.c_char_p, C.POINTER(C.c_int32)]
_dll.eos_hl_get_last_epic_account_id.restype = C.c_int

EOS_Success = 0
EOS_LimitExceeded = 38  # buffer too small sentinel from EOS

_bootstrapped = False
_last_epic_account_id: Optional[str] = None


def _result_to_str(rc: int) -> str:
    p = _dll.eos_hl_result_to_string(int(rc))
    return p.decode("utf-8", "ignore") if p else ""


def _check(rc: int) -> None:
    if rc != EOS_Success:
        raise RuntimeError(f"EOS error {rc} ({_result_to_str(rc)})")


def _call_with_buffer(fn, *args) -> str:
    size = C.c_int32(256)
    buf = C.create_string_buffer(size.value)
    rc = fn(*args, buf, C.byref(size))
    if rc == EOS_LimitExceeded:
        buf = C.create_string_buffer(size.value)
        rc = fn(*args, buf, C.byref(size))
    _check(rc)
    return buf.value.decode()


def _resolve_account_id(epic_account_id: Optional[str]) -> bytes:
    acct = epic_account_id or _last_epic_account_id
    if not acct:
        raise RuntimeError("No EpicAccountId available")
    return acct.encode()


def bootstrap(product_name: str,
              product_version: str,
              product_id: str,
              sandbox_id: str,
              deployment_id: str,
              client_id: str,
              client_secret: str,
              dev_tool_address: str,
              dev_auth_user_id: str,
              *,
              encryption_key: Optional[str] = None,
              cache_dir: Optional[str] = None,
              persist_login: bool = True,
              is_server: bool = False,
              tick_budget_ms: int = 0,
              tick_thread_ms: int = 0) -> None:
    global _bootstrapped, _last_epic_account_id
    _check(_dll.eos_hl_bootstrap(
        product_name.encode(),
        product_version.encode(),
        product_id.encode(),
        sandbox_id.encode(),
        deployment_id.encode(),
        client_id.encode(),
        client_secret.encode(),
        None if encryption_key is None else encryption_key.encode(),
        None if cache_dir is None else cache_dir.encode(),
        dev_tool_address.encode(),
        dev_auth_user_id.encode(),
        1 if persist_login else 0,
        1 if is_server else 0,
        int(tick_budget_ms),
        int(tick_thread_ms)
    ))
    _bootstrapped = True
    _last_epic_account_id = None


def shutdown() -> None:
    global _bootstrapped, _last_epic_account_id
    if not _bootstrapped:
        return
    _dll.eos_hl_shutdown()
    _bootstrapped = False
    _last_epic_account_id = None


def tick() -> None:
    if _bootstrapped:
        _dll.eos_hl_tick()


def start_tick_thread(period_ms: int = 16) -> None:
    if _bootstrapped:
        _check(_dll.eos_hl_start_tick_thread(int(period_ms)))


def stop_tick_thread() -> None:
    if _bootstrapped:
        _dll.eos_hl_stop_tick_thread()


def auth_login_developer() -> str:
    global _last_epic_account_id
    token = _call_with_buffer(_dll.eos_hl_login_developer)
    _last_epic_account_id = _call_with_buffer(_dll.eos_hl_get_last_epic_account_id)
    return token


def auth_login_password(user_id: str, secret: str, persist: bool = True) -> str:
    global _last_epic_account_id
    acct = _call_with_buffer(
        _dll.eos_hl_login_password,
        user_id.encode(),
        secret.encode(),
        1 if persist else 0
    )
    _last_epic_account_id = acct
    return acct


def auth_login_exchange_code(exchange_code: str, persist: bool = True) -> str:
    global _last_epic_account_id
    acct = _call_with_buffer(
        _dll.eos_hl_login_exchange_code,
        exchange_code.encode(),
        1 if persist else 0
    )
    _last_epic_account_id = acct
    return acct


def auth_logout(epic_account_id: Optional[str] = None) -> None:
    global _last_epic_account_id
    _check(_dll.eos_hl_logout(_resolve_account_id(epic_account_id)))
    if epic_account_id is None:
        _last_epic_account_id = None


def auth_copy_user_auth_token(epic_account_id: Optional[str] = None) -> str:
    return _call_with_buffer(
        _dll.eos_hl_copy_user_auth_token,
        _resolve_account_id(epic_account_id)
    )


def auth_query_id_token(epic_account_id: Optional[str] = None) -> None:
    _check(_dll.eos_hl_query_id_token(_resolve_account_id(epic_account_id)))


def auth_copy_id_token(epic_account_id: Optional[str] = None) -> str:
    return _call_with_buffer(
        _dll.eos_hl_copy_id_token,
        _resolve_account_id(epic_account_id)
    )


def auth_get_login_status(epic_account_id: Optional[str] = None) -> int:
    return int(_dll.eos_hl_get_login_status(_resolve_account_id(epic_account_id)))


def last_epic_account_id() -> Optional[str]:
    return _last_epic_account_id


if __name__ == "__main__":
    bootstrap(
        "MyProduct", "1.0",
        "<product_id>", "<sandbox_id>", "<deployment_id>",
        "<client_id>", "<client_secret>",
        "127.0.0.1:7777", "dev_user",
        tick_thread_ms=16
    )
    start_tick_thread(16)
    token = auth_login_developer()
    acct = last_epic_account_id() or ""
    jwt = auth_copy_id_token(acct)
    status = auth_get_login_status(acct)
    print("Token:", token[:8], "...", "Status:", status, "JWT len:", len(jwt))
    auth_logout(acct)
    shutdown()
