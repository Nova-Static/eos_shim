# eos_runtime.py
import ctypes as C
import os
import sys
from typing import Optional

def _libname() -> str:
    if sys.platform.startswith("win"):
        return "eos_shim.dll"
    if sys.platform == "darwin":
        return "libeos_shim.dylib"
    return "libeos_shim.so"

def _b(s: Optional[str]) -> Optional[bytes]:
    return None if s is None else s.encode("utf-8")

EOS_Success = 0
EOS_LimitExceeded = 38

class EOS:
    def __init__(self, lib_path: Optional[str] = None):
        self._dll = C.CDLL(os.path.abspath(lib_path or _libname()))
        self._plat = C.c_void_p(0)
        self._acct: Optional[str] = None
        self._set_prototypes()

    # -------- Prototypes --------
    def _set_prototypes(self) -> None:
        d = self._dll

        d.eos_initialize_basic.argtypes = [C.c_char_p, C.c_char_p]
        d.eos_initialize_basic.restype  = C.c_int
        d.eos_shutdown.argtypes = []
        d.eos_shutdown.restype  = None

        d.eos_platform_create_basic.argtypes = [
            C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p,
            C.c_char_p, C.c_char_p, C.c_int, C.c_int
        ]
        d.eos_platform_create_basic.restype  = C.c_void_p
        d.eos_platform_release.argtypes      = [C.c_void_p]
        d.eos_platform_release.restype       = None
        d.eos_platform_tick.argtypes         = [C.c_void_p]
        d.eos_platform_tick.restype          = None
        d.eos_platform_start_tick_thread.argtypes = [C.c_void_p, C.c_int]
        d.eos_platform_start_tick_thread.restype  = C.c_int
        d.eos_platform_stop_tick_thread.argtypes  = [C.c_void_p]
        d.eos_platform_stop_tick_thread.restype   = None

        d.eos_result_to_string.argtypes = [C.c_int]
        d.eos_result_to_string.restype  = C.c_char_p

        d.eos_auth_login_developer.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_auth_login_developer.restype  = C.c_int
        d.eos_auth_login_password.argtypes  = [C.c_void_p, C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_auth_login_password.restype   = C.c_int
        d.eos_auth_login_exchange_code.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_auth_login_exchange_code.restype  = C.c_int
        d.eos_auth_logout.argtypes          = [C.c_void_p, C.c_char_p]
        d.eos_auth_logout.restype           = C.c_int

        d.eos_auth_copy_user_auth_token.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_auth_copy_user_auth_token.restype  = C.c_int
        d.eos_auth_query_id_token.argtypes       = [C.c_void_p, C.c_char_p]
        d.eos_auth_query_id_token.restype        = C.c_int
        d.eos_auth_copy_id_token.argtypes        = [C.c_void_p, C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_auth_copy_id_token.restype         = C.c_int
        d.eos_auth_get_login_status.argtypes     = [C.c_void_p, C.c_char_p]
        d.eos_auth_get_login_status.restype      = C.c_int

    # -------- Helpers --------
    def _check(self, rc: int) -> None:
        if rc != EOS_Success:
            s = self._dll.eos_result_to_string(rc)
            msg = s.decode("utf-8", "ignore") if s else ""
            raise RuntimeError(f"EOS error {rc} ({msg})")

    def _buf_call(self, fn, *args) -> str:
        n = C.c_int32(256)
        buf = C.create_string_buffer(n.value)
        rc = fn(*args, buf, C.byref(n))
        if rc == EOS_LimitExceeded:
            buf = C.create_string_buffer(n.value)
            rc = fn(*args, buf, C.byref(n))
        self._check(rc)
        return buf.value.decode()

    def _need_platform(self) -> C.c_void_p:
        if not self._plat:
            raise RuntimeError("Platform not created")
        return self._plat

    def _need_account(self, epic_account_id: Optional[str]) -> bytes:
        aid = epic_account_id or self._acct
        if not aid:
            raise RuntimeError("No EpicAccountId available")
        return aid.encode()

    # -------- Lifecycle --------
    def initialize(self, product_name: str, product_version: str) -> None:
        self._check(self._dll.eos_initialize_basic(_b(product_name), _b(product_version)))

    def shutdown(self) -> None:
        self.stop_tick_thread()
        self.release_platform()
        self._dll.eos_shutdown()

    # -------- Platform --------
    def create_platform(self,
                        product_id: str, sandbox_id: str, deployment_id: str,
                        client_id: str, client_secret: str,
                        encryption_key: Optional[str] = None,
                        cache_dir: Optional[str] = None,
                        is_server: bool = False,
                        tick_budget_ms: int = 0) -> None:
        if self._plat:
            self.release_platform()
        h = self._dll.eos_platform_create_basic(
            _b(product_id), _b(sandbox_id), _b(deployment_id),
            _b(client_id), _b(client_secret),
            _b(encryption_key), _b(cache_dir),
            1 if is_server else 0, int(tick_budget_ms)
        )
        if not h:
            raise RuntimeError("EOS_Platform_Create failed")
        self._plat = C.c_void_p(h)

    def release_platform(self) -> None:
        if self._plat:
            self._dll.eos_platform_release(self._plat)
            self._plat = C.c_void_p(0)
        self._acct = None

    def tick(self) -> None:
        if self._plat:
            self._dll.eos_platform_tick(self._plat)

    def start_tick_thread(self, period_ms: int = 16) -> None:
        if self._plat:
            self._check(self._dll.eos_platform_start_tick_thread(self._plat, int(period_ms)))

    def stop_tick_thread(self) -> None:
        if self._plat:
            self._dll.eos_platform_stop_tick_thread(self._plat)

    # -------- Auth --------
    def login_developer(self, tool_addr_port: str, dev_user_id: str, persist: bool = True) -> str:
        acct = self._buf_call(
            self._dll.eos_auth_login_developer,
            self._need_platform(),
            _b(tool_addr_port),
            _b(dev_user_id),
            1 if persist else 0
        )
        self._acct = acct
        return acct

    def login_password(self, user_id: str, secret: str, persist: bool = True) -> str:
        acct = self._buf_call(
            self._dll.eos_auth_login_password,
            self._need_platform(),
            _b(user_id),
            _b(secret),
            1 if persist else 0
        )
        self._acct = acct
        return acct

    def login_exchange_code(self, exchange_code: str, persist: bool = True) -> str:
        acct = self._buf_call(
            self._dll.eos_auth_login_exchange_code,
            self._need_platform(),
            _b(exchange_code),
            1 if persist else 0
        )
        self._acct = acct
        return acct

    def logout(self, epic_account_id: Optional[str] = None) -> None:
        self._check(self._dll.eos_auth_logout(self._need_platform(), self._need_account(epic_account_id)))
        if not epic_account_id:
            self._acct = None

    def copy_user_auth_token(self, epic_account_id: Optional[str] = None) -> str:
        return self._buf_call(
            self._dll.eos_auth_copy_user_auth_token,
            self._need_platform(),
            self._need_account(epic_account_id)
        )

    def query_id_token(self, epic_account_id: Optional[str] = None) -> None:
        self._check(self._dll.eos_auth_query_id_token(self._need_platform(), self._need_account(epic_account_id)))

    def copy_id_token(self, epic_account_id: Optional[str] = None) -> str:
        return self._buf_call(
            self._dll.eos_auth_copy_id_token,
            self._need_platform(),
            self._need_account(epic_account_id)
        )

    def get_login_status(self, epic_account_id: Optional[str] = None) -> int:
        return int(self._dll.eos_auth_get_login_status(self._need_platform(), self._need_account(epic_account_id)))

    # -------- Context manager --------
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass
