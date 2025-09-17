import ctypes as C
import json
import os
import sys
from typing import Dict, Optional

EOS_Success = 0
EOS_LimitExceeded = 38

_PLATFORM_REFS: Dict[int, C.c_void_p] = {}


def _as_c_void_p(handle) -> C.c_void_p:
    """Normalize arbitrary handle inputs to a ctypes void* without double-wrapping."""
    if isinstance(handle, C.c_void_p):
        return handle
    if handle is None:
        return C.c_void_p(0)
    return C.c_void_p(int(handle))


def _retain_platform(handle) -> C.c_void_p:
    """Remember a platform handle for the process lifetime until an explicit release."""
    h = _as_c_void_p(handle)
    if h and h.value:
        _PLATFORM_REFS[h.value] = h
    return h


def _forget_platform(handle) -> None:
    h = _as_c_void_p(handle)
    if h and h.value:
        _PLATFORM_REFS.pop(h.value, None)

def _libname() -> str:
    if sys.platform.startswith("win"):
        return "eos_shim.dll"
    if sys.platform == "darwin":
        return "libeos_shim.dylib"
    return "libeos_shim.so"

def _b(s: Optional[str]) -> Optional[bytes]:
    return None if s is None else s.encode("utf-8")

def _find_config(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("EOS_CONFIG")
    if env:
        return env
    return os.path.join(os.getcwd(), "eos.json")

def _load_config(path: Optional[str] = None) -> dict:
    p = _find_config(path)
    with open(p, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    required = [
        "product_name", "product_version",
        "product_id", "sandbox_id", "deployment_id",
        "client_id", "client_secret"
    ]
    missing = [k for k in required if k not in cfg or cfg[k] in (None, "")]
    if missing:
        raise KeyError(f"Missing config keys: {', '.join(missing)}")
    # Defaults
    cfg.setdefault("encryption_key", None)
    cfg.setdefault("cache_dir", None)
    cfg.setdefault("is_server", False)
    cfg.setdefault("tick_budget_ms", 0)
    cfg.setdefault("tick_thread_ms", 16)
    return cfg

class EOS:
    def __init__(self, lib_path: Optional[str] = None, config_path: Optional[str] = None):
        self._dll = C.CDLL(os.path.abspath(lib_path or _libname()))
        self._cfg = _load_config(config_path)
        self._plat = C.c_void_p(0)
        self._acct: Optional[str] = None
        self._init_product_name: Optional[bytes] = None
        self._init_product_version: Optional[bytes] = None
        self._set_prototypes()

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
        if not self._plat or not self._plat.value:
            raise RuntimeError("Platform not created")
        return self._plat

    def _need_account(self, epic_account_id: Optional[str]) -> bytes:
        aid = epic_account_id or self._acct
        if not aid:
            raise RuntimeError("No EpicAccountId available")
        return aid.encode()

    # Config-backed lifecycle
    def bootstrap(self, start_tick_thread: bool = True) -> None:
        self.initialize()
        self.create_platform()
        if start_tick_thread:
            self.start_tick_thread(self._cfg.get("tick_thread_ms", 16))

    def initialize(self) -> None:
        # Keep the initialization strings alive for the duration of the SDK session.
        # EOS may continue to reference the pointers provided in EOS_Initialize after
        # the call returns, so we retain the encoded bytes until shutdown.
        self._init_product_name = _b(self._cfg["product_name"])
        self._init_product_version = _b(self._cfg["product_version"])
        self._check(self._dll.eos_initialize_basic(
            self._init_product_name,
            self._init_product_version
        ))

    def shutdown(self) -> None:
        self.stop_tick_thread()
        self.release_platform()
        self._dll.eos_shutdown()
        self._init_product_name = None
        self._init_product_version = None

    def create_platform(self) -> None:
        if self._plat:
            self.release_platform()
        cfg = self._cfg
        h = self._dll.eos_platform_create_basic(
            _b(cfg["product_id"]),
            _b(cfg["sandbox_id"]),
            _b(cfg["deployment_id"]),
            _b(cfg["client_id"]),
            _b(cfg["client_secret"]),
            _b(cfg.get("encryption_key")),
            _b(cfg.get("cache_dir")),
            1 if cfg.get("is_server", False) else 0,
            int(cfg.get("tick_budget_ms", 0))
        )
        if not h:
            raise RuntimeError("EOS_Platform_Create failed")
        self._plat = _retain_platform(h)

    def release_platform(self) -> None:
        if self._plat:
            self._dll.eos_platform_release(self._plat)
            _forget_platform(self._plat)
            self._plat = C.c_void_p(0)
        self._acct = None

    def tick(self) -> None:
        if self._plat and self._plat.value:
            self._dll.eos_platform_tick(self._plat)

    def start_tick_thread(self, period_ms: int = 16) -> None:
        if self._plat and self._plat.value:
            self._check(self._dll.eos_platform_start_tick_thread(self._plat, int(period_ms)))

    def stop_tick_thread(self) -> None:
        if self._plat and self._plat.value:
            self._dll.eos_platform_stop_tick_thread(self._plat)

    # Auth
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass
