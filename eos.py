import ctypes as C
import json
import os
import sys
from typing import Optional

EOS_Success = 0
EOS_LimitExceeded = 38

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
        "client_id", "client_secret",
        "dev_tool_address", "dev_auth_user_id"
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
    cfg.setdefault("persist_login", True)
    return cfg

class EOS:
    def __init__(self, lib_path: Optional[str] = None, config_path: Optional[str] = None):
        self._dll = C.CDLL(os.path.abspath(lib_path or _libname()))
        self._cfg = _load_config(config_path)
        self._acct: Optional[str] = None
        self._bootstrapped = False
        self._set_prototypes()

    def _set_prototypes(self) -> None:
        d = self._dll
        d.eos_hl_bootstrap.argtypes = [
            C.c_char_p, C.c_char_p,
            C.c_char_p, C.c_char_p, C.c_char_p,
            C.c_char_p, C.c_char_p,
            C.c_char_p, C.c_char_p,
            C.c_char_p, C.c_char_p,
            C.c_int, C.c_int, C.c_int, C.c_int
        ]
        d.eos_hl_bootstrap.restype = C.c_int

        d.eos_hl_shutdown.argtypes = []
        d.eos_hl_shutdown.restype = None

        d.eos_hl_tick.argtypes = []
        d.eos_hl_tick.restype = None

        d.eos_hl_start_tick_thread.argtypes = [C.c_int]
        d.eos_hl_start_tick_thread.restype = C.c_int

        d.eos_hl_stop_tick_thread.argtypes = []
        d.eos_hl_stop_tick_thread.restype = None

        d.eos_hl_result_to_string.argtypes = [C.c_int]
        d.eos_hl_result_to_string.restype = C.c_char_p

        d.eos_hl_login_developer.argtypes = [C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_login_developer.restype = C.c_int

        d.eos_hl_login_password.argtypes = [C.c_char_p, C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_login_password.restype = C.c_int

        d.eos_hl_login_exchange_code.argtypes = [C.c_char_p, C.c_int, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_login_exchange_code.restype = C.c_int

        d.eos_hl_logout.argtypes = [C.c_char_p]
        d.eos_hl_logout.restype = C.c_int

        d.eos_hl_copy_user_auth_token.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_copy_user_auth_token.restype = C.c_int

        d.eos_hl_query_id_token.argtypes = [C.c_char_p]
        d.eos_hl_query_id_token.restype = C.c_int

        d.eos_hl_copy_id_token.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_copy_id_token.restype = C.c_int

        d.eos_hl_get_login_status.argtypes = [C.c_char_p]
        d.eos_hl_get_login_status.restype = C.c_int

        d.eos_hl_get_last_epic_account_id.argtypes = [C.c_char_p, C.POINTER(C.c_int32)]
        d.eos_hl_get_last_epic_account_id.restype = C.c_int

    def _check(self, rc: int) -> None:
        if rc != EOS_Success:
            s = self._dll.eos_hl_result_to_string(rc)
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

    def _need_account(self, epic_account_id: Optional[str]) -> bytes:
        aid = epic_account_id or self._acct
        if not aid:
            raise RuntimeError("No EpicAccountId available")
        return aid.encode()

    # Config-backed lifecycle
    def bootstrap(self, start_tick_thread: bool = True) -> None:
        self._ensure_bootstrap(start_tick_thread=start_tick_thread)

    def initialize(self) -> None:
        self._ensure_bootstrap(start_tick_thread=False)

    def shutdown(self) -> None:
        if not self._bootstrapped:
            return
        self.stop_tick_thread()
        self._dll.eos_hl_shutdown()
        self._bootstrapped = False
        self._acct = None

    def create_platform(self) -> None:
        self._ensure_bootstrap(start_tick_thread=False)

    def release_platform(self) -> None:
        self.shutdown()

    def tick(self) -> None:
        if self._bootstrapped:
            self._dll.eos_hl_tick()

    def start_tick_thread(self, period_ms: int = 16) -> None:
        if self._bootstrapped:
            self._check(self._dll.eos_hl_start_tick_thread(int(period_ms)))

    def stop_tick_thread(self) -> None:
        if self._bootstrapped:
            self._dll.eos_hl_stop_tick_thread()

    # Auth
    def login_developer(self) -> str:
        token = self._buf_call(
            self._dll.eos_hl_login_developer
        )
        self._acct = self._buf_call(self._dll.eos_hl_get_last_epic_account_id)
        return token

    def login_password(self, user_id: str, secret: str, persist: bool = True) -> str:
        acct = self._buf_call(
            self._dll.eos_hl_login_password,
            _b(user_id),
            _b(secret),
            1 if persist else 0
        )
        self._acct = acct
        return acct

    def login_exchange_code(self, exchange_code: str, persist: bool = True) -> str:
        acct = self._buf_call(
            self._dll.eos_hl_login_exchange_code,
            _b(exchange_code),
            1 if persist else 0
        )
        self._acct = acct
        return acct

    def logout(self, epic_account_id: Optional[str] = None) -> None:
        self._check(self._dll.eos_hl_logout(self._need_account(epic_account_id)))
        if not epic_account_id:
            self._acct = None

    def copy_user_auth_token(self, epic_account_id: Optional[str] = None) -> str:
        return self._buf_call(
            self._dll.eos_hl_copy_user_auth_token,
            self._need_account(epic_account_id)
        )

    def query_id_token(self, epic_account_id: Optional[str] = None) -> None:
        self._check(self._dll.eos_hl_query_id_token(self._need_account(epic_account_id)))

    def copy_id_token(self, epic_account_id: Optional[str] = None) -> str:
        return self._buf_call(
            self._dll.eos_hl_copy_id_token,
            self._need_account(epic_account_id)
        )

    def get_login_status(self, epic_account_id: Optional[str] = None) -> int:
        return int(self._dll.eos_hl_get_login_status(self._need_account(epic_account_id)))

    def last_epic_account_id(self) -> Optional[str]:
        try:
            return self._buf_call(self._dll.eos_hl_get_last_epic_account_id)
        except RuntimeError:
            return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def _ensure_bootstrap(self, start_tick_thread: bool) -> None:
        if self._bootstrapped:
            if start_tick_thread:
                self.start_tick_thread(self._cfg.get("tick_thread_ms", 16))
            return
        cfg = self._cfg
        period = int(cfg.get("tick_thread_ms", 16)) if start_tick_thread else 0
        self._check(self._dll.eos_hl_bootstrap(
            _b(cfg["product_name"]),
            _b(cfg["product_version"]),
            _b(cfg["product_id"]),
            _b(cfg["sandbox_id"]),
            _b(cfg["deployment_id"]),
            _b(cfg["client_id"]),
            _b(cfg["client_secret"]),
            _b(cfg.get("encryption_key")),
            _b(cfg.get("cache_dir")),
            _b(cfg.get("dev_tool_address")),
            _b(cfg.get("dev_auth_user_id")),
            1 if cfg.get("persist_login", True) else 0,
            1 if cfg.get("is_server", False) else 0,
            int(cfg.get("tick_budget_ms", 0)),
            period
        ))
        self._bootstrapped = True
        if start_tick_thread:
            self.start_tick_thread(self._cfg.get("tick_thread_ms", 16))
