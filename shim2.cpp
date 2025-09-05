// eos_shim.cpp
// Native shim with logging over Epic Online Services (EOS).
// Exports a C ABI suitable for ctypes. Includes crash logging and EOS verbose logs.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <ctime>

#include "eos_sdk.h"
#include "eos_platform.h"
#include "eos_auth.h"
#include "eos_userinfo.h"
#include "eos_logging.h"

#if defined(_WIN32)
  #define DLL_EXPORT extern "C" __declspec(dllexport)
  #include <Windows.h>
  #include <dbghelp.h>
#else
  #define DLL_EXPORT extern "C" __attribute__((visibility("default")))
  #include <signal.h>
  #include <execinfo.h>
#endif

// ---------- File logging ----------
static std::mutex g_log_mu;
static FILE* g_log = nullptr;

static void log_open() {
#if defined(_WIN32)
    if (!g_log) { fopen_s(&g_log, "eos_shim.log", "a"); }
#else
    if (!g_log) { g_log = std::fopen("eos_shim.log", "a"); }
#endif
}
static void logfv(const char* lvl, const char* fmt, va_list ap) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    log_open();
    if (!g_log) return;
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char ts[32]; std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    std::fprintf(g_log, "%s [%s] ", ts, lvl);
    std::vfprintf(g_log, fmt, ap);
    std::fputc('\n', g_log);
    std::fflush(g_log);
}
static void logf(const char* lvl, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); logfv(lvl, fmt, ap); va_end(ap);
}
#define LOGI(...) logf("I", __VA_ARGS__)
#define LOGE(...) logf("E", __VA_ARGS__)

// ---------- Crash logging ----------
#if defined(_WIN32)
static LONG CALLBACK vectored_handler(EXCEPTION_POINTERS* ep) {
    LOGE("SEH exception code=0x%08X at %p", ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
    HMODULE hDbg = LoadLibraryA("dbghelp.dll");
    if (hDbg) {
        auto pMiniDumpWriteDump = (BOOL (WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
            PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION))
            GetProcAddress(hDbg, "MiniDumpWriteDump");
        if (pMiniDumpWriteDump) {
            HANDLE hFile = CreateFileA("eos_shim.dmp", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                MINIDUMP_EXCEPTION_INFORMATION mei{};
                mei.ThreadId = GetCurrentThreadId();
                mei.ExceptionPointers = ep;
                mei.ClientPointers = FALSE;
                pMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                                   (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory),
                                   &mei, nullptr, nullptr);
                CloseHandle(hFile);
                LOGE("Wrote eos_shim.dmp");
            }
        }
        FreeLibrary(hDbg);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#else
static void sig_handler(int sig) {
    LOGE("Signal %d", sig);
    void* addrs[64]; int n = backtrace(addrs, 64);
    char** syms = backtrace_symbols(addrs, n);
    for (int i = 0; i < n; ++i) LOGE("bt %s", syms[i]);
    std::fflush(nullptr);
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif

// ---------- EOS logging ----------
static void EOS_CALL eos_log_cb(const EOS_LogMessage* m) {
    if (!m || !m->Message) return;
    LOGI("EOS[%d] %s", (int)m->Level, m->Message);
#if defined(_WIN32)
    OutputDebugStringA(m->Message);
    OutputDebugStringA("\n");
#endif
}

// ---------- Helpers ----------
struct PlatformShim {
    EOS_HPlatform h{nullptr};
    std::atomic<bool> run{false};
    std::thread tick_thread;
    int tick_ms{16};
    ~PlatformShim() {
        stop_tick_thread();
        if (h) {
            LOGI("Platform release %p", (void*)h);
            EOS_Platform_Release(h);
            h = nullptr;
        }
    }
    void start_tick_thread(int period_ms) {
        if (run.load()) return;
        tick_ms = period_ms > 0 ? period_ms : 16;
        run.store(true);
        tick_thread = std::thread([this]{
            LOGI("Tick thread start (%d ms)", tick_ms);
            while (run.load()) {
                if (h) EOS_Platform_Tick(h);
                std::this_thread::sleep_for(std::chrono::milliseconds(tick_ms));
            }
            LOGI("Tick thread stop");
        });
    }
    void stop_tick_thread() {
        if (!run.load()) return;
        run.store(false);
        if (tick_thread.joinable()) tick_thread.join();
    }
    bool ticking() const { return run.load(); }
};

static inline const char* r2s(EOS_EResult r) {
    const char* s = EOS_EResult_ToString(r);
    return s ? s : "EOS_Unknown";
}

static inline std::string epic_id_to_str(EOS_EpicAccountId id) {
    if (!id) return {};
    char buf[EOS_EPICACCOUNTID_MAX_LENGTH + 1] = {};
    int32_t n = static_cast<int32_t>(sizeof(buf));
    EOS_EResult rc = EOS_EpicAccountId_ToString(id, buf, &n);
    if (rc != EOS_Success) return {};
    return std::string(buf);
}

static inline EOS_EResult write_out_string(const std::string& s, char* out, int32_t* inout_len) {
    if (!inout_len) return EOS_Success;
    int32_t needed = static_cast<int32_t>(s.size()) + 1;
    if (!out || *inout_len < needed) {
        *inout_len = needed;
        return EOS_LimitExceeded;
    }
    std::memcpy(out, s.c_str(), static_cast<size_t>(needed));
    *inout_len = needed;
    return EOS_Success;
}

struct WaitState {
    std::mutex m;
    std::condition_variable cv;
    bool done{false};
    EOS_EResult rc{EOS_UnexpectedError};
    std::string epic_id;

    // Owned input storage to survive async lifetime
    std::string id_s;
    std::string token_s;
    EOS_Auth_Credentials creds{};
    EOS_Auth_LoginOptions opts{};
};

static EOS_HAuth auth_if(PlatformShim* ps) {
    return ps && ps->h ? EOS_Platform_GetAuthInterface(ps->h) : nullptr;
}
static EOS_HUserInfo userinfo_if(PlatformShim* ps) {
    return ps && ps->h ? EOS_Platform_GetUserInfoInterface(ps->h) : nullptr;
}

// ---------- Callback shims (correct calling convention) ----------
static void EOS_CALL OnAuthLogin(const EOS_Auth_LoginCallbackInfo* info) {
    auto* pst = static_cast<WaitState*>(info->ClientData);
    if (!pst) return;
    std::lock_guard<std::mutex> lk(pst->m);
    pst->rc = info->ResultCode;
    pst->epic_id = epic_id_to_str(info->LocalUserId);
    pst->done = true;
    pst->cv.notify_all();
}

struct LWait { std::mutex m; std::condition_variable cv; bool done{false}; EOS_EResult rc{EOS_UnexpectedError}; };
static void EOS_CALL OnAuthLogout(const EOS_Auth_LogoutCallbackInfo* info) {
    auto* pst = static_cast<LWait*>(info->ClientData);
    if (!pst) return;
    std::lock_guard<std::mutex> lk(pst->m);
    pst->rc = info->ResultCode;
    pst->done = true;
    pst->cv.notify_all();
}

struct QWait { std::mutex m; std::condition_variable cv; bool done{false}; EOS_EResult rc{EOS_UnexpectedError}; };
static void EOS_CALL OnQueryIdToken(const EOS_Auth_QueryIdTokenCallbackInfo* info) {
    auto* pst = static_cast<QWait*>(info->ClientData);
    if (!pst) return;
    std::lock_guard<std::mutex> lk(pst->m);
    pst->rc = info->ResultCode;
    pst->done = true;
    pst->cv.notify_all();
}

struct UIWait { std::mutex m; std::condition_variable cv; bool done{false}; EOS_EResult rc{EOS_UnexpectedError}; };
static void EOS_CALL OnUserInfoQuery(const EOS_UserInfo_QueryUserInfoCallbackInfo* info) {
    auto* pst = static_cast<UIWait*>(info->ClientData);
    if (!pst) return;
    std::lock_guard<std::mutex> lk(pst->m);
    pst->rc = info->ResultCode;
    pst->done = true;
    pst->cv.notify_all();
}

// ---------- Core ----------
DLL_EXPORT int eos_initialize_basic(const char* product_name, const char* product_version) {
    LOGI("eos_initialize_basic name=%s ver=%s",
         product_name ? product_name : "(null)",
         product_version ? product_version : "(null)");

#if defined(_WIN32)
    AddVectoredExceptionHandler(1, vectored_handler);
#else
    signal(SIGSEGV, sig_handler);
    signal(SIGABRT, sig_handler);
#endif

    EOS_InitializeOptions o{};
    o.ApiVersion     = EOS_INITIALIZE_API_LATEST;
    o.ProductName    = product_name;
    o.ProductVersion = product_version;
    EOS_EResult rc = EOS_Initialize(&o);

    if (rc == EOS_Success) {
        EOS_Logging_SetCallback(eos_log_cb);
        EOS_Logging_SetLogLevel(EOS_LC_ALL_CATEGORIES, EOS_LOG_VeryVerbose);
        LOGI("EOS_Initialize -> Success");
    } else {
        LOGE("EOS_Initialize -> %d (%s)", (int)rc, r2s(rc));
    }
    return (int)rc;
}

DLL_EXPORT void eos_shutdown(void) {
    LOGI("eos_shutdown");
    EOS_Shutdown();
}

// ---------- Platform ----------
DLL_EXPORT void* eos_platform_create_basic(const char* product_id,
                                           const char* sandbox_id,
                                           const char* deployment_id,
                                           const char* client_id,
                                           const char* client_secret,
                                           const char* encryption_key,
                                           const char* cache_dir,
                                           int is_server,
                                           int tick_budget_ms) {
    LOGI("platform_create pid=%s sbx=%s dep=%s cid=%s is_server=%d tick=%d enc=%s cache=%s",
         product_id ? product_id : "(null)",
         sandbox_id ? sandbox_id : "(null)",
         deployment_id ? deployment_id : "(null)",
         client_id ? "(redacted)" : "(null)",
         is_server, tick_budget_ms,
         encryption_key ? "(set)" : "(null)",
         cache_dir ? cache_dir : "(null)");

    EOS_Platform_ClientCredentials creds{};
    creds.ApiVersion  = EOS_PLATFORM_CLIENTCREDENTIALS_API_LATEST;
    creds.ClientId    = client_id;
    creds.ClientSecret= client_secret;

    EOS_Platform_Options opts{};
    opts.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
    opts.ProductId  = product_id;
    opts.SandboxId  = sandbox_id;
    opts.DeploymentId = deployment_id;
    opts.ClientCredentials = creds;
    opts.EncryptionKey = (encryption_key && *encryption_key) ? encryption_key : nullptr;
    opts.CacheDirectory= (cache_dir && *cache_dir) ? cache_dir : nullptr;
    opts.bIsServer = is_server ? EOS_TRUE : EOS_FALSE;
    opts.TickBudgetInMilliseconds = tick_budget_ms;

    EOS_HPlatform h = EOS_Platform_Create(&opts);
    if (!h) {
        LOGE("EOS_Platform_Create -> NULL");
        return nullptr;
    }

    auto* ps = new PlatformShim();
    ps->h = h;
    LOGI("platform handle=%p", (void*)ps->h);
    return reinterpret_cast<void*>(ps);
}

DLL_EXPORT void eos_platform_release(void* handle) {
    LOGI("platform_release handle=%p", handle);
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps) return;
    delete ps;
}

DLL_EXPORT void eos_platform_tick(void* handle) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps || !ps->h) return;
    EOS_Platform_Tick(ps->h);
}

DLL_EXPORT int eos_platform_start_tick_thread(void* handle, int tick_period_ms) {
    LOGI("platform_start_tick_thread handle=%p period=%d", handle, tick_period_ms);
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps || !ps->h) return static_cast<int>(EOS_InvalidAuth);
    ps->start_tick_thread(tick_period_ms);
    return static_cast<int>(EOS_Success);
}

DLL_EXPORT void eos_platform_stop_tick_thread(void* handle) {
    LOGI("platform_stop_tick_thread handle=%p", handle);
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps) return;
    ps->stop_tick_thread();
}

// ---------- Utilities ----------
DLL_EXPORT const char* eos_result_to_string(int result_code) {
    return r2s(static_cast<EOS_EResult>(result_code));
}

// Debug echo to validate ctypes buffer passing
DLL_EXPORT int eos_debug_echo_to_buf(const char* s, char* out, int32_t* inout_len) {
    std::string msg = s ? s : "NULL";
    EOS_EResult rc = write_out_string(msg, out, inout_len);
    LOGI("echo_to_buf in='%s' rc=%d (%s) need=%d", msg.c_str(), (int)rc, r2s(rc), inout_len ? *inout_len : -1);
    return (int)rc;
}

// ---------- Auth (blocking; owns input storage) ----------
static EOS_EResult do_login_blocking(PlatformShim* ps,
                                     EOS_ELoginCredentialType type,
                                     const char* id,
                                     const char* token,
                                     bool persist,
                                     std::string& out_epic_id) {
    EOS_HAuth h = auth_if(ps);
    if (!h) return EOS_InvalidAuth;

    WaitState st;

    st.id_s    = id    ? id    : std::string();
    st.token_s = token ? token : std::string();

    st.creds.ApiVersion = EOS_AUTH_CREDENTIALS_API_LATEST;
    st.creds.Type  = type;
    st.creds.Id    = st.id_s.empty()    ? nullptr : st.id_s.c_str();
    st.creds.Token = st.token_s.empty() ? nullptr : st.token_s.c_str();

    st.opts.ApiVersion   = EOS_AUTH_LOGIN_API_LATEST;
    st.opts.Credentials  = &st.creds;
    st.opts.ScopeFlags   = EOS_AS_BasicProfile | EOS_AS_FriendsList;
    st.opts.bPersistLogin = persist ? EOS_TRUE : EOS_FALSE;

    LOGI("Auth_Login type=%d id='%s' token='%s' persist=%d",
         (int)type,
         st.creds.Id ? st.creds.Id : "(null)",
         st.creds.Token ? "(set)" : "(null)",
         persist ? 1 : 0);

    EOS_Auth_Login(h, &st.opts, &st, &OnAuthLogin);

    using namespace std::chrono;
    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps && ps->h && !ps->ticking()) EOS_Platform_Tick(ps->h);
        std::this_thread::sleep_for(milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, milliseconds(10));
    }

    LOGI("Auth_Login complete rc=%d (%s) epic='%s'", (int)st.rc, r2s(st.rc), st.epic_id.c_str());
    out_epic_id = std::move(st.epic_id);
    return st.rc;
}

DLL_EXPORT int eos_auth_login_exchange_code(void* handle,
                                            const char* exchange_code,
                                            int persist_in_session,
                                            char* out_epic_account_id,
                                            int32_t* inout_len) {
    LOGI("login_exchange handle=%p persist=%d out=%p lenp=%p",
         handle, persist_in_session, (void*)out_epic_account_id, (void*)inout_len);
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_ExchangeCode, nullptr, exchange_code, persist_in_session != 0, acct);
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
    }
    return (int)rc;
}

DLL_EXPORT int eos_auth_login_password(void* handle,
                                       const char* id,
                                       const char* secret,
                                       int persist_in_session,
                                       char* out_epic_account_id,
                                       int32_t* inout_len) {
    LOGI("login_password handle=%p id=%s persist=%d", handle, id ? id : "(null)", persist_in_session);
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_Password, id, secret, persist_in_session != 0, acct);
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
    }
    return (int)rc;
}

DLL_EXPORT int eos_auth_login_developer(void* handle,
                                        const char* tool_address_and_port,
                                        const char* dev_auth_user_id,
                                        int persist_in_session,
                                        char* out_epic_account_id,
                                        int32_t* inout_len) {
    LOGI("login_developer handle=%p addr=%s user=%s persist=%d out=%p lenp=%p",
         handle,
         tool_address_and_port ? tool_address_and_port : "(null)",
         dev_auth_user_id ? dev_auth_user_id : "(null)",
         persist_in_session, (void*)out_epic_account_id, (void*)inout_len);

    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_Developer, tool_address_and_port, dev_auth_user_id, persist_in_session != 0, acct);
    LOGI("login_developer rc=%d (%s) acct=%s", (int)rc, r2s(rc), acct.c_str());
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
    }
    return (int)rc;
}

DLL_EXPORT int eos_auth_logout(void* handle,
                               const char* epic_account_id_str) {
    LOGI("logout handle=%p eaid=%s", handle, epic_account_id_str ? epic_account_id_str : "(null)");
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return (int)EOS_InvalidAuth;

    LWait st;

    EOS_Auth_LogoutOptions opts{};
    opts.ApiVersion = EOS_AUTH_LOGOUT_API_LATEST;
    opts.LocalUserId = account;

    EOS_Auth_Logout(h, &opts, &st, &OnAuthLogout);

    using namespace std::chrono;
    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps && ps->h && !ps->ticking()) EOS_Platform_Tick(ps->h);
        std::this_thread::sleep_for(milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, milliseconds(10));
    }
    LOGI("logout rc=%d (%s)", (int)st.rc, r2s(st.rc));
    return (int)st.rc;
}

// ---------- Auth tokens ----------
DLL_EXPORT int eos_auth_copy_user_auth_token(void* handle,
                                             const char* epic_account_id_str,
                                             char* out_access_token,
                                             int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return (int)EOS_InvalidAuth;

    EOS_Auth_Token* token = nullptr;
    EOS_Auth_CopyUserAuthTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYUSERAUTHTOKEN_API_LATEST;

    EOS_EResult rc = EOS_Auth_CopyUserAuthToken(h, &opts, account, &token);
    LOGI("copy_user_auth_token rc=%d (%s)", (int)rc, r2s(rc));
    if (rc == EOS_Success && token && token->AccessToken) {
        EOS_EResult wr = write_out_string(token->AccessToken, out_access_token, inout_len);
        EOS_Auth_Token_Release(token);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
        return (int)rc;
    }
    if (token) EOS_Auth_Token_Release(token);
    return (int)rc;
}

DLL_EXPORT int eos_auth_query_id_token(void* handle,
                                       const char* epic_account_id_str) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return (int)EOS_InvalidAuth;

    QWait st;

    EOS_Auth_QueryIdTokenOptions q{};
    q.ApiVersion = EOS_AUTH_QUERYIDTOKEN_API_LATEST;
    q.AccountId  = account;

    EOS_Auth_QueryIdToken(h, &q, &st, &OnQueryIdToken);

    using namespace std::chrono;
    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps && ps->h && !ps->ticking()) EOS_Platform_Tick(ps->h);
        std::this_thread::sleep_for(milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, milliseconds(10));
    }
    LOGI("query_id_token rc=%d (%s)", (int)st.rc, r2s(st.rc));
    return (int)st.rc;
}

DLL_EXPORT int eos_auth_copy_id_token(void* handle,
                                      const char* epic_account_id_str,
                                      char* out_jwt,
                                      int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return (int)EOS_InvalidAuth;

    EOS_Auth_IdToken* idtok = nullptr;
    EOS_Auth_CopyIdTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYIDTOKEN_API_LATEST;
    opts.AccountId  = account;

    EOS_EResult rc = EOS_Auth_CopyIdToken(h, &opts, &idtok);
    LOGI("copy_id_token rc=%d (%s)", (int)rc, r2s(rc));
    if (rc == EOS_Success && idtok && idtok->JsonWebToken) {
        EOS_EResult wr = write_out_string(idtok->JsonWebToken, out_jwt, inout_len);
        EOS_Auth_IdToken_Release(idtok);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
        return (int)rc;
    }
    if (idtok) EOS_Auth_IdToken_Release(idtok);
    return (int)rc;
}

DLL_EXPORT int eos_auth_get_login_status(void* handle,
                                         const char* epic_account_id_str) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return (int)EOS_InvalidAuth;
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return (int)EOS_InvalidAuth;
    int rc = (int)EOS_Auth_GetLoginStatus(h, account);
    LOGI("get_login_status -> %d", rc);
    return rc;
}

// ---------- UserInfo ----------
DLL_EXPORT int eos_userinfo_query(void* handle,
                                  const char* local_epic_account_id,
                                  const char* target_epic_account_id) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HUserInfo ui = userinfo_if(ps);
    if (!ui) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId local  = EOS_EpicAccountId_FromString(local_epic_account_id);
    EOS_EpicAccountId target = EOS_EpicAccountId_FromString(target_epic_account_id);
    if (!local || !target) return (int)EOS_InvalidAuth;

    UIWait st;

    EOS_UserInfo_QueryUserInfoOptions q{};
    q.ApiVersion   = EOS_USERINFO_QUERYUSERINFO_API_LATEST;
    q.LocalUserId  = local;
    q.TargetUserId = target;

    LOGI("userinfo_query local=%s target=%s",
         local_epic_account_id ? local_epic_account_id : "(null)",
         target_epic_account_id ? target_epic_account_id : "(null)");

    EOS_UserInfo_QueryUserInfo(ui, &q, &st, &OnUserInfoQuery);

    using namespace std::chrono;
    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps && ps->h && !ps->ticking()) EOS_Platform_Tick(ps->h);
        std::this_thread::sleep_for(milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, milliseconds(10));
    }
    LOGI("userinfo_query rc=%d (%s)", (int)st.rc, r2s(st.rc));
    return (int)st.rc;
}

DLL_EXPORT int eos_userinfo_copy_display_name(void* handle,
                                              const char* local_epic_account_id,
                                              const char* target_epic_account_id,
                                              char* out_display_name,
                                              int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HUserInfo ui = userinfo_if(ps);
    if (!ui) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId local  = EOS_EpicAccountId_FromString(local_epic_account_id);
    EOS_EpicAccountId target = EOS_EpicAccountId_FromString(target_epic_account_id);
    if (!local || !target) return (int)EOS_InvalidAuth;

    EOS_UserInfo* info = nullptr;
    EOS_UserInfo_CopyUserInfoOptions co{};
    co.ApiVersion   = EOS_USERINFO_COPYUSERINFO_API_LATEST;
    co.LocalUserId  = local;
    co.TargetUserId = target;

    EOS_EResult rc = EOS_UserInfo_CopyUserInfo(ui, &co, &info);
    LOGI("userinfo_copy rc=%d (%s)", (int)rc, r2s(rc));
    if (rc == EOS_Success && info && info->DisplayName) {
        EOS_EResult wr = write_out_string(info->DisplayName, out_display_name, inout_len);
        EOS_UserInfo_Release(info);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
        return (int)rc;
    }
    if (info) EOS_UserInfo_Release(info);
    return (int)rc;
}

DLL_EXPORT int eos_userinfo_copy_country(void* handle,
                                         const char* local_epic_account_id,
                                         const char* target_epic_account_id,
                                         char* out_country,
                                         int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HUserInfo ui = userinfo_if(ps);
    if (!ui) return (int)EOS_InvalidAuth;

    EOS_EpicAccountId local  = EOS_EpicAccountId_FromString(local_epic_account_id);
    EOS_EpicAccountId target = EOS_EpicAccountId_FromString(target_epic_account_id);
    if (!local || !target) return (int)EOS_InvalidAuth;

    EOS_UserInfo* info = nullptr;
    EOS_UserInfo_CopyUserInfoOptions co{};
    co.ApiVersion   = EOS_USERINFO_COPYUSERINFO_API_LATEST;
    co.LocalUserId  = local;
    co.TargetUserId = target;

    EOS_EResult rc = EOS_UserInfo_CopyUserInfo(ui, &co, &info);
    LOGI("userinfo_copy_country rc=%d (%s)", (int)rc, r2s(rc));
    if (rc == EOS_Success && info && info->Country) {
        EOS_EResult wr = write_out_string(info->Country, out_country, inout_len);
        EOS_UserInfo_Release(info);
        if (wr != EOS_Success) { LOGE("write_out_string -> %d (%s)", (int)wr, r2s(wr)); return (int)wr; }
        return (int)rc;
    }
    if (info) EOS_UserInfo_Release(info);
    return (int)rc;
}
