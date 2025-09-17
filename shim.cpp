// eos_shim.cpp
// Thin native shim exporting a C ABI over a minimal subset of Epic Online Services (EOS).
// Implements: initialize/shutdown, platform create/release/tick(+optional tick thread),
// blocking Auth login (exchange/password/developer), logout, result-to-string,
// copy user auth token, query/copy ID token, login status.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <memory>

#include "eos_sdk.h"
#include "eos_platform.h"
#include "eos_auth.h"

#if defined(_WIN32)
  #define DLL_EXPORT extern "C" __declspec(dllexport)
#else
  #define DLL_EXPORT extern "C" __attribute__((visibility("default")))
#endif

struct LoginCredentialHold {
    std::string id;
    std::string token;
    EOS_Auth_Credentials creds{};
    EOS_Auth_LoginOptions opts{};

    LoginCredentialHold(EOS_ELoginCredentialType type,
                        const char* id_in,
                        const char* token_in,
                        bool persist) {
        id = id_in ? id_in : "";
        token = token_in ? token_in : "";

        creds.ApiVersion = EOS_AUTH_CREDENTIALS_API_LATEST;
        creds.Type = type;
        creds.Id = id.empty() ? nullptr : id.c_str();
        creds.Token = token.empty() ? nullptr : token.c_str();

        opts.ApiVersion = EOS_AUTH_LOGIN_API_LATEST;
        opts.Credentials = &creds;
        opts.ScopeFlags = EOS_AS_BasicProfile | EOS_AS_FriendsList;
        opts.bPersistLogin = persist ? EOS_TRUE : EOS_FALSE;
    }
};

struct PlatformShim {
    EOS_HPlatform h{nullptr};
    std::atomic<bool> run{false};
    std::thread tick_thread;
    int tick_ms{16};
    std::mutex tick_mu;

    std::mutex login_mu;
    std::unordered_map<std::string, std::shared_ptr<LoginCredentialHold>> active_logins;

    // retain copies of input strings so EOS can reference them safely
    std::string s_product_id, s_sandbox_id, s_deployment_id;
    std::string s_client_id, s_client_secret;
    std::string s_encryption_key, s_cache_dir;
    ~PlatformShim() {
        stop_tick_thread();
        if (h) {
            EOS_Platform_Release(h);
            h = nullptr;
        }
    }
    void tick_once() {
        std::lock_guard<std::mutex> lk(tick_mu);
        if (h) EOS_Platform_Tick(h);
    }
    void start_tick_thread(int period_ms) {
        if (run.load()) return;
        tick_ms = period_ms > 0 ? period_ms : 16;
        run.store(true);
        tick_thread = std::thread([this]{
            while (run.load()) {
                tick_once();
                std::this_thread::sleep_for(std::chrono::milliseconds(tick_ms));
            }
        });
    }
    void stop_tick_thread() {
        if (!run.load()) return;
        run.store(false);
        if (tick_thread.joinable()) tick_thread.join();
    }

    void remember_login(const std::string& epic_id,
                        const std::shared_ptr<LoginCredentialHold>& hold) {
        if (epic_id.empty() || !hold) return;
        std::lock_guard<std::mutex> lk(login_mu);
        active_logins[epic_id] = hold;
    }

    void forget_login(const std::string& epic_id) {
        if (epic_id.empty()) return;
        std::lock_guard<std::mutex> lk(login_mu);
        active_logins.erase(epic_id);
    }
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

    std::shared_ptr<LoginCredentialHold> cred_hold;
};

static EOS_HAuth auth_if(PlatformShim* ps) {
    return ps && ps->h ? EOS_Platform_GetAuthInterface(ps->h) : nullptr;
}

// Core
DLL_EXPORT int eos_initialize_basic(const char* product_name, const char* product_version) {
    EOS_InitializeOptions o{};
    o.ApiVersion     = EOS_INITIALIZE_API_LATEST;
    o.ProductName    = product_name;
    o.ProductVersion = product_version;
    EOS_EResult rc = EOS_Initialize(&o);
    return static_cast<int>(rc);
}

DLL_EXPORT void eos_shutdown(void) {
    EOS_Shutdown();
}

// Platform
DLL_EXPORT void* eos_platform_create_basic(const char* product_id,
                                           const char* sandbox_id,
                                           const char* deployment_id,
                                           const char* client_id,
                                           const char* client_secret,
                                           const char* encryption_key,
                                           const char* cache_dir,
                                           int is_server,
                                           int tick_budget_ms) {
    auto* ps = new PlatformShim();

    // take ownership of all inputs so EOS can safely reference them
    ps->s_product_id    = product_id    ? product_id    : "";
    ps->s_sandbox_id    = sandbox_id    ? sandbox_id    : "";
    ps->s_deployment_id = deployment_id ? deployment_id : "";
    ps->s_client_id     = client_id     ? client_id     : "";
    ps->s_client_secret = client_secret ? client_secret : "";
    ps->s_encryption_key= encryption_key? encryption_key: "";
    ps->s_cache_dir     = cache_dir     ? cache_dir     : "";

    EOS_Platform_ClientCredentials creds{};
    creds.ApiVersion  = EOS_PLATFORM_CLIENTCREDENTIALS_API_LATEST;
    creds.ClientId    = ps->s_client_id.empty() ? nullptr : ps->s_client_id.c_str();
    creds.ClientSecret= ps->s_client_secret.empty() ? nullptr : ps->s_client_secret.c_str();

    EOS_Platform_Options opts{};
    opts.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
    opts.ProductId  = ps->s_product_id.empty() ? nullptr : ps->s_product_id.c_str();
    opts.SandboxId  = ps->s_sandbox_id.empty() ? nullptr : ps->s_sandbox_id.c_str();
    opts.DeploymentId = ps->s_deployment_id.empty() ? nullptr : ps->s_deployment_id.c_str();
    opts.ClientCredentials = creds;
    opts.EncryptionKey = ps->s_encryption_key.empty() ? nullptr : ps->s_encryption_key.c_str();
    opts.CacheDirectory= ps->s_cache_dir.empty() ? nullptr : ps->s_cache_dir.c_str();
    opts.bIsServer = is_server ? EOS_TRUE : EOS_FALSE;
    opts.TickBudgetInMilliseconds = tick_budget_ms;

    ps->h = EOS_Platform_Create(&opts);
    if (!ps->h) {
        delete ps;
        return nullptr;
    }
    return reinterpret_cast<void*>(ps);
}

DLL_EXPORT void eos_platform_release(void* handle) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps) return;
    delete ps;
}

DLL_EXPORT void eos_platform_tick(void* handle) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps) return;
    ps->tick_once();
}

DLL_EXPORT int eos_platform_start_tick_thread(void* handle, int tick_period_ms) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps || !ps->h) return static_cast<int>(EOS_InvalidAuth);
    ps->start_tick_thread(tick_period_ms);
    return static_cast<int>(EOS_Success);
}

DLL_EXPORT void eos_platform_stop_tick_thread(void* handle) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    if (!ps) return;
    ps->stop_tick_thread();
}

// Utilities
DLL_EXPORT const char* eos_result_to_string(int result_code) {
    return r2s(static_cast<EOS_EResult>(result_code));
}

// Auth: common blocking login
static EOS_EResult do_login_blocking(PlatformShim* ps,
                                     EOS_ELoginCredentialType type,
                                     const char* id,
                                     const char* token,
                                     bool persist,
                                     std::string& out_epic_id) {
    EOS_HAuth h = auth_if(ps);
    if (!h) return EOS_InvalidAuth;

    WaitState st;
    st.cred_hold = std::make_shared<LoginCredentialHold>(type, id, token, persist);

    EOS_Auth_LoginOptions* opts = st.cred_hold ? &st.cred_hold->opts : nullptr;
    if (!opts) {
        out_epic_id.clear();
        return EOS_OutOfMemory;
    }

    EOS_Auth_Login(h, opts, &st,
        [](const EOS_Auth_LoginCallbackInfo* info){
            auto* pst = static_cast<WaitState*>(info->ClientData);
            std::lock_guard<std::mutex> lk(pst->m);
            pst->rc = info->ResultCode;
            pst->epic_id = epic_id_to_str(info->LocalUserId);
            pst->done = true;
            pst->cv.notify_all();
        });

    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps) ps->tick_once();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, std::chrono::milliseconds(10));
    }

    std::string epic_id = std::move(st.epic_id);
    if (st.rc == EOS_Success && ps) {
        ps->remember_login(epic_id, st.cred_hold);
    }
    out_epic_id = std::move(epic_id);
    return st.rc;
}

// Auth: logins
DLL_EXPORT int eos_auth_login_exchange_code(void* handle,
                                            const char* exchange_code,
                                            int persist_in_session,
                                            char* out_epic_account_id,
                                            int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_ExchangeCode, nullptr, exchange_code, persist_in_session != 0, acct);
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) return static_cast<int>(wr);
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_auth_login_password(void* handle,
                                       const char* id,
                                       const char* secret,
                                       int persist_in_session,
                                       char* out_epic_account_id,
                                       int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_Password, id, secret, persist_in_session != 0, acct);
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) return static_cast<int>(wr);
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_auth_login_developer(void* handle,
                                        const char* tool_address_and_port,
                                        const char* dev_auth_user_id,
                                        int persist_in_session,
                                        char* out_epic_account_id,
                                        int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    std::string acct;
    EOS_EResult rc = do_login_blocking(ps, EOS_LCT_Developer, tool_address_and_port, dev_auth_user_id, persist_in_session != 0, acct);
    if (rc == EOS_Success) {
        EOS_EResult wr = write_out_string(acct, out_epic_account_id, inout_len);
        if (wr != EOS_Success) return static_cast<int>(wr);
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_auth_logout(void* handle,
                               const char* epic_account_id_str) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return static_cast<int>(EOS_InvalidAuth);

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return static_cast<int>(EOS_InvalidAuth);
    std::string acct_str = epic_account_id_str ? epic_account_id_str : "";

    WaitState st;
    EOS_Auth_LogoutOptions opts{};
    opts.ApiVersion = EOS_AUTH_LOGOUT_API_LATEST;
    opts.LocalUserId = account;

    EOS_Auth_Logout(h, &opts, &st,
        [](const EOS_Auth_LogoutCallbackInfo* info){
            auto* pst = static_cast<WaitState*>(info->ClientData);
            std::lock_guard<std::mutex> lk(pst->m);
            pst->rc = info->ResultCode;
            pst->done = true;
            pst->cv.notify_all();
        });

    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps) ps->tick_once();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, std::chrono::milliseconds(10));
    }

    if (st.rc == EOS_Success && ps) {
        ps->forget_login(acct_str);
    }
    return static_cast<int>(st.rc);
}

// Auth tokens
DLL_EXPORT int eos_auth_copy_user_auth_token(void* handle,
                                             const char* epic_account_id_str,
                                             char* out_access_token,
                                             int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return static_cast<int>(EOS_InvalidAuth);

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return static_cast<int>(EOS_InvalidAuth);

    EOS_Auth_Token* token = nullptr;
    EOS_Auth_CopyUserAuthTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYUSERAUTHTOKEN_API_LATEST;

    EOS_EResult rc = EOS_Auth_CopyUserAuthToken(h, &opts, account, &token);
    if (rc == EOS_Success && token && token->AccessToken) {
        EOS_EResult wr = write_out_string(token->AccessToken, out_access_token, inout_len);
        EOS_Auth_Token_Release(token);
        if (wr != EOS_Success) return static_cast<int>(wr);
        return static_cast<int>(rc);
    }
    if (token) EOS_Auth_Token_Release(token);
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_auth_query_id_token(void* handle,
                                       const char* epic_account_id_str) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return static_cast<int>(EOS_InvalidAuth);

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return static_cast<int>(EOS_InvalidAuth);

    WaitState st;
    EOS_Auth_QueryIdTokenOptions q{};
    q.ApiVersion = EOS_AUTH_QUERYIDTOKEN_API_LATEST;
    q.AccountId  = account;

    EOS_Auth_QueryIdToken(h, &q, &st, [](const EOS_Auth_QueryIdTokenCallbackInfo* info){
        auto* pst = static_cast<WaitState*>(info->ClientData);
        std::lock_guard<std::mutex> lk(pst->m);
        pst->rc = info->ResultCode;
        pst->done = true;
        pst->cv.notify_all();
    });

    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps) ps->tick_once();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) st.cv.wait_for(lk, std::chrono::milliseconds(10));
    }
    return static_cast<int>(st.rc);
}

DLL_EXPORT int eos_auth_copy_id_token(void* handle,
                                      const char* epic_account_id_str,
                                      char* out_jwt,
                                      int32_t* inout_len) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return static_cast<int>(EOS_InvalidAuth);

    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return static_cast<int>(EOS_InvalidAuth);

    EOS_Auth_IdToken* idtok = nullptr;
    EOS_Auth_CopyIdTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYIDTOKEN_API_LATEST;
    opts.AccountId  = account;

    EOS_EResult rc = EOS_Auth_CopyIdToken(h, &opts, &idtok);
    if (rc == EOS_Success && idtok && idtok->JsonWebToken) {
        EOS_EResult wr = write_out_string(idtok->JsonWebToken, out_jwt, inout_len);
        EOS_Auth_IdToken_Release(idtok);
        if (wr != EOS_Success) return static_cast<int>(wr);
        return static_cast<int>(rc);
    }
    if (idtok) EOS_Auth_IdToken_Release(idtok);
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_auth_get_login_status(void* handle,
                                         const char* epic_account_id_str) {
    auto* ps = reinterpret_cast<PlatformShim*>(handle);
    EOS_HAuth h = auth_if(ps);
    if (!h) return static_cast<int>(EOS_InvalidAuth);
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_account_id_str);
    if (!account) return static_cast<int>(EOS_InvalidAuth);
    return static_cast<int>(EOS_Auth_GetLoginStatus(h, account));
}
