// shim_bootstrap.cpp
// High-level EOS shim that retains global platform state so callers do not
// have to shuttle opaque handles between Python and C++.
// Provides bootstrap/shutdown helpers and wraps common auth flows while
// safely storing any buffers that EOS needs to keep referencing.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "eos_auth.h"
#include "eos_platform.h"
#include "eos_sdk.h"

#if defined(_WIN32)
  #define DLL_EXPORT extern "C" __declspec(dllexport)
#else
  #define DLL_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace {

struct LoginCredentialHold {
    std::string id;
    std::string token;
    EOS_Auth_Credentials creds{};
    EOS_Auth_LoginOptions opts{};

    LoginCredentialHold(EOS_ELoginCredentialType type,
                        const char* id_in,
                        const char* token_in,
                        bool persist) {
        if (id_in) id = id_in;
        if (token_in) token = token_in;

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
        if (h) {
            EOS_Platform_Tick(h);
        }
    }

    void start_tick_thread(int period_ms) {
        if (run.load()) {
            return;
        }
        tick_ms = period_ms > 0 ? period_ms : 16;
        run.store(true);
        tick_thread = std::thread([this] {
            while (run.load()) {
                tick_once();
                std::this_thread::sleep_for(std::chrono::milliseconds(tick_ms));
            }
        });
    }

    void stop_tick_thread() {
        if (!run.load()) {
            return;
        }
        run.store(false);
        if (tick_thread.joinable()) {
            tick_thread.join();
        }
    }

    void remember_login(const std::string& epic_id,
                        const std::shared_ptr<LoginCredentialHold>& hold) {
        if (epic_id.empty() || !hold) {
            return;
        }
        std::lock_guard<std::mutex> lk(login_mu);
        active_logins[epic_id] = hold;
    }

    void forget_login(const std::string& epic_id) {
        if (epic_id.empty()) {
            return;
        }
        std::lock_guard<std::mutex> lk(login_mu);
        active_logins.erase(epic_id);
    }
};

struct WaitState {
    std::mutex m;
    std::condition_variable cv;
    bool done{false};
    EOS_EResult rc{EOS_UnexpectedError};
    std::string epic_id;
    std::shared_ptr<LoginCredentialHold> cred_hold;
};

struct GlobalState {
    std::mutex mu;
    std::shared_ptr<PlatformShim> platform;
    bool initialized{false};

    std::string init_product_name;
    std::string init_product_version;

    std::string dev_tool_address;
    std::string dev_auth_user_id;
    bool dev_persist{true};

    std::string last_epic_account_id;
};

GlobalState g_state;

static inline const char* r2s(EOS_EResult r) {
    const char* s = EOS_EResult_ToString(r);
    return s ? s : "EOS_Unknown";
}

static EOS_HAuth auth_if(PlatformShim* ps) {
    return ps && ps->h ? EOS_Platform_GetAuthInterface(ps->h) : nullptr;
}

static std::string epic_id_to_str(EOS_EpicAccountId id) {
    if (!id) {
        return {};
    }
    char buf[EOS_EPICACCOUNTID_MAX_LENGTH + 1] = {};
    int32_t n = static_cast<int32_t>(sizeof(buf));
    EOS_EResult rc = EOS_EpicAccountId_ToString(id, buf, &n);
    if (rc != EOS_Success) {
        return {};
    }
    return std::string(buf);
}

static EOS_EResult write_out_string(const std::string& s, char* out, int32_t* inout_len) {
    if (!inout_len) {
        return EOS_Success;
    }
    int32_t needed = static_cast<int32_t>(s.size()) + 1;
    if (!out || *inout_len < needed) {
        *inout_len = needed;
        return EOS_LimitExceeded;
    }
    std::memcpy(out, s.c_str(), static_cast<size_t>(needed));
    *inout_len = needed;
    return EOS_Success;
}

static EOS_EResult do_login_blocking(PlatformShim* ps,
                                     EOS_ELoginCredentialType type,
                                     const char* id,
                                     const char* token,
                                     bool persist,
                                     std::string& out_epic_id) {
    EOS_HAuth h = auth_if(ps);
    if (!h) {
        return EOS_InvalidAuth;
    }

    WaitState st;
    st.cred_hold = std::make_shared<LoginCredentialHold>(type, id, token, persist);
    EOS_Auth_LoginOptions* opts = st.cred_hold ? &st.cred_hold->opts : nullptr;
    if (!opts) {
        out_epic_id.clear();
        return EOS_OutOfMemory;
    }

    EOS_Auth_Login(h, opts, &st, [](const EOS_Auth_LoginCallbackInfo* info) {
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
        if (ps) {
            ps->tick_once();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) {
            st.cv.wait_for(lk, std::chrono::milliseconds(10));
        }
    }

    std::string epic_id = std::move(st.epic_id);
    if (st.rc == EOS_Success && ps) {
        ps->remember_login(epic_id, st.cred_hold);
    }
    out_epic_id = std::move(epic_id);
    return st.rc;
}

static std::shared_ptr<PlatformShim> get_platform() {
    std::lock_guard<std::mutex> lk(g_state.mu);
    return g_state.platform;
}

static bool resolve_account_id(const char* maybe_id, std::string& out_id) {
    if (maybe_id && maybe_id[0]) {
        out_id = maybe_id;
        return true;
    }
    std::lock_guard<std::mutex> lk(g_state.mu);
    if (g_state.last_epic_account_id.empty()) {
        return false;
    }
    out_id = g_state.last_epic_account_id;
    return true;
}

static void set_last_account_id(const std::string& id) {
    std::lock_guard<std::mutex> lk(g_state.mu);
    g_state.last_epic_account_id = id;
}

static EOS_EResult copy_user_auth_token(PlatformShim* ps,
                                        const std::string& epic_id,
                                        std::string& out_token) {
    EOS_HAuth h = auth_if(ps);
    if (!h) {
        return EOS_InvalidAuth;
    }
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_id.c_str());
    if (!account) {
        return EOS_InvalidAuth;
    }
    EOS_Auth_Token* token = nullptr;
    EOS_Auth_CopyUserAuthTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYUSERAUTHTOKEN_API_LATEST;

    EOS_EResult rc = EOS_Auth_CopyUserAuthToken(h, &opts, account, &token);
    if (rc == EOS_Success && token && token->AccessToken) {
        out_token = token->AccessToken;
    }
    if (token) {
        EOS_Auth_Token_Release(token);
    }
    return rc;
}

static EOS_EResult copy_id_token(PlatformShim* ps,
                                 const std::string& epic_id,
                                 std::string& out_jwt) {
    EOS_HAuth h = auth_if(ps);
    if (!h) {
        return EOS_InvalidAuth;
    }
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_id.c_str());
    if (!account) {
        return EOS_InvalidAuth;
    }
    EOS_Auth_IdToken* token = nullptr;
    EOS_Auth_CopyIdTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_COPYIDTOKEN_API_LATEST;
    opts.AccountId = account;

    EOS_EResult rc = EOS_Auth_CopyIdToken(h, &opts, &token);
    if (rc == EOS_Success && token && token->JsonWebToken) {
        out_jwt = token->JsonWebToken;
    }
    if (token) {
        EOS_Auth_IdToken_Release(token);
    }
    return rc;
}

static EOS_EResult logout_account(PlatformShim* ps, const std::string& epic_id) {
    EOS_HAuth h = auth_if(ps);
    if (!h) {
        return EOS_InvalidAuth;
    }
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(epic_id.c_str());
    if (!account) {
        return EOS_InvalidAuth;
    }

    WaitState st;
    EOS_Auth_LogoutOptions opts{};
    opts.ApiVersion = EOS_AUTH_LOGOUT_API_LATEST;
    opts.LocalUserId = account;

    EOS_Auth_Logout(h, &opts, &st, [](const EOS_Auth_LogoutCallbackInfo* info) {
        auto* pst = static_cast<WaitState*>(info->ClientData);
        std::lock_guard<std::mutex> lk(pst->m);
        pst->rc = info->ResultCode;
        pst->done = true;
        pst->cv.notify_all();
    });

    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps) {
            ps->tick_once();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) {
            st.cv.wait_for(lk, std::chrono::milliseconds(10));
        }
    }

    if (st.rc == EOS_Success && ps) {
        ps->forget_login(epic_id);
    }
    return st.rc;
}

} // namespace

DLL_EXPORT int eos_hl_bootstrap(const char* product_name,
                                const char* product_version,
                                const char* product_id,
                                const char* sandbox_id,
                                const char* deployment_id,
                                const char* client_id,
                                const char* client_secret,
                                const char* encryption_key,
                                const char* cache_dir,
                                const char* tool_address_and_port,
                                const char* dev_auth_user_id,
                                int persist_login,
                                int is_server,
                                int tick_budget_ms,
                                int tick_period_ms) {
    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        if (g_state.platform) {
            return static_cast<int>(EOS_AlreadyConfigured);
        }
        g_state.init_product_name = product_name ? product_name : "";
        g_state.init_product_version = product_version ? product_version : "";
        g_state.dev_tool_address = tool_address_and_port ? tool_address_and_port : "";
        g_state.dev_auth_user_id = dev_auth_user_id ? dev_auth_user_id : "";
        g_state.dev_persist = persist_login != 0;
        g_state.last_epic_account_id.clear();
    }

    EOS_InitializeOptions init_opts{};
    init_opts.ApiVersion = EOS_INITIALIZE_API_LATEST;
    init_opts.ProductName = g_state.init_product_name.empty() ? nullptr : g_state.init_product_name.c_str();
    init_opts.ProductVersion = g_state.init_product_version.empty() ? nullptr : g_state.init_product_version.c_str();

    EOS_EResult init_rc = EOS_Initialize(&init_opts);
    if (init_rc != EOS_Success) {
        std::lock_guard<std::mutex> lk(g_state.mu);
        g_state.init_product_name.clear();
        g_state.init_product_version.clear();
        return static_cast<int>(init_rc);
    }

    auto ps = std::make_shared<PlatformShim>();
    ps->s_product_id = product_id ? product_id : "";
    ps->s_sandbox_id = sandbox_id ? sandbox_id : "";
    ps->s_deployment_id = deployment_id ? deployment_id : "";
    ps->s_client_id = client_id ? client_id : "";
    ps->s_client_secret = client_secret ? client_secret : "";
    ps->s_encryption_key = encryption_key ? encryption_key : "";
    ps->s_cache_dir = cache_dir ? cache_dir : "";

    EOS_Platform_ClientCredentials creds{};
    creds.ApiVersion = EOS_PLATFORM_CLIENTCREDENTIALS_API_LATEST;
    creds.ClientId = ps->s_client_id.empty() ? nullptr : ps->s_client_id.c_str();
    creds.ClientSecret = ps->s_client_secret.empty() ? nullptr : ps->s_client_secret.c_str();

    EOS_Platform_Options plat_opts{};
    plat_opts.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
    plat_opts.ProductId = ps->s_product_id.empty() ? nullptr : ps->s_product_id.c_str();
    plat_opts.SandboxId = ps->s_sandbox_id.empty() ? nullptr : ps->s_sandbox_id.c_str();
    plat_opts.DeploymentId = ps->s_deployment_id.empty() ? nullptr : ps->s_deployment_id.c_str();
    plat_opts.ClientCredentials = creds;
    plat_opts.EncryptionKey = ps->s_encryption_key.empty() ? nullptr : ps->s_encryption_key.c_str();
    plat_opts.CacheDirectory = ps->s_cache_dir.empty() ? nullptr : ps->s_cache_dir.c_str();
    plat_opts.bIsServer = is_server ? EOS_TRUE : EOS_FALSE;
    plat_opts.TickBudgetInMilliseconds = tick_budget_ms;

    ps->h = EOS_Platform_Create(&plat_opts);
    if (!ps->h) {
        EOS_Shutdown();
        std::lock_guard<std::mutex> lk(g_state.mu);
        g_state.init_product_name.clear();
        g_state.init_product_version.clear();
        g_state.dev_tool_address.clear();
        g_state.dev_auth_user_id.clear();
        return static_cast<int>(EOS_UnexpectedError);
    }

    if (tick_period_ms > 0) {
        ps->start_tick_thread(tick_period_ms);
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        g_state.platform = ps;
        g_state.initialized = true;
    }
    return static_cast<int>(EOS_Success);
}

DLL_EXPORT void eos_hl_shutdown() {
    std::shared_ptr<PlatformShim> ps;
    bool do_shutdown = false;
    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        ps = std::move(g_state.platform);
        do_shutdown = g_state.initialized;
        g_state.initialized = false;
        g_state.init_product_name.clear();
        g_state.init_product_version.clear();
        g_state.dev_tool_address.clear();
        g_state.dev_auth_user_id.clear();
        g_state.last_epic_account_id.clear();
    }
    ps.reset();
    if (do_shutdown) {
        EOS_Shutdown();
    }
}

DLL_EXPORT void eos_hl_tick() {
    auto ps = get_platform();
    if (ps) {
        ps->tick_once();
    }
}

DLL_EXPORT int eos_hl_start_tick_thread(int period_ms) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    ps->start_tick_thread(period_ms);
    return static_cast<int>(EOS_Success);
}

DLL_EXPORT void eos_hl_stop_tick_thread() {
    auto ps = get_platform();
    if (ps) {
        ps->stop_tick_thread();
    }
}

DLL_EXPORT int eos_hl_get_last_epic_account_id(char* out_epic_account_id,
                                               int32_t* inout_len) {
    std::string acct;
    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        acct = g_state.last_epic_account_id;
    }
    if (acct.empty()) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    return static_cast<int>(write_out_string(acct, out_epic_account_id, inout_len));
}

DLL_EXPORT int eos_hl_login_developer(char* out_access_token,
                                      int32_t* inout_len) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }

    std::string tool_addr;
    std::string user_id;
    bool persist = true;
    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        tool_addr = g_state.dev_tool_address;
        user_id = g_state.dev_auth_user_id;
        persist = g_state.dev_persist;
    }

    std::string epic_id;
    EOS_EResult rc = do_login_blocking(ps.get(), EOS_LCT_Developer,
                                       tool_addr.empty() ? nullptr : tool_addr.c_str(),
                                       user_id.empty() ? nullptr : user_id.c_str(),
                                       persist,
                                       epic_id);
    if (rc != EOS_Success) {
        return static_cast<int>(rc);
    }

    set_last_account_id(epic_id);

    std::string token;
    rc = copy_user_auth_token(ps.get(), epic_id, token);
    if (rc != EOS_Success) {
        return static_cast<int>(rc);
    }
    return static_cast<int>(write_out_string(token, out_access_token, inout_len));
}

DLL_EXPORT int eos_hl_login_exchange_code(const char* exchange_code,
                                          int persist_in_session,
                                          char* out_epic_account_id,
                                          int32_t* inout_len) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string epic_id;
    EOS_EResult rc = do_login_blocking(ps.get(), EOS_LCT_ExchangeCode,
                                       nullptr,
                                       exchange_code,
                                       persist_in_session != 0,
                                       epic_id);
    if (rc == EOS_Success) {
        set_last_account_id(epic_id);
        EOS_EResult wr = write_out_string(epic_id, out_epic_account_id, inout_len);
        if (wr != EOS_Success) {
            return static_cast<int>(wr);
        }
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_hl_login_password(const char* id,
                                     const char* secret,
                                     int persist_in_session,
                                     char* out_epic_account_id,
                                     int32_t* inout_len) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string epic_id;
    EOS_EResult rc = do_login_blocking(ps.get(), EOS_LCT_Password,
                                       id,
                                       secret,
                                       persist_in_session != 0,
                                       epic_id);
    if (rc == EOS_Success) {
        set_last_account_id(epic_id);
        EOS_EResult wr = write_out_string(epic_id, out_epic_account_id, inout_len);
        if (wr != EOS_Success) {
            return static_cast<int>(wr);
        }
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_hl_logout(const char* epic_account_id) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string acct;
    if (!resolve_account_id(epic_account_id, acct)) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    EOS_EResult rc = logout_account(ps.get(), acct);
    if (rc == EOS_Success) {
        std::lock_guard<std::mutex> lk(g_state.mu);
        if (g_state.last_epic_account_id == acct) {
            g_state.last_epic_account_id.clear();
        }
    }
    return static_cast<int>(rc);
}

DLL_EXPORT int eos_hl_copy_user_auth_token(const char* epic_account_id,
                                           char* out_access_token,
                                           int32_t* inout_len) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string acct;
    if (!resolve_account_id(epic_account_id, acct)) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string token;
    EOS_EResult rc = copy_user_auth_token(ps.get(), acct, token);
    if (rc != EOS_Success) {
        return static_cast<int>(rc);
    }
    return static_cast<int>(write_out_string(token, out_access_token, inout_len));
}

DLL_EXPORT int eos_hl_query_id_token(const char* epic_account_id) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string acct;
    if (!resolve_account_id(epic_account_id, acct)) {
        return static_cast<int>(EOS_InvalidAuth);
    }

    EOS_HAuth h = auth_if(ps.get());
    if (!h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(acct.c_str());
    if (!account) {
        return static_cast<int>(EOS_InvalidAuth);
    }

    WaitState st;
    EOS_Auth_QueryIdTokenOptions opts{};
    opts.ApiVersion = EOS_AUTH_QUERYIDTOKEN_API_LATEST;
    opts.AccountId = account;

    EOS_Auth_QueryIdToken(h, &opts, &st, [](const EOS_Auth_QueryIdTokenCallbackInfo* info) {
        auto* pst = static_cast<WaitState*>(info->ClientData);
        std::lock_guard<std::mutex> lk(pst->m);
        pst->rc = info->ResultCode;
        pst->done = true;
        pst->cv.notify_all();
    });

    std::unique_lock<std::mutex> lk(st.m);
    while (!st.done) {
        lk.unlock();
        if (ps) {
            ps->tick_once();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        lk.lock();
        if (!st.done) {
            st.cv.wait_for(lk, std::chrono::milliseconds(10));
        }
    }
    return static_cast<int>(st.rc);
}

DLL_EXPORT int eos_hl_copy_id_token(const char* epic_account_id,
                                    char* out_jwt,
                                    int32_t* inout_len) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string acct;
    if (!resolve_account_id(epic_account_id, acct)) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string jwt;
    EOS_EResult rc = copy_id_token(ps.get(), acct, jwt);
    if (rc != EOS_Success) {
        return static_cast<int>(rc);
    }
    return static_cast<int>(write_out_string(jwt, out_jwt, inout_len));
}

DLL_EXPORT int eos_hl_get_login_status(const char* epic_account_id) {
    auto ps = get_platform();
    if (!ps || !ps->h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    std::string acct;
    if (!resolve_account_id(epic_account_id, acct)) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    EOS_HAuth h = auth_if(ps.get());
    if (!h) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    EOS_EpicAccountId account = EOS_EpicAccountId_FromString(acct.c_str());
    if (!account) {
        return static_cast<int>(EOS_InvalidAuth);
    }
    return static_cast<int>(EOS_Auth_GetLoginStatus(h, account));
}

DLL_EXPORT const char* eos_hl_result_to_string(int result_code) {
    return r2s(static_cast<EOS_EResult>(result_code));
}
