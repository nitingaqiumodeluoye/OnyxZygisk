#include "module.hpp"

#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cerrno>
#include <poll.h>
#include <string>
#include <utility>
#include <vector>

#include <lsplt.hpp>

#include "daemon.hpp"
#include "dl.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "module_loader.hpp"
#include "zygisk.hpp"

using namespace std;

ZygiskModule::ZygiskModule(int id, std::string name, void *handle, void *entry, bool custom)
    : id(id),
      name(std::move(name)),
      handle(handle),
      custom(custom),
      entry{entry},
      api{},
      mod{nullptr} {
    // Make sure all pointers are null
    memset(&api, 0, sizeof(api));
    api.base.impl = this;
    api.base.registerModule = &ZygiskModule::RegisterModuleImpl;
}

bool ZygiskModule::RegisterModuleImpl(ApiTable *api, long *module) {
    if (api == nullptr || module == nullptr) return false;

    long api_version = *module;
    // Unsupported version
    if (api_version > ZYGISK_API_VERSION) return false;

    // Set the actual module_abi*
    api->base.impl->mod = {module};

    // Fill in API accordingly with module API version
    if (api_version >= 1) {
        api->v1.hookJniNativeMethods = hookJniNativeMethods;
        api->v1.pltHookRegister = [](auto a, auto b, auto c, auto d) {
            if (g_ctx) g_ctx->plt_hook_register(a, b, c, d);
        };
        api->v1.pltHookExclude = [](auto a, auto b) {
            if (g_ctx) g_ctx->plt_hook_exclude(a, b);
        };
        api->v1.pltHookCommit = []() { return g_ctx && g_ctx->plt_hook_commit(); };
        api->v1.connectCompanion = [](ZygiskModule *m) { return m->connectCompanion(); };
        api->v1.setOption = [](ZygiskModule *m, auto opt) { m->setOption(opt); };
    }
    if (api_version >= 2) {
        api->v2.getModuleDir = [](ZygiskModule *m) { return m->getModuleDir(); };
        api->v2.getFlags = [](auto) { return ZygiskModule::getFlags(); };
    }
    if (api_version >= 4) {
        api->v4.pltHookCommit = []() { return lsplt::CommitHook(g_hook->cached_map_infos); };
        api->v4.pltHookRegister = [](dev_t dev, ino_t inode, const char *symbol, void *fn,
                                     void **backup) {
            if (dev == 0 || inode == 0 || symbol == nullptr || fn == nullptr) return;
            lsplt::RegisterHook(dev, inode, symbol, fn, backup);
        };
        api->v4.exemptFd = [](int fd) { return g_ctx && g_ctx->exempt_fd(fd); };
    }

    return true;
}

bool ZygiskModule::valid() const {
    if (mod.api_version == nullptr) return false;
    switch (*mod.api_version) {
    case 5:
    case 4:
    case 3:
    case 2:
    case 1:
        return mod.v1->impl && mod.v1->preAppSpecialize && mod.v1->postAppSpecialize &&
               mod.v1->preServerSpecialize && mod.v1->postServerSpecialize;
    default:
        return false;
    }
}

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::connectCompanion() const { return zygiskd::ConnectCompanion(id); }

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::getModuleDir() const { return zygiskd::GetModuleDir(id, name.c_str()); }

void ZygiskModule::setOption(zygisk::Option opt) {
    if (g_ctx == nullptr) return;
    switch (opt) {
    case zygisk::FORCE_DENYLIST_UNMOUNT:
        g_ctx->flags |= DO_REVERT_UNMOUNT;
        break;
    case zygisk::DLCLOSE_MODULE_LIBRARY:
        unload = true;
        break;
    }
}

uint32_t ZygiskModule::getFlags() { return g_ctx ? (g_ctx->info_flags & ~PRIVATE_MASK) : 0; }

bool ZygiskModule::tryUnload() const { return unload && UnloadModule(handle, custom); }

// -----------------------------------------------------------------

#define call_app(method)                                                                           \
    switch (*mod.api_version) {                                                                    \
    case 1:                                                                                        \
    case 2: {                                                                                      \
        AppSpecializeArgs_v1 a(args);                                                              \
        mod.v1->method(mod.v1->impl, &a);                                                          \
        break;                                                                                     \
    }                                                                                              \
    case 3:                                                                                        \
    case 4:                                                                                        \
    case 5:                                                                                        \
        mod.v1->method(mod.v1->impl, args);                                                        \
        break;                                                                                     \
    }

void ZygiskModule::preAppSpecialize(AppSpecializeArgs_v5 *args) const { call_app(preAppSpecialize) }

void ZygiskModule::postAppSpecialize(const AppSpecializeArgs_v5 *args) const {
    call_app(postAppSpecialize)
}

void ZygiskModule::preServerSpecialize(ServerSpecializeArgs_v1 *args) const {
    mod.v1->preServerSpecialize(mod.v1->impl, args);
}

void ZygiskModule::postServerSpecialize(const ServerSpecializeArgs_v1 *args) const {
    mod.v1->postServerSpecialize(mod.v1->impl, args);
}

// -----------------------------------------------------------------

void ZygiskContext::plt_hook_register(const char *regex, const char *symbol, void *fn,
                                      void **backup) {
    if (regex == nullptr || symbol == nullptr || fn == nullptr) return;
    regex_t re;
    if (regcomp(&re, regex, REG_NOSUB) != 0) return;
    mutex_guard lock(hook_info_lock);
    register_info.emplace_back(RegisterInfo{re, symbol, fn, backup});
}

void ZygiskContext::plt_hook_exclude(const char *regex, const char *symbol) {
    if (!regex) return;
    regex_t re;
    if (regcomp(&re, regex, REG_NOSUB) != 0) return;
    mutex_guard lock(hook_info_lock);
    ignore_info.emplace_back(IgnoreInfo{re, symbol ?: ""});
}

void ZygiskContext::plt_hook_process_regex() {
    if (register_info.empty()) return;
    for (auto &map : g_hook->cached_map_infos) {
        if (map.offset != 0 || !map.is_private || !(map.perms & PROT_READ)) continue;
        for (auto &reg : register_info) {
            if (regexec(&reg.regex, map.path.data(), 0, nullptr, 0) != 0) continue;
            bool ignored = false;
            for (auto &ign : ignore_info) {
                if (regexec(&ign.regex, map.path.data(), 0, nullptr, 0) != 0) continue;
                if (ign.symbol.empty() || ign.symbol == reg.symbol) {
                    ignored = true;
                    break;
                }
            }
            if (!ignored) {
                lsplt::RegisterHook(map.dev, map.inode, reg.symbol, reg.callback, reg.backup);
            }
        }
    }
}

bool ZygiskContext::plt_hook_commit() {
    {
        mutex_guard lock(hook_info_lock);
        plt_hook_process_regex();
        register_info.clear();
        ignore_info.clear();
    }
    return lsplt::CommitHook(g_hook->cached_map_infos);
}

// -----------------------------------------------------------------

void ZygiskContext::sanitize_fds() {
    if (!is_child()) {
        return;
    }

    if (can_exempt_fd() && !exempted_fds.empty()) {
        auto update_fd_array = [&](int old_len) -> jintArray {
            jintArray array = env->NewIntArray(static_cast<int>(old_len + exempted_fds.size()));
            if (array == nullptr) return nullptr;

            env->SetIntArrayRegion(array, old_len, static_cast<int>(exempted_fds.size()),
                                   exempted_fds.data());
            for (int fd : exempted_fds) {
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            *args.app->fds_to_ignore = array;
            return array;
        };

        if (jintArray fdsToIgnore = *args.app->fds_to_ignore) {
            int *arr = env->GetIntArrayElements(fdsToIgnore, nullptr);
            int len = env->GetArrayLength(fdsToIgnore);
            for (int i = 0; i < len; ++i) {
                int fd = arr[i];
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            if (jintArray newFdList = update_fd_array(len)) {
                env->SetIntArrayRegion(newFdList, 0, len, arr);
            }
            env->ReleaseIntArrayElements(fdsToIgnore, arr, JNI_ABORT);
        } else {
            update_fd_array(0);
        }
    }

    // Close all forbidden fds to prevent crashing
    auto dir = open_dir("/proc/self/fd");
    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if ((fd < 0 || static_cast<size_t>(fd) >= allowed_fds.size() || !allowed_fds[fd]) &&
            fd != dfd) {
            close(fd);
        }
    }
}

bool ZygiskContext::exempt_fd(int fd) {
    if ((flags & POST_SPECIALIZE) || (flags & SKIP_CLOSE_LOG_PIPE)) return true;
    if (!can_exempt_fd()) return false;
    exempted_fds.push_back(fd);
    LOGV("exempt fd %d", fd);
    return true;
}

bool ZygiskContext::can_exempt_fd() const {
    return (flags & APP_FORK_AND_SPECIALIZE) && args.app->fds_to_ignore;
}

static int sigmask(int how, int signum) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return sigprocmask(how, &set, nullptr);
}

void ZygiskContext::fork_pre() {
    // Do our own fork before loading any 3rd party code
    // First block SIGCHLD, unblock after original fork is done
    sigmask(SIG_BLOCK, SIGCHLD);
    pid = old_fork();

    if (!is_child()) return;

    // Record all open fds
    auto dir = xopen_dir("/proc/self/fd");
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if (fd < 0 || static_cast<size_t>(fd) >= allowed_fds.size()) {
            close(fd);
            continue;
        }
        allowed_fds[fd] = true;
    }
    // The dirfd will be closed once out of scope
    allowed_fds[dirfd(dir.get())] = false;
}

void ZygiskContext::fork_post() {
    // Unblock SIGCHLD in case the original method didn't
    sigmask(SIG_UNBLOCK, SIGCHLD);
}

/* Zygisksu changed: Load module fds */

/// True when the comma-separated `list` contains `needle` (whitespace-tolerant).
static bool list_contains(std::string_view list, std::string_view needle) {
    size_t start = 0;
    for (;;) {
        auto comma = list.find(',', start);
        auto token = list.substr(start, comma == std::string_view::npos ? std::string_view::npos
                                                                        : comma - start);
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) {
            token.remove_prefix(1);
        }
        while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) {
            token.remove_suffix(1);
        }
        if (token == needle) return true;
        if (comma == std::string_view::npos) return false;
        start = comma + 1;
    }
}

/// Whether the process being specialized falls inside the FN node's declared
/// scope. `scope` is 0 = all, 1 = allowlist, 2 = denylist; `process` is the
/// specialize `nice_name`, usually the package name. Processes like
/// `pkg:sub` are matched against the `pkg` prefix as well.
static bool fn_scope_matches(const zygiskd::FnModule &fn, const char *process) {
    if (fn.scope == 0 || process == nullptr || process[0] == '\0') return true;
    std::string_view proc(process);
    auto base = proc.substr(0, proc.find(':'));
    bool listed = list_contains(fn.apps, proc) || list_contains(fn.apps, base);
    return fn.scope == 1 ? listed : !listed;
}

/// Whether an FN node's `trigger` list applies to the process type being
/// specialized: `app`/`zygote` for app processes, `system_server`/`zygote`
/// for system_server. `zygote` means "at zygote level", i.e. everywhere.
static bool fn_applies(const zygiskd::FnModule &fn, bool is_server) {
    if (is_server) {
        return list_contains(fn.triggers, "system_server") || list_contains(fn.triggers, "zygote");
    }
    return list_contains(fn.triggers, "app") || list_contains(fn.triggers, "zygote");
}

void ZygiskContext::run_modules_pre() {
    auto ms = zygiskd::ReadModules();
    auto size = ms.size();
    for (size_t i = 0; i < size; i++) {
        auto &m = ms[i];
        if (LoadedModule lm = LoadModuleFromMemfd(m.memfd)) {
            modules.emplace_back(i, m.name, lm.handle, lm.entry, lm.custom);
        }
    }

    // FN (Functional Node) modules — phase 2. After the classic Zygisk modules
    // are loaded, load the entry libraries of the active FN nodes whose
    // triggers match this process type and whose scope covers the package
    // being specialized. FN indices are offset past the classic modules so
    // companion and module-dir requests resolve to the right node on the
    // daemon side (see `handle_read_fn_modules` in zygiskd).
    const bool is_server = (flags & SERVER_FORK_AND_SPECIALIZE) != 0;
    auto fns = zygiskd::ReadFnModules();
    for (size_t i = 0; i < fns.size(); i++) {
        auto &fn = fns[i];
        if (!fn_applies(fn, is_server)) continue;
        if (!is_server && !fn_scope_matches(fn, process)) continue;
        if (LoadedModule lm = LoadModuleFromMemfd(fn.memfd)) {
            LOGI("loading FN module `%s` into %s (priority %u)", fn.id.c_str(),
                 is_server ? "system_server" : process ? process : "unknown", fn.priority);
            modules.emplace_back(size + i, fn.id, lm.handle, lm.entry, lm.custom);
        }
    }

    for (auto &m : modules) {
        m.onLoad(env);
        if (flags & APP_SPECIALIZE) {
            m.preAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.preServerSpecialize(args.server);
        }
    }
}

void ZygiskContext::run_modules_post() {
    flags |= POST_SPECIALIZE;

    size_t modules_unloaded = 0;
    for (const auto &m : modules) {
        if (flags & APP_SPECIALIZE) {
            m.postAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.postServerSpecialize(args.server);
        }
        if (m.tryUnload()) modules_unloaded++;
    }

    if (modules.size() > 0) {
        LOGV("modules unloaded: %zu/%zu", modules_unloaded, modules.size());
        if (modules.size() == modules_unloaded) {
            clean_libc_trace();
            // Only safe once every module this process loaded — custom or
            // system-linker — is actually gone: a still-resident
            // custom-loaded module (one that didn't ask to unload) depends on
            // the custom loader's global TLS bookkeeping for as long as it
            // keeps running.
            DeinitCustomLoaderIfUsed();
        }
        clean_linker_trace("jit-cache-zygisk", modules.size(), modules_unloaded, true);
        g_hook->should_spoof_maps =
            (flags & APP_SPECIALIZE) && (modules.size() - modules_unloaded) > 0;
    }
}

void ZygiskContext::app_specialize_pre() {
    uid_t uid = args.app->uid;
    bool is_isolated_aid = uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END;
    if (is_isolated_aid && args.app->app_data_dir) {
        const char *data_dir = nullptr;
        data_dir = env->GetStringUTFChars(args.app->app_data_dir, nullptr);
        if (data_dir != nullptr) {
            struct stat st;
            if (stat(data_dir, &st) != -1) {
                // Correct uid for isolated services
                uid = st.st_uid;
            }
            LOGV("Found isolated process [uid:%d, data_dir:%s]", uid, data_dir);
            env->ReleaseStringUTFChars(args.app->app_data_dir, data_dir);
        }
    }

    bool skip_zygiskd = false;
    if (is_isolated_aid) {
        UniqueFd fd = zygiskd::Connect(1);
        if (fd == -1) {
            skip_zygiskd = true;
        }
    }

    if (!skip_zygiskd && info_flags == 0) info_flags = zygiskd::GetProcessFlags(uid);

    if ((info_flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        LOGI("[%s] is on the denylist", process);
        flags |= DO_REVERT_UNMOUNT;
    }

    flags |= APP_SPECIALIZE;
    if (!skip_zygiskd) run_modules_pre();
}

void ZygiskContext::app_specialize_post() {
    run_modules_post();

    if ((info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
        LOGI("current uid %d is manager!", args.app->uid);
        setenv("ZYGISK_ENABLED", "1", 1);
    }

    // Cleanups
    env->ReleaseStringUTFChars(args.app->nice_name, process);
}

// Experimental post-boot live loading, based on d1763cd. Keep only durable
// process state: the specialization context and its JNIEnv are stack/thread local.
static constexpr int kHotplugSignal = 40;
static int hotplug_pipe[2] = {-1, -1};
static JavaVM *hotplug_vm = nullptr;
static std::vector<std::string> hotplug_loaded;
static uint32_t hotplug_flags = 0;
static std::atomic<bool> hotplug_worker_started{false};

bool live_hotplug_armed() { return hotplug_pipe[0] >= 0; }

static void hotplug_signal_handler(int) {
    const int saved_errno = errno;
    const char request = 1;
    // Nonblocking async-signal-safe wakeup. A full pipe already has work queued.
    (void) write(hotplug_pipe[1], &request, sizeof(request));
    errno = saved_errno;
}

static void *hotplug_worker(void *) {
    JNIEnv *env = nullptr;
    if (hotplug_vm->AttachCurrentThreadAsDaemon(&env, nullptr) != JNI_OK) {
        LOGE("hot-plug: could not attach live loader worker to JVM");
        return nullptr;
    }
    // Owned for process life, never the old specialization stack object.
    auto *ctx = new ZygiskContext(env, nullptr);
    ctx->info_flags = hotplug_flags;
    ctx->flags = SERVER_FORK_AND_SPECIALIZE;
    g_ctx = nullptr;
    LOGI("hot-plug: live loader worker ready (pid %d)", getpid());
    for (;;) {
        pollfd wake{hotplug_pipe[0], POLLIN, 0};
        if (poll(&wake, 1, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char requests[64];
        if (read(hotplug_pipe[0], requests, sizeof(requests)) <= 0) continue;
        auto ms = zygiskd::ReadModules();
        for (size_t i = 0; i < ms.size(); ++i) {
            auto &m = ms[i];
            if (std::find(hotplug_loaded.begin(), hotplug_loaded.end(), m.name) != hotplug_loaded.end()) continue;
            LOGI("hot-plug: live load begin module=%s pid=%d", m.name.c_str(), getpid());
            auto lm = LoadModuleFromMemfd(m.memfd);
            if (!lm) continue;
            ctx->modules.emplace_back(static_cast<int>(i), m.name, lm.handle, lm.entry, lm.custom);
            auto &mod = ctx->modules.back();
            jint uid = 1000, gid = 1000, runtime_flags = 0;
            jintArray gids = nullptr;
            jlong permitted = 0, effective = 0;
            ServerSpecializeArgs_v1 args(uid, gid, gids, runtime_flags, permitted, effective);
            ctx->args.server = &args;
            ctx->flags = SERVER_FORK_AND_SPECIALIZE;
            g_ctx = ctx;
            mod.onLoad(env);
            if (mod.valid() && !env->ExceptionCheck()) {
                LOGI("hot-plug: preServerSpecialize module=%s", m.name.c_str());
                mod.preServerSpecialize(&args);
                if (!env->ExceptionCheck()) {
                    ctx->flags |= POST_SPECIALIZE;
                    mod.postServerSpecialize(&args);
                }
            }
            if (env->ExceptionCheck()) {
                LOGE("hot-plug: Java exception module=%s", m.name.c_str());
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            mod.clearApi();
            mod.tryUnload();
            ctx->args.ptr = nullptr;
            g_ctx = nullptr;
            // Never run initialization twice for a resident library, even on error.
            hotplug_loaded.push_back(m.name);
            LOGI("hot-plug: live load end module=%s", m.name.c_str());
        }
    }
    hotplug_vm->DetachCurrentThread();
    return nullptr;
}

void start_live_hotplug_worker() {
    if (hotplug_worker_started.exchange(true)) return;
    pthread_t worker;
    const int error = pthread_create(&worker, nullptr, hotplug_worker, nullptr);
    if (error != 0) {
        hotplug_worker_started.store(false);
        LOGE("hot-plug: worker creation failed: %d", error);
        return;
    }
    pthread_detach(worker);
}

void ZygiskContext::server_specialize_pre() {
    // Retain only the daemon directory, not access to /data/adb (root:0700).
    // Later socket connects resolve relative to this fd after dropping uid.
    int live_dir = open(zygiskd::GetTmpPath().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (live_dir >= 0 && static_cast<size_t>(live_dir) < allowed_fds.size()) {
        allowed_fds[live_dir] = true;
        std::string path = "/proc/self/fd/" + std::to_string(live_dir);
        zygiskd::Init(path.c_str());
    } else {
        if (live_dir >= 0) close(live_dir);
        LOGE("hot-plug: failed to retain daemon directory");
    }
    // Notify the daemon BEFORE loading any module. The daemon's hot-plug
    // circuit breaker keys off this heartbeat: if a freshly hot-plugged
    // module crashes or hangs system_server while being loaded below, the
    // restart guard would otherwise stay armed forever and the breaker
    // could never unplug the offending module.
    zygiskd::SystemServerStarted();
    run_modules_pre();
}

void ZygiskContext::server_specialize_post() {
    // Capture names before post callbacks may unload module libraries.
    for (const auto &mod : modules) hotplug_loaded.push_back(mod.getName());
    run_modules_post();
    if (env->GetJavaVM(&hotplug_vm) != JNI_OK) return;
    hotplug_flags = info_flags;
    struct sigaction previous {};
    if (sigaction(kHotplugSignal, nullptr, &previous) != 0 || previous.sa_handler != SIG_DFL) {
        LOGW("hot-plug: signal 40 is already owned; live loading unavailable");
        return;
    }
    if (pipe2(hotplug_pipe, O_CLOEXEC | O_NONBLOCK) != 0) return;
    struct sigaction action {};
    action.sa_handler = hotplug_signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    if (sigaction(kHotplugSignal, &action, nullptr) != 0) {
        close(hotplug_pipe[0]);
        close(hotplug_pipe[1]);
        hotplug_pipe[0] = hotplug_pipe[1] = -1;
        return;
    }
    // No thread is created here: setcon must complete single-threaded.
    LOGI("hot-plug: armed live loader signal in system_server (pid %d)", getpid());
}

// -----------------------------------------------------------------

void ZygiskContext::nativeSpecializeAppProcess_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre specialize [%s]", process);
    // App specialize does not check FD
    flags |= SKIP_CLOSE_LOG_PIPE;
    app_specialize_pre();
}

void ZygiskContext::nativeSpecializeAppProcess_post() {
    LOGV("post specialize [%s]", process);
    app_specialize_post();
}

void ZygiskContext::nativeForkSystemServer_pre() {
    LOGV("pre forkSystemServer");
    flags |= SERVER_FORK_AND_SPECIALIZE;

    for (auto &map : g_hook->cached_map_infos) {
        if (map.dev == 0 && map.inode == 0 && map.offset == 0 && map.is_private &&
            map.path == "[anon:stack_and_tls:main]") {
            if ((map.perms & PROT_READ) == 0) {
                LOGV("Skipping non-readable stack map at %p", reinterpret_cast<void *>(map.start));
                continue;
            }
            auto search_from = reinterpret_cast<char *>(map.start);
            auto search_to = reinterpret_cast<char *>(map.end);
            spoof_zygote_fossil(search_from, search_to, "ref_profiles");
            break;
        }
    }

    fork_pre();
    if (is_child()) {
        server_specialize_pre();
        zygiskd::CacheMountNamespace(getpid());
    }
    sanitize_fds();
}

void ZygiskContext::nativeForkSystemServer_post() {
    if (is_child()) {
        LOGV("post forkSystemServer");
        server_specialize_post();
    }
    fork_post();
}

bool abort_zygote_unmount(const std::vector<mount_info> &traces, uint32_t info_flags) {
    if (traces.size() == 0) {
        LOGV("abort unmounting zygote with an empty trace list");
        return true;
    }
    bool is_magisk = info_flags & PROCESS_ROOT_IS_MAGISK;
    for (const auto &trace : traces) {
        if (trace.target.rfind("/product", 0) == 0) {
            if (trace.target.rfind("/product/bin", 0) == 0) continue;
            if (!is_magisk && trace.target != "/product") continue;
            // workaround for zygote resource overlay (JingMatrix/NeoZygisk#26)
            LOGV("abort unmounting zygote due to prohibited target: [%s]", trace.raw_info.c_str());
            return true;
        }
    }
    return false;
}

void ZygiskContext::nativeForkAndSpecialize_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre forkAndSpecialize [%s]", process);
    flags |= APP_FORK_AND_SPECIALIZE;

    // Direct zygote unmounting is the "revert only" mount mode only. In the
    // "namespace switch" and "global" modes the zygote keeps its module mounts
    // (denylisted apps are handled by setns / not at all — see the unshare
    // hook), so this whole step is skipped.
    if (!g_hook->zygote_unmounted && g_hook->zygote_traces.size() == 0) {
        info_flags = zygiskd::GetProcessFlags(args.app->uid);

        if (!(info_flags & (MOUNT_MODE_SETNS | MOUNT_MODE_GLOBAL))) {
            g_hook->zygote_traces = check_zygote_traces(info_flags);

            if (!abort_zygote_unmount(g_hook->zygote_traces, info_flags)) {
                auto removal_predicate = [](const mount_info &trace) {
                    LOGV("unmounting %s (mnt_id: %u)", trace.target.c_str(), trace.id);
                    if (umount2(trace.target.c_str(), MNT_DETACH) == 0) {
                        return true;  // Success: Mark for removal.
                    } else {
                        LOGE("failed to unmount %s: %s", trace.target.c_str(), strerror(errno));
                        return false;  // Failure: Keep this trace in the vector.
                    }
                };

                auto new_end = std::remove_if(g_hook->zygote_traces.begin(),
                                              g_hook->zygote_traces.end(), removal_predicate);

                g_hook->zygote_traces.erase(new_end, g_hook->zygote_traces.end());
                g_hook->zygote_unmounted = true;
            }
        }
    }

    fork_pre();
    if (is_child()) {
        app_specialize_pre();
    }

    sanitize_fds();
}

void ZygiskContext::nativeForkAndSpecialize_post() {
    if (is_child()) {
        LOGV("post forkAndSpecialize [%s]", process);
        app_specialize_post();
    }
    fork_post();
}

// -----------------------------------------------------------------

bool ZygiskContext::update_mount_namespace(zygiskd::MountNamespace namespace_type) {
    const char *type_str = (namespace_type == zygiskd::MountNamespace::Clean ? "Clean" : "Root");
    LOGV("updating mount namespace to type %s", type_str);

    int ns_fd = zygiskd::UpdateMountNamespace(namespace_type);

    // Check for failure (Not cached or error)
    if (ns_fd < 0) {
        LOGW("mount namespace [%s] not available/cached", type_str);
        return false;
    }

    // Apply the namespace
    // setns works directly with the FD received from the socket.
    int ret = setns(ns_fd, CLONE_NEWNS);
    if (ret != 0) {
        PLOGE("setns failed for type %s", type_str);
        close(ns_fd);
        return false;
    }

    close(ns_fd);
    return true;
}
