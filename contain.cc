#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string>
#include <unordered_set>

#include <kj/debug.h>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

namespace {

enum Option : char { kOptionMap = 'm' };

const char *kDefaultFileSystemMap[] = {
    "/bin",  "/dev", "/etc",           "/lib", "/lib64",
    "/proc", "/sys", "/tmp/.X11-unix", "/usr", "/var"};

std::unordered_set<std::string> xauth;
std::unordered_set<std::string> file_system_map;
int disable_networking;
int print_version;
int print_help;

struct option kLongOptions[] = {
    {"disable-networking", no_argument, &disable_networking, 1},
    {"map", required_argument, nullptr, kOptionMap},
    {"help", no_argument, &print_help, 1},
    {"version", no_argument, &print_version, 1},
    {nullptr, 0, nullptr, 0}};

// Drops some capabilities only needed by system administrators.
void DropCapabilities() {
  static const std::array<cap_value_t, 12> kCapabilities{{
      // Block system suspend.
      CAP_BLOCK_SUSPEND,

      // Use reboot(2) and kexec_load(2).
      CAP_SYS_BOOT,

      // Lock memory (mlock, MAP_LOCKED).
      CAP_IPC_LOCK,

      // Override Mandatory Access Control.
      CAP_MAC_ADMIN, CAP_MAC_OVERRIDE,

      // Configure network interfaces
      CAP_NET_ADMIN,

      // Load and unload kernel modules.
      CAP_SYS_MODULE,

      // Use the acct(2).
      CAP_SYS_PACCT,

      // Access hardware IO ports.
      CAP_SYS_RAWIO,

      // Change system clock.
      CAP_SYS_TIME,

      // Perform privileged operations on syslog.
      CAP_SYSLOG,

      // Trigger something that will wake up the system.
      CAP_WAKE_ALARM,
  }};

  static const cap_flag_t kFlags[] = {CAP_INHERITABLE, CAP_PERMITTED,
                                      CAP_EFFECTIVE};

  auto caps = cap_get_proc();

  // XXX: Cargo cult programming based on capability.c from systemd.

  for (const auto cap : kCapabilities) {
    KJ_SYSCALL(prctl(PR_CAPBSET_DROP, cap));
  }

  for (const auto flag : kFlags) {
    KJ_SYSCALL(cap_set_flag(caps, flag, kCapabilities.size(),
                            kCapabilities.data(), CAP_CLEAR));
  }

  KJ_SYSCALL(cap_set_proc(caps));

  cap_free(caps);
}

void MkDirIfNotExists(const std::string &path, int mode) {
  static std::unordered_set<std::string> existing_paths;

  auto i = path.find('/', 1);

  while (i != std::string::npos) {
    auto path_prefix = path.substr(0, i);

    if (!existing_paths.count(path_prefix)) {
      auto ret = mkdir(path_prefix.c_str(), mode);
      if (ret == -1 && errno != EEXIST) {
        KJ_FAIL_SYSCALL("mkdir", errno, path_prefix);
      }
      existing_paths.emplace(path_prefix);
    }

    i = path.find('/', i + 1);
  }

  if (existing_paths.count(path)) return;

  auto ret = mkdir(path.c_str(), mode);
  if (ret == -1 && errno != EEXIST) {
    KJ_FAIL_SYSCALL("mkdir", errno, path);
  }

  existing_paths.emplace(path);
}

// Drops access to namespaces we don't need.
void DropNamespaces() {
  const auto kUser = "nobody";

  auto pwent = getpwnam(kUser);
  KJ_REQUIRE(pwent != nullptr, kUser);
  auto uid = pwent->pw_uid;
  auto gid = pwent->pw_gid;

  std::vector<gid_t> groups;
  groups.emplace_back(gid);

  // These don't seem to be needed.
  // auto audio_group = getgrnam("audio");
  // if (audio_group) groups.emplace_back(audio_group->gr_gid);
  // auto video_group = getgrnam("video");
  // if (video_group) groups.emplace_back(video_group->gr_gid);

  const char *tmpdir = getenv("TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";

  char *root_path;
  KJ_SYSCALL(asprintf(&root_path, "%s/contain.XXXXXX", tmpdir));

  umask(0);

  root_path = mkdtemp(root_path);
  if (!root_path) {
    KJ_FAIL_SYSCALL("mkdtemp", errno, root_path);
  }

  std::string home_path = root_path;
  home_path += "/myhome";
  MkDirIfNotExists(home_path.c_str(), 0770);
  KJ_SYSCALL(chown(home_path.c_str(), uid, gid), home_path);

  std::string tmp_path = root_path;
  tmp_path += "/tmp";
  MkDirIfNotExists(tmp_path.c_str(), 01777);

  int unshare_flags = CLONE_NEWIPC | CLONE_NEWNS;
  if (disable_networking) unshare_flags |= CLONE_NEWNET;
  KJ_SYSCALL(unshare(unshare_flags));

  KJ_SYSCALL(mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr));

  for (const auto &path : file_system_map) {
    std::string target(root_path);
    target += path;

    MkDirIfNotExists(target.c_str(), 0755);
    KJ_SYSCALL(mount(path.c_str(), target.c_str(), nullptr,
                     MS_BIND | MS_REC | MS_NOSUID, nullptr),
               path);
  }

  KJ_SYSCALL(chroot(root_path), root_path);
  KJ_SYSCALL(chmod("/", 0755));
  KJ_SYSCALL(chdir("/myhome"));

  KJ_SYSCALL(setgroups(groups.size(), groups.data()));
  KJ_SYSCALL(setgid(gid));
  KJ_SYSCALL(setuid(uid));

  umask(0022);
}

void GetXAuth() {
  std::unique_ptr<FILE, decltype(&fclose)> input(popen("xauth list", "r"),
                                                 fclose);
  if (!input) return;

  char line[1024];
  while (fgets(line, sizeof(line), input.get())) {
    line[sizeof(line) - 1] = 0;
    auto len = strlen(line);
    while (len > 0 && std::isspace(line[len - 1])) line[--len] = 0;
    xauth.emplace(line);
  }
}

void PutXAuth() {
  if (xauth.empty()) return;

  int fd;
  KJ_SYSCALL(fd = creat("/myhome/.Xauthority", 0700));
  close(fd);

  std::unique_ptr<FILE, decltype(&fclose)> output(
      popen("xauth -f /myhome/.Xauthority -q", "w"), fclose);
  if (!output) return;

  for (const auto &xa : xauth) fprintf(output.get(), "add %s\n", xa.c_str());
}

}  // namespace

int main(int argc, char **argv) try {
  int i;
  while ((i = getopt_long(argc, argv, "D:n", kLongOptions, 0)) != -1) {
    if (!i) continue;
    if (i == '?')
      errx(EX_USAGE, "Try '%s --help' for more information.", argv[0]);

    switch (static_cast<Option>(i)) {
      case kOptionMap: {
        auto i = optarg;

        for (;;) {
          auto end = strchr(i, ':');
          if (end == nullptr) {
            KJ_REQUIRE(*i == '/');
            file_system_map.emplace(i);
            break;
          }

          *end = 0;
          KJ_REQUIRE(*i == '/');
          file_system_map.emplace(i);

          i = end + 1;
        }

      } break;
    }
  }

  if (print_help) {
    printf(
        "Usage: %s [OPTION]... COMMAND...\n"
        "\n"
        "      --map=DIR[:DIR]...     colon delimited list of paths to map\n"
        "      --disable-network      unshare network namespace\n"
        "      --help     display this help and exit\n"
        "      --version  display version information and exit\n"
        "\n"
        "Report bugs to <morten.hustveit@gmail.com>\n",
        argv[0]);

    return EXIT_SUCCESS;
  }

  if (print_version) {
    puts(PACKAGE_STRING);

    return EXIT_SUCCESS;
  }

  for (const auto path : kDefaultFileSystemMap) {
    if (0 != access(path, F_OK)) continue;
    file_system_map.emplace(path);
  }

  std::vector<std::string> environ_buffer;
  environ_buffer.emplace_back("HOME=/myhome");
  environ_buffer.emplace_back("TMPDIR=/tmp");
  environ_buffer.emplace_back("XAUTHORITY=/myhome/.Xauthority");
  environ_buffer.emplace_back("PATH=/bin:/usr/bin");

  auto display = getenv("DISPLAY");
  if (display) {
    environ_buffer.emplace_back(std::string("DISPLAY=") + display);
    GetXAuth();
  }

  auto term = getenv("TERM");
  if (term) environ_buffer.emplace_back(std::string("TERM=") + term);

  DropCapabilities();
  DropNamespaces();

  PutXAuth();

  std::vector<char *> command(&argv[optind], &argv[argc]);
  if (command.empty()) command.emplace_back(const_cast<char *>("/bin/bash"));
  command.emplace_back(nullptr);

  std::vector<char *> command_environ;
  for (const auto &e : environ_buffer)
    command_environ.emplace_back(const_cast<char *>(e.c_str()));
  command_environ.emplace_back(nullptr);

  struct stat st;
  KJ_SYSCALL(execve(command[0], command.data(), command_environ.data()));
} catch (kj::Exception e) {
  KJ_LOG(ERROR, e);
  return EXIT_FAILURE;
}
