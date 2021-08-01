/*
 *  sandbox.c
 *
 *  Copyright (c) 2021 Pacman Development Team <pacman-dev@archlinux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef HAVE_LINUX_LANDLOCK_H
# include <linux/landlock.h>
# include <sys/prctl.h>
# include <sys/syscall.h>
#endif /* HAVE_LINUX_LANDLOCK_H */

#ifdef HAVE_LIBSECCOMP
# include <seccomp.h>
#endif /* HAVE_LIBSECCOMP */

#include "alpm_sandbox.h"

#ifdef HAVE_LINUX_LANDLOCK_H
#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif /* landlock_create_ruleset */

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr, const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif /* landlock_add_rule */

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif /* landlock_restrict_self */

#define _LANDLOCK_ACCESS_FS_WRITE ( \
  LANDLOCK_ACCESS_FS_WRITE_FILE | \
  LANDLOCK_ACCESS_FS_REMOVE_DIR | \
  LANDLOCK_ACCESS_FS_REMOVE_FILE | \
  LANDLOCK_ACCESS_FS_MAKE_CHAR | \
  LANDLOCK_ACCESS_FS_MAKE_DIR | \
  LANDLOCK_ACCESS_FS_MAKE_REG | \
  LANDLOCK_ACCESS_FS_MAKE_SOCK | \
  LANDLOCK_ACCESS_FS_MAKE_FIFO | \
  LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
  LANDLOCK_ACCESS_FS_MAKE_SYM)

#define _LANDLOCK_ACCESS_FS_READ ( \
  LANDLOCK_ACCESS_FS_READ_FILE | \
  LANDLOCK_ACCESS_FS_READ_DIR)

static int sandbox_write_only_beneath_cwd(void)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = \
			_LANDLOCK_ACCESS_FS_READ | \
			_LANDLOCK_ACCESS_FS_WRITE | \
			LANDLOCK_ACCESS_FS_EXECUTE,
	};
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = _LANDLOCK_ACCESS_FS_WRITE,
	};
	int result = 0;
	int ruleset_fd;

	ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if(ruleset_fd < 0) {
		return ruleset_fd;
	}

	/* allow / as read-only */
	path_beneath.parent_fd = open("/", O_PATH | O_CLOEXEC | O_DIRECTORY);
	path_beneath.allowed_access = _LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE;

	if(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
		result = errno;
	}

	close(path_beneath.parent_fd);

	if(result == 0) {
		/* allow the current working directory as read-write */
		path_beneath.parent_fd = open(".", O_PATH | O_CLOEXEC | O_DIRECTORY);
		path_beneath.allowed_access = _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;

		if(!landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
			prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
			if(landlock_restrict_self(ruleset_fd, 0)) {
				result = errno;
			}
		} else {
			result = errno;
		}

		close(path_beneath.parent_fd);
	}

	close(ruleset_fd);
	return result;
}
#endif /* HAVE_LINUX_LANDLOCK_H */

#ifdef HAVE_LIBSECCOMP

static int sandbox_filter_syscalls(void)
{
	int ret = 0;
	/* see https://docs.docker.com/engine/security/seccomp/ for inspiration,
		 as well as systemd's src/shared/seccomp-util.c */
	const char* denied_syscalls[] = {
		/* kernel modules */
		"delete_module",
		"finit_module",
		"init_module",
		/* mount */
		"chroot",
		"fsconfig",
		"fsmount",
		"fsopen",
		"fspick",
		"mount",
		"move_mount",
		"open_tree",
		"pivot_root",
		"umount",
		"umount2",
		/* keyring */
		"add_key",
		"keyctl",
		"request_key",
		/* CPU emulation */
		"modify_ldt",
		"subpage_prot",
		"switch_endian",
		"vm86",
		"vm86old",
		/* debug */
		"kcmp",
		"lookup_dcookie",
		"perf_event_open",
		"ptrace",
		"rtas",
		"sys_debug_setcontext",
		/* set clock */
		"adjtimex",
		"clock_adjtime",
		"clock_adjtime64",
		"clock_settime",
		"clock_settime64",
		"settimeofday",
		/* raw IO */
		"ioperm",
		"iopl",
		"pciconfig_iobase",
		"pciconfig_read",
		"pciconfig_write",
		/* kexec */
		"kexec_file_load",
		"kexec_load",
		/* reboot */
		"reboot",
		/* privileged */
		"acct",
		"bpf",
		"personality",
		/* obsolete */
		"_sysctl",
		"afs_syscall",
		"bdflush",
		"break",
		"create_module",
		"ftime",
		"get_kernel_syms",
		"getpmsg",
		"gtty",
		"idle",
		"lock",
		"mpx",
		"prof",
		"profil",
		"putpmsg",
		"query_module",
		"security",
		"sgetmask",
		"ssetmask",
		"stime",
		"stty",
		"sysfs",
		"tuxcall",
		"ulimit",
		"uselib",
		"ustat",
		"vserver",
		/* swap */
		"swapon",
		"swapoff",
	};
	/* allow all syscalls that are not listed */
	size_t idx;
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	if(ctx == NULL) {
		return errno;
	}

	for(idx = 0; idx < sizeof(denied_syscalls) / sizeof(*denied_syscalls); idx++) {
		int syscall = seccomp_syscall_resolve_name(denied_syscalls[idx]);
		if(syscall != __NR_SCMP_ERROR) {
			if(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall, 0) != 0) {
				//pm_printf(ALPM_LOG_WARNING, _("Error blocking syscall %s\n"), denied_syscalls[idx]);
			}
		}
	}

	if(seccomp_load(ctx) != 0) {
		ret = errno;
	}

	seccomp_release(ctx);
	return ret;
}
#endif /* HAVE_LIBSECCOMP */

/* check exported library symbols with: nm -C -D <lib> */
#define SYMEXPORT __attribute__((visibility("default")))

int SYMEXPORT alpm_sandbox_child(void)
{
	int result = 0;
#ifdef HAVE_LINUX_LANDLOCK_H
	int ret = 0;
#endif/* HAVE_LINUX_LANDLOCK_H */

#ifdef HAVE_LIBSECCOMP
	result = sandbox_filter_syscalls();
#endif /* HAVE_LIBSECCOMP */

#ifdef HAVE_LIBCAP
	cap_t caps = cap_get_proc();
	cap_clear(caps);
	if(cap_set_mode(CAP_MODE_NOPRIV) != 0) {
		cap_free(caps);
		if(result == 0) {
			result = errno;
		}
	}
	if(cap_set_proc(caps) != 0) {
		cap_free(caps);
		if(result == 0) {
			result = errno;
		}
	}
	cap_free(caps);
#endif /* HAVE_LIBCAP */

#ifdef HAVE_LINUX_LANDLOCK_H
	ret = sandbox_write_only_beneath_cwd();
	if(result == 0) {
		result = ret;
	}
#endif /* HAVE_LINUX_LANDLOCK_H */
	return result;
}
