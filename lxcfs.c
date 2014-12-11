/* lxcfs
 *
 * Copyright © 2014 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>


static int lxcfs_getattr(const char *path, struct stat *sb)
{
	struct timespec now;

	memset(sb, 0, sizeof(struct stat));

	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	sb->st_size = 0;

	if (strcmp(path, "/cgroup") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	} else if (strncmp(path, "/cgroup/", 8) == 0) {
		printf("got request for cgroup file %s\n", path);
	}
	return -EINVAL;
}

static int lxcfs_opendir(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/cgroup") == 0) {
		return 0;
	} else if (strncmp(path, "/cgroup/", 8) == 0) {
		// return list of keys for the controller, and list of child cgroups
	}
	return -EINVAL;
}

static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	if (strcmp(path, "/cgroup") == 0) {
		// get list of controllers
		if (filler(buf, "blkio", NULL, 0) != 0 ||
				filler(buf, "freezer", NULL, 0) != 0) {
			printf("error filling in controllers\n");
			return -EINVAL;
		}
		return 0;
	} else if (strncmp(path, "/cgroup/", 8) == 0) {
		// return list of keys for the controller, and list of child cgroups
	}
	return -EINVAL;
}

static int lxcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

const struct fuse_operations lxcfs_ops = {
	.getattr = lxcfs_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = NULL,
	.unlink = NULL,
	.rmdir = NULL,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = NULL,
	.chown = NULL,
	.truncate = NULL,
	.utime = NULL,
	.open = NULL,
	.read = NULL,
	.write = NULL,
	.statfs = NULL,
	.flush = NULL,
	.release = NULL,
	.fsync = NULL,

	.setxattr = NULL,
	.getxattr = NULL,
	.listxattr = NULL,
	.removexattr = NULL,

	.opendir = lxcfs_opendir,
	.readdir = lxcfs_readdir,
	.releasedir = lxcfs_releasedir,

	.fsyncdir = NULL,
	.init = NULL,
	.destroy = NULL,
	.access = NULL,
	.create = NULL,
	.ftruncate = NULL,
	.fgetattr = NULL,
};

void usage(const char *me)
{
	printf("Usage:\n");
	printf("\n");
	printf("%s [FUSE and mount options] mountpoint\n", me);
	exit(1);
}

bool is_help(char *w)
{
	if (strcmp(w, "-h") == 0 ||
			strcmp(w, "--help") == 0 ||
			strcmp(w, "-help") == 0 ||
			strcmp(w, "help") == 0)
		return true;
	return false;
}

int main(int argc, char *argv[])
{
	int ret;
//	struct lxcfs_state *lxcfs_data;

	if (argc < 2 || is_help(argv[1]))
		usage(argv[0]);

	ret = fuse_main(argc, argv, &lxcfs_ops, NULL);

	return ret;
}
