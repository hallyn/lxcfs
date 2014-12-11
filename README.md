# lxcfs

This contains a FUSE filesystem to present a cgroup filesystem
to containers, as well as /proc/{cpu,mem}info as filtered by cgroups.

## notes

### usage

The expected usage is:

root on the host mounts an instance of lxcfs.

When a container is started, it bind mounts its cgroups into
the container.

Therefore, lxcfs does not do the ancestry checks the way cgmanager does.
If a container wants to see /cgroup/freezer/lxc/l1 even though it is in
/cgroup/freezer/lxc/l2, we won't stop it based on just that.  (That should
have been denied by not having that path mounted in the container).
Note that we WILL deny it based on file permissions, if appropriate.

### directory descend

If a task in /cgroup/freezer/lxc/l2/user.slice/foo wants to look at
something under /cgroup/freezer/lxc/l2/user.slice/foo/x1, then we
will only check for directory 'x' checks from /cgroup/freezer/lxc/l2/user.slice/foo
downward.  So marking /cgroup/freezer/lxc 000 won't prevent that.
Note that the analogous would have been true with regular bind mounts.
The difference is that we are only checking from the caller's cgroup
downward, which may be deeper tha the bind mount.

if /cgroup/freezer/lxc/l2/user.slice/foo wants to look at something
under /cgroup/freezer/lxc/l3/user.slice/bar, then we will check full
perms from /cgroup/freezer/lxc downward.  This is becasue there is no
good way for us to detect which path was bind-mounted.
