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
