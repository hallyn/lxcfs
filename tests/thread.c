/*
 * This is based on lxcfs.c, cgmanager,c and some of
 * S.Çağlar's concurrent lxc test

 * Copyright © 2015 Serge Hallyn <serge.hallyn@ubuntu.com>
 * Copyright © 2013 S.Çağlar Onur <caglar@10ur.org>
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

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <sys/param.h>
#include <wait.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/error.h>

#ifdef WITH_CGMANAGER
#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_proxy.h>
#include <cgmanager/cgmanager-client.h>
#include "../cgmanager.h"
// else use libgdbus
#endif

#include "../config.h"

static int nthreads = 5;
static int iterations = 1;
static int debug = 0;
static int quiet = 0;
static int delay = 0;

static const struct option options[] = {
	{"threads", required_argument, NULL, 'j'},
	{"iterations", required_argument, NULL, 'i'},
	{"modes", required_argument, NULL, 'm'},
	{"quiet", no_argument, NULL, 'q'},
	{"debug", no_argument, NULL, 'D'},
	{"help", no_argument, NULL, '?'},
	{0, 0, 0, 0},
};

static void
usage (void)
{
	fprintf (stderr, "Usage: lxc-test-concurrent [OPTION]...\n\n"
			"Common options :\n"
			"  -j, --threads=N              Threads to run concurrently\n"
			"                               (default: 5, use 1 for no threading)\n"
			"  -i, --iterations=N           Number times to run the test (default: 1)\n"
			"  -m, --modes=<mode,mode,...>  Modes to run (create, start, stop, destroy)\n"
			"  -q, --quiet                  Don't produce any output\n"
			"  -D, --debug                  Create a debug log\n"
			"  -?, --help                   Give this help list\n"
			"\n"
			"Mandatory or optional arguments to long options are also mandatory or optional\n"
			"for any corresponding short options.\n\n");
}

#define BASE_CG "test_cgm_nih"

static int gettid(void)
{
	return (int)syscall(__NR_gettid);
}

static __thread NihDBusProxy *cgroup_manager = NULL;
static __thread int32_t api_version;

static void
cgm_dbus_disconnect (void)
{
	if (cgroup_manager)
	{
		dbus_connection_flush (cgroup_manager->connection);
		dbus_connection_close (cgroup_manager->connection);
		nih_free (cgroup_manager);
	}
	cgroup_manager = NULL;
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static bool
cgm_dbus_connect (void)
{
	DBusError dbus_error;
	static DBusConnection *connection;

	dbus_error_init (&dbus_error);

	connection =
		dbus_connection_open_private (CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection)
	{
		fprintf (stderr, "Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free (&dbus_error);
		return false;
	}
	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_error_free (&dbus_error);
	cgroup_manager = nih_dbus_proxy_new (NULL, connection, NULL /* p2p */ ,
			"/org/linuxcontainers/cgmanager", NULL,
			NULL);
	dbus_connection_unref (connection);
	if (!cgroup_manager)
	{
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "Error opening cgmanager proxy: %s\n", nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		return false;
	}

	// get the api version
	if (cgmanager_get_api_version_sync (NULL, cgroup_manager, &api_version) !=
			0)
	{
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "Error cgroup manager api version: %s\n",
				nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		return false;
	}
	return true;
}

struct thread_args
{
	int thread_id;
	int victim_pid;
	int return_code;
	const char *mode;
};

static bool rm_cg(char *cg)
{
	int32_t existed = 0, rec = 1;

	if (!cgm_dbus_connect ())
		return false;
	if (cgmanager_remove_sync(NULL, cgroup_manager, "freezer", cg, rec, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "call to remove (%s) failed: %s\n", cg, nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		return false;
	}
	cgm_dbus_disconnect ();
	return true;
}

static bool create_cg(char *cg)
{
	int32_t existed;

	if (!cgm_dbus_connect ())
		return false;
	if (cgmanager_create_sync(NULL, cgroup_manager, "freezer", cg, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "call to create (%s) failed: %s\n", cg, nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		return false;
	}
	cgm_dbus_disconnect ();
	return true;
}

static void thread_create_cg(struct thread_args *args)
{
	char path[MAXPATHLEN];
	int ret;

	ret = snprintf(path, MAXPATHLEN, "%s/t_%d", BASE_CG, args->thread_id);
	if (ret < 0 || ret >= MAXPATHLEN)
		args->return_code = -1;
	fprintf(stderr, "creating %s\n", path);
	if (!create_cg(path))
		args->return_code = -1;
}

static void do_getcg (struct thread_args *args)
{
	char *output = NULL;
	int r = 1;
	void *retval = &r;

	if (!cgm_dbus_connect ())
	{
		fprintf (stderr, "%s: connect failed\n", __func__);
		args->return_code = -1;
		goto out;
	}

	if (cgmanager_get_pid_cgroup_sync
			(NULL, cgroup_manager, "freezer", args->victim_pid, &output) != 0)
	{
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "call to get_pid_cgroup (%s) failed: %s\n", "freezer",
				nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		fprintf (stderr, "%s: exiting early\n", __func__);
		args->return_code = -1;
		goto out;
	}

	cgm_dbus_disconnect ();
	printf ("victim is in %s\n", output);
	nih_free (output);
	args->return_code = 0;
out:
	fprintf(stderr, "movepid %d: %d\n", args->thread_id, args->return_code);
}

static bool movepid(const char *cg, int pid)
{
	if (!cgm_dbus_connect ())
		return false;
	if (cgmanager_move_pid_sync (NULL, cgroup_manager, "freezer", cg, (int32_t) pid) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get ();
		fprintf (stderr, "call to movepid (%s,%d) failed: %s\n", cg, pid, nerr->message);
		nih_free (nerr);
		cgm_dbus_disconnect ();
		return false;
	}
	cgm_dbus_disconnect ();
	return true;
}

static void do_movepid(struct thread_args *args)
{
	char path[MAXPATHLEN];
	int ret;

	ret = snprintf(path, MAXPATHLEN, "%s/t_%d", BASE_CG, args->thread_id);
	if (ret < 0 || ret >= MAXPATHLEN)
		args->return_code = -1;
	if (!movepid(path, args->victim_pid))
		args->return_code = -1;
	fprintf(stderr, "movepid %d: %d\n", args->thread_id, args->return_code);
}

static void do_createcg(struct thread_args *args)
{
	thread_create_cg(args);
	fprintf(stderr, "create %d: %d\n", args->thread_id, args->return_code);
}

static void
do_function (void *arguments)
{
	char name[NAME_MAX + 1];
	struct thread_args *args = arguments;
	struct lxc_container *c;

	if (strcmp (args->mode, "create") == 0)
		do_createcg (args);
	else if (strcmp (args->mode, "getcg") == 0)
		do_getcg (args);
	else if (strcmp (args->mode, "movepid") == 0)
		do_movepid (args);
}

static void *
concurrent (void *arguments)
{
	do_function (arguments);

	return NULL;
}

static bool
detect_libnih_threadsafe (void)
{
#ifdef HAVE_NIH_THREADSAFE
	if (nih_threadsafe ())
		return true;
#endif
	return false;
}

int
main (int argc, char *argv[])
{
	int i, j, iter, opt, v_pid, ret;
	pthread_attr_t attr;
	pthread_t *threads;
	struct thread_args *args;

	char *modes_default[] = { "create", "movepid", "getcg", NULL };
	char **modes = modes_default;

	if (!detect_libnih_threadsafe ())
	{
		fprintf (stderr, "libnih is not compiled with safe threading.\n");
		exit (1);
	}

	pthread_attr_init (&attr);

	if (!create_cg(BASE_CG)) {
		fprintf (stderr, "Failed to create base cgroup\n");
		exit (1);
	}

	v_pid = fork();
	if (v_pid < 0) {
		fprintf (stderr, "Fork failed\n");
		exit (1);
	}
	if (v_pid == 0) {
		pause();
		exit(0);
	}

	while ((opt =
				getopt_long (argc, argv, "j:i:t:d:m:qD", options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'j':
				nthreads = atoi (optarg);
				break;
			case 'i':
				iterations = atoi (optarg);
				break;
			case 'q':
				quiet = 1;
				break;
			case 'D':
				debug = 1;
				break;
			case 'm':
				{
					char *mode_tok, *tok, *saveptr = NULL;

					modes = NULL;
					for (i = 0, mode_tok = optarg;
							(tok = strtok_r (mode_tok, ",", &saveptr));
							i++, mode_tok = NULL)
					{
						modes = realloc (modes, sizeof (*modes) * (i + 2));
						if (!modes)
						{
							perror ("realloc");
							_exit (EXIT_FAILURE);
						}
						modes[i] = tok;
					}
					modes[i] = NULL;
					break;
				}
			default:		/* '?' */
				usage ();
				_exit (EXIT_FAILURE);
		}
	}

	dbus_threads_init_default ();
	threads = malloc (sizeof (*threads) * nthreads);
	args = malloc (sizeof (*args) * nthreads);
	if (threads == NULL || args == NULL)
	{
		fprintf (stderr, "Unable malloc enough memory for %d threads\n",
				nthreads);
		_exit (EXIT_FAILURE);
	}

	ret = EXIT_FAILURE;
	for (iter = 1; iter <= iterations; iter++)
	{
		int fd;
		fd = open ("/", O_RDONLY);
		if (fd < 0)
		{
			fprintf (stderr, "Failed to open /\n");
			continue;
		}

		if (!quiet)
			printf ("\nIteration %d/%d maxfd:%d\n", iter, iterations, fd);
		close (fd);

		for (i = 0; modes[i]; i++)
		{
			if (!quiet)
				printf ("Executing (%s) for %d threads...\n", modes[i], nthreads);
			for (j = 0; j < nthreads; j++)
			{
				memset(&args[j], 0, sizeof(struct thread_args));
				args[j].thread_id  = j;
				args[j].mode       = modes[i];
				args[j].victim_pid = v_pid;

				if (nthreads > 1)
				{
					if (pthread_create
							(&threads[j], &attr, concurrent,
							 (void *) &args[j]) != 0)
					{
						perror ("pthread_create() error");
						goto cleanup;
					}
				}
				else
				{
					do_function (&args[j]);
				}
			}

			for (j = 0; j < nthreads; j++)
			{
				if (nthreads > 1)
				{
					if (pthread_join (threads[j], NULL) != 0)
					{
						perror ("pthread_join() error");
						goto cleanup;
					}
				}
				if (args[j].return_code)
				{
					fprintf (stderr, "thread returned error %d\n",
							args[j].return_code);
					goto cleanup;
				}
			}
		}
	}
	ret = EXIT_SUCCESS;

cleanup:
	free (args);
	free (threads);
	pthread_attr_destroy (&attr);
	kill(v_pid, SIGTERM);
	_exit (EXIT_SUCCESS);
}
