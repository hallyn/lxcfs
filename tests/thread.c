/*
 * Thiis is based on lxcfs.c, cgmanager,c and some of
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
#include <sys/socket.h>
#include <sys/mount.h>
#include <wait.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <dbus/dbus.h>
#include "../config.h"

/*
 * TODO - return value should denote whether child exited with failure
 * so callers can return errors.  Esp read/write of tasks and cgroup.procs
 */
static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static int nthreads = 5;
static int iterations = 1;
static int debug = 0;
static int quiet = 0;
static int delay = 0;

static const struct option options[] = {
    { "threads",     required_argument, NULL, 'j' },
    { "iterations",  required_argument, NULL, 'i' },
    { "modes",       required_argument, NULL, 'm' },
    { "quiet",       no_argument,       NULL, 'q' },
    { "debug",       no_argument,       NULL, 'D' },
    { "help",        no_argument,       NULL, '?' },
    { 0, 0, 0, 0 },
};

static void usage(void) {
    fprintf(stderr, "Usage: lxc-test-concurrent [OPTION]...\n\n"
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

struct thread_args {
    int thread_id;
    int return_code;
    const char *mode;
};

static DBusConnection *connection;
static int32_t api_version;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_lock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

void lock(void) {
	lock_mutex(&mutex);
}
void unlock(void) {
	unlock_mutex(&mutex);
}

int refcount;

static void cgm_dbus_disconnect(void)
{
	lock();
	if (--refcount) {
		unlock();
		return;
	}
	if (connection) {
		dbus_connection_flush(connection);
		dbus_connection_close(connection);
		dbus_connection_unref(connection);
	}
	connection = NULL;
	unlock();
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static bool cgm_dbus_connect(void)
{
	DBusError dbus_error;

	lock();
	if (connection) {
		refcount++;
		unlock();
		return true;
	}
	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		fprintf(stderr, "Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		unlock();
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	refcount++;
	unlock();

	return true;
}

void do_getcg(void) {
	char *output = NULL;
	int r = 1;
	void *retval = &r;
	const char *controller = "freezer";

	if (!cgm_dbus_connect()) {
		fprintf(stderr, "exiting early\n");
		pthread_exit(retval);
		_exit(1);
	}

	DBusMessage *message = NULL, *reply = NULL;
	DBusMessageIter iter;
	message = dbus_message_new_method_call(dbus_bus_get_unique_name(connection),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "GetPidCgroup");
	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING,
                                              &controller)) {
		fprintf(stderr, "error appending controller to msg\n");
		pthread_exit(retval);
		_exit(1);
        }

	int32_t pid = getpid();
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32,
                                              &pid)) {
		fprintf(stderr, "error appending pid to msg\n");
		pthread_exit(retval);
		_exit(1);
        }

	DBusError dbus_error;
	dbus_error_init(&dbus_error);

	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &dbus_error);
	if (! reply) {
		dbus_message_unref (message);
		fprintf(stderr, "dbus error: %s: %s\n", dbus_error.name, dbus_error.message);
		dbus_error_free (&dbus_error);
		pthread_exit(retval);
		_exit(1);
	}
	dbus_message_unref (message);

	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		dbus_message_unref(reply);
		fprintf(stderr, "bad dbus reply\n");
		pthread_exit(retval);
		_exit(1);
	}
	const char *dbus_str;
	dbus_message_iter_get_basic(&iter, &dbus_str);
	output = malloc(strlen(dbus_str)+1);
	if (!output) {
		dbus_message_unref(reply);
		fprintf(stderr, "out of memory\n");
		pthread_exit(retval);
		_exit(1);
	}
	strcpy(output, dbus_str);
	dbus_message_unref(reply);

	cgm_dbus_disconnect();
	printf("I'm in %s\n", output);
	free(output);
}

static void do_function(void *arguments)
{
    char name[NAME_MAX+1];
    struct thread_args *args = arguments;
    struct lxc_container *c;

    if (strcmp(args->mode, "getcg") == 0) {
	    do_getcg();
    }
}

static void *concurrent(void *arguments)
{
    do_function(arguments);
    pthread_exit(NULL);

    return NULL;
}

int main(int argc, char *argv[]) {
    int i, j, iter, opt;
    pthread_attr_t attr;
    pthread_t *threads;
    struct thread_args *args;

    //char *modes_default[] = {"create", "movepid", "getcg"};
    char *modes_default[] = {"getcg"};
    char **modes = modes_default;

    pthread_attr_init(&attr);

    while ((opt = getopt_long(argc, argv, "j:i:t:d:m:qD", options, NULL)) != -1) {
        switch(opt) {
        case 'j':
            nthreads = atoi(optarg);
            break;
        case 'i':
            iterations = atoi(optarg);
            break;
        case 'q':
            quiet = 1;
            break;
	case 'D':
	    debug = 1;
	    break;
        case 'm': {
            char *mode_tok, *tok, *saveptr = NULL;

            modes = NULL;
            for (i = 0, mode_tok = optarg;
                 (tok = strtok_r(mode_tok, ",", &saveptr));
                i++, mode_tok = NULL) {
                modes = realloc(modes, sizeof(*modes) * (i+2));
                if (!modes) {
                    perror("realloc");
                    _exit(EXIT_FAILURE);
                }
                modes[i] = tok;
	    }
            modes[i] = NULL;
            break;
	}
        default: /* '?' */
            usage();
            _exit(EXIT_FAILURE);
        }
    }

    dbus_threads_init_default();
    threads = malloc(sizeof(*threads) * nthreads);
    args = malloc(sizeof(*args) * nthreads);
    if (threads == NULL || args == NULL) {
        fprintf(stderr, "Unable malloc enough memory for %d threads\n", nthreads);
        _exit(EXIT_FAILURE);
    }

    for (iter = 1; iter <= iterations; iter++) {
        int fd;
        fd = open("/", O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Failed to open /\n");
            continue;
        }

        if (!quiet)
            printf("\nIteration %d/%d maxfd:%d\n", iter, iterations, fd);
        close(fd);

        for (i = 0; modes[i];i++) {
            if (!quiet)
                printf("Executing (%s) for %d threads...\n", modes[i], nthreads);
            for (j = 0; j < nthreads; j++) {
                args[j].thread_id = j;
                args[j].mode = modes[i];

                if (nthreads > 1) {
                    if (pthread_create(&threads[j], &attr, concurrent, (void *) &args[j]) != 0) {
                        perror("pthread_create() error");
                        _exit(EXIT_FAILURE);
                    }
                } else {
                    do_function(&args[j]);
                }
            }

            for (j = 0; j < nthreads; j++) {
                if (nthreads > 1) {
                    if (pthread_join(threads[j], NULL) != 0) {
                        perror("pthread_join() error");
                        _exit(EXIT_FAILURE);
                    }
                }
                if (args[j].return_code) {
                    fprintf(stderr, "thread returned error %d\n", args[j].return_code);
                    _exit(EXIT_FAILURE);
                }
            }
        }
    }

    free(args);
    free(threads);
    pthread_attr_destroy(&attr);
    _exit(EXIT_SUCCESS);
}
