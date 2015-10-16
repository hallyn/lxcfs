/*
 * Copyright © 2015 Canonical Limited
 *
 * Authors:
 *   Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

#include <glib.h>
#include <gio/gio.h>

#define CGM_DBUS_ADDRESS          "unix:path=/sys/fs/cgroup/cgmanager/sock"
#define CGM_REQUIRED_VERSION      9  // we need list_keys

static __thread GDBusConnection *cgroup_manager = NULL;

static void cgm_dbus_disconnect(void *)
{
       GError *error = NULL;

       if (cgroup_manager) {
	       if (!g_dbus_connection_flush_sync(cgroup_manager, NULL, &error)) {
		       g_warning("failed to flush connection: %s."
		           "Use G_DBUS_DEBUG=message for more info.", error->message);
		       g_error_free(error);
	       }
	       if (!g_dbus_connection_close(cgroup_manager, NULL)) {
		       g_warning("failed to close connection: %s."
		           "Use G_DBUS_DEBUG=message for more info.", error->message);
		       g_error_free(error);
	       }
       }
       cgroup_manager = NULL;
}

static bool cgm_dbus_connect(void)
{
	GDBusConnection *connection;
	GVariant *reply;
	GVariant *version;
	GError *error = NULL;

	if (cgroup_manager)
		return true;

	connection = g_dbus_connection_new_for_address_sync (CGM_DBUS_ADDRESS,
			G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
			NULL, NULL, &error);
	if (!connection) {
		g_warning("Could not connect to cgmanager: %s\n"
			"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
		return false;

	reply = g_dbus_connection_call_sync (connection, NULL, "/org/linuxcontainers/cgmanager",
			"org.freedesktop.DBus.Properties", "Get",
			g_variant_new ("(ss)", "org.linuxcontainers.cgmanager0_0", "api_version"),
			G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!reply)
	{
		g_warning("Failed to get cgmanager api version: %s\n"
			"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
		g_object_unref (connection);
		return false;
	}
	g_variant_get (reply, "(v)", &version);
	g_variant_unref (reply);
	if (!g_variant_is_of_type (version, G_VARIANT_TYPE_INT32) || g_variant_get_int32 (version) < CGM_REQUIRED_VERSION)
	{
		g_warning("Cgmanager does not meet minimal API version");
		g_object_unref (connection);
		g_variant_unref (version);
		return false;
	}
	g_variant_unref (version);
	pthread_cleanup_push(cgm_dbus_disconnect, NULL);

	return true;
}

bool cgm_get_controllers(char ***contrls)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_controllers_sync(NULL, cgroup_manager, contrls) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_controllers failed: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_list_keys(const char *controller, const char *cgroup, struct cgm_keys ***keys)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_keys_sync(NULL, cgroup_manager, controller, cgroup,
				(CgmanagerListKeysOutputElement ***)keys) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_keys (%s:%s) failed: %s\n", controller, cgroup, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_list_children(const char *controller, const char *cgroup, char ***list)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_children_sync(NULL, cgroup_manager, controller, cgroup, list) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_children (%s:%s) failed: %s\n", controller, cgroup, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

char *cgm_get_pid_cgroup(pid_t pid, const char *controller)
{
	char *output = NULL;

	if (!cgm_dbus_connect()) {
		return NULL;
	}

	if ( cgmanager_get_pid_cgroup_sync(NULL, cgroup_manager, controller, pid, &output) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to get_pid_cgroup (%s) failed: %s\n", controller, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return NULL;
	}

	cgm_dbus_disconnect();
	return output;
}

bool cgm_escape_cgroup(void)
{
	return cgcall("MovePidAbs", g_variant_new("(ssi)", "all", "/", getpid()),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_move_pid(const char *controller, const char *cgroup, pid_t pid)
{
	return cgcall("MovePid", g_variant_new("(ssi)", controller, cgroup, pid),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_get_value(const char *controller, const char *cgroup, const char *file,
		char **value)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_get_value_sync(NULL, cgroup_manager, controller, cgroup,
			file, value) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to get_value (%s:%s, %s) failed: %s\n", controller, cgroup, file, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value)
{
	return cgcall("SetValue", g_variant_new("(ssss)", controller, cgroup, file, value),
			G_VARIANT_TYPE_UNIT, NULL);
}

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

bool cgm_create(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	int32_t e;
	pid_t pid = fork();

	if (pid) {
		if (wait_for_pid(pid) != 0)
			return false;
		return true;
	}

	if (setgroups(0, NULL))
		_exit(1);
	if (setresgid(gid, gid, gid))
		_exit(1);
	if (setresuid(uid, uid, uid))
		_exit(1);

	if (!cgcall("Create", g_variant_new("(ss)", controller, cg),
				G_VARIANT_TYPE ("(i)"), NULL))
		_exit(1);

	_exit(0);
}

bool cgm_chown_file(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	return cgcall("Chown", g_variant_new("(ssii)", controller, cg, uid, gid),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_chmod_file(const char *controller, const char *file, mode_t mode)
{
	return cgcall("Chmod", g_variant_new("(sssi)", controller, file, "", mode), G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_remove(const char *controller, const char *cg)
{
	int32_t r = 0, e;

	return cgcall("Remove", g_variant_new ("(ssi)", "all", path, 1), G_VARIANT_TYPE ("(i)"), NULL);
}
