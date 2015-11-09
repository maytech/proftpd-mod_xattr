/*
 * ProFTPD: mod_xattr -- a module for reading files/directories extended
 * attributes to ENV variable.
 *
 * Copyright (c) 2015 Bohdan Kmit
 * Copyright (c) 2006-2015 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_xattr, contrib software for proftpd 1.2.x/1.3.x and above.
 * For more information contact Bohdan Kmit <bkmit@maytech.net>.
 *
 */

#include "conf.h"
#include "mod_tls.h"
#include <sys/types.h>
#include <sys/xattr.h>

#define MOD_XATTR_VERSION  "mod_xattr/0.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030500
#error "ProFTPD 1.3.5 or later required"
#endif

module xattr_module;

static unsigned int xattr_engine = TRUE;
static const char *trace_channel = "xattr";
static pr_table_t *xattr_table = NULL;
static pool *xattr_pool;

/* Configuration handlers */

/* usage: XattrEngine on|off */
MODRET set_xattrengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof (int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: XattrList xattr.name1 xattr.name2 ... */
MODRET set_xattrlist(cmd_rec *cmd) {
  int i;
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    add_config_param_str(cmd->argv[0], 1, cmd->argv[i]);
  }

  return PR_HANDLED(cmd);
}

/* Event handlers */

#if defined(PR_SHARED_MODULE)

static void xattr_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_xattr.c", (const char *) event_data) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&xattr_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void xattr_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  const char *xattr_name;

  c = find_config(main_server->conf, CONF_PARAM, "XattrEngine", TRUE);
  if (c &&
          *((unsigned int *) c->argv[0]) == FALSE) {
    xattr_engine = FALSE;
  }
  pr_trace_msg(trace_channel, 8, "XattrEngine = %s", xattr_engine ? "on" : "off");

  if (xattr_table) {
    pr_table_empty(xattr_table);
    pr_table_free(xattr_table);
  }

  if (!xattr_engine) {
    return;
  }

  xattr_table = pr_table_alloc(permanent_pool, 0);
  if (xattr_table) {
    c = find_config(main_server->conf, CONF_PARAM, "XattrList", TRUE);
    while (c) {
      pr_signals_handle();
      if (c->argc == 1) {
        xattr_name = (char *) c->argv[0];
        pr_trace_msg(trace_channel, 9, " will retrive '%s'", xattr_name);
        if (pr_table_add(xattr_table, xattr_name, (void *) "1", 0) == -1) {
          pr_log_debug(DEBUG0, MOD_XATTR_VERSION
                  ": error saving '%s' to table: %s", xattr_name, strerror(errno));
        }
      }
      c = find_config_next(c, c->next, CONF_PARAM, "XattrList", FALSE);
    }
  } else {
    pr_log_debug(DEBUG0, MOD_XATTR_VERSION
            ": error allocating extened attributes map table: %s", strerror(errno));
  }

  return;
}
/* reinitalize our sub-pool if filename change to avoid memory leaks */
static void xattr_reinit_pool(void) {
  const char *xattr_name;

  if (xattr_table) {
    pr_table_rewind(xattr_table);
    while ((xattr_name = pr_table_next(xattr_table))) {
      pr_signals_handle();
      pr_table_remove(session.notes, xattr_name, NULL);
    }
  }
  if (xattr_pool) {
    destroy_pool(xattr_pool);
  }
  xattr_pool = make_sub_pool(session.pool);
}

static void xattr_sess_reinit_ev(const void *event_data, void *user_data) {
  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&xattr_module, "core.session-reinit",
          xattr_sess_reinit_ev);

  xattr_reinit_pool();
  xattr_engine = TRUE;
}

static const char *xattr_retrive_path (cmd_rec *cmd)
{
  char *path;
  if ((path = session.xfer.path ? session.xfer.path : cmd->arg)) {
    pr_trace_msg(trace_channel, 9, "path='%s' arg='%s' final='%s'", 
            session.xfer.path, cmd->arg, path);
  }
  return path;
}

#define XATTR_MAX_XATTR_SIZE 2048
static void xattr_retrive_do(cmd_rec *cmd, const char *path, const char *xattr_name) {
  char xattr_value[XATTR_MAX_XATTR_SIZE];
  ssize_t xattr_value_len;

  pr_trace_msg(trace_channel, 9, " retriving '%s' for '%s'", xattr_name, path);
  if ((xattr_value_len = getxattr(path, xattr_name, xattr_value, sizeof(xattr_value) - 1)) == -1) {
    if (errno != ENOENT && errno != ENODATA) {
      pr_log_debug(DEBUG0, MOD_XATTR_VERSION
            ": error getting xattr '%s' for path '%s': %s", xattr_name, 
            path, strerror(errno));
    }
    pr_table_remove(session.notes, xattr_name, NULL);
    pr_trace_msg(trace_channel, 8, "'%s': remove '%s'", path, xattr_name);
  } else {
    xattr_value[xattr_value_len] = '\0';
    if (pr_table_set(session.notes, xattr_name, pstrdup(xattr_pool, xattr_value), 0) == -1) {
      pr_table_add_dup(session.notes, xattr_name, pstrdup(xattr_pool, xattr_value), 0);
    }
    pr_trace_msg(trace_channel, 8, "'%s': '%s'='%s'", path, xattr_name, xattr_value);
  }
}

/* Command handlers
 */

MODRET xattr_retrive_pre(cmd_rec *cmd) {
  const char *xattr_name;
  const char *prev_path;
  const char *path;

  if (!xattr_engine) {
    return PR_DECLINED(cmd);
  }
  pr_trace_msg(trace_channel, 8, "xattr_retrive_pre called for '%s' on '%s'",
          (char*) (cmd->argv[0]), cmd->argc >= 2 ? cmd->arg : "");
  if (!xattr_table || !pr_table_count(xattr_table)) {
    return PR_DECLINED(cmd);
  }
  path = xattr_retrive_path(cmd);
  if (!path) {
    return PR_DECLINED(cmd);
  }
  prev_path = pr_table_get(session.notes, "mod_xattr.prev-path", NULL);
  if (prev_path && strcmp(path, prev_path) == 0) {
    return PR_DECLINED(cmd);
  }
  xattr_reinit_pool();
  pr_table_rewind(xattr_table);
  while ((xattr_name = pr_table_next(xattr_table))) {
    pr_signals_handle();
    xattr_retrive_do(cmd, path, xattr_name);
  }
  if (pr_table_set(session.notes, "mod_xattr.prev-path", pstrdup(xattr_pool, path), 0) == -1)
    pr_table_add(session.notes, "mod_xattr.prev-path", (void *)pstrdup(xattr_pool, path), 0);
  if (!pr_table_get(cmd->notes, "mod_xattr.pre-filled", NULL)) {
    pr_table_add(cmd->notes, "mod_xattr.pre-filled", "1", 1);
  }
  return PR_DECLINED(cmd);
}

MODRET xattr_retrive_post(cmd_rec *cmd) {
  const char *xattr_name;
  const char *prev_path;
  const char *path;
  
  if (!xattr_engine) {
    return PR_DECLINED(cmd);
  }
  pr_trace_msg(trace_channel, 8, "xattr_retrive_post called for '%s' on '%s'",
          (char*) (cmd->argv[0]), cmd->argc >= 2 ? cmd->arg : "");
  if (!xattr_table || !pr_table_count(xattr_table)) {
    return PR_DECLINED(cmd);
  }
  if (!pr_table_remove(cmd->notes, "mod_xattr.pre-filled", NULL)) {
    path = xattr_retrive_path(cmd);
    if (!path) {
      return PR_DECLINED(cmd);
    }
    prev_path = pr_table_get(session.notes, "mod_xattr.prev-path", NULL);
    if (prev_path && strcmp(path, prev_path) == 0) {
      return PR_DECLINED(cmd);
    }
    xattr_reinit_pool();
    pr_table_rewind(xattr_table);
    while ((xattr_name = pr_table_next(xattr_table))) {
      pr_signals_handle();
      xattr_retrive_do(cmd, path, xattr_name);
    }
    if (pr_table_set(session.notes, "mod_xattr.prev-path", pstrdup(xattr_pool, path), 0) == -1)
      pr_table_add(session.notes, "mod_xattr.prev-path", (void *)pstrdup(xattr_pool, path), 0);
  }
  return PR_DECLINED(cmd);
}

/* Initialization functions
 */

static int xattr_init(void) {

#if defined(PR_SHARED_MODULE)
          pr_event_register(&xattr_module, "core.module-unload",
          xattr_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
          pr_event_register(&xattr_module, "core.postparse", xattr_postparse_ev, NULL);

  return 0;
}

static int xattr_sess_init(void) {
  config_rec *c;

  pr_event_register(&xattr_module, "core.session-reinit", xattr_sess_reinit_ev, NULL);

  if (!xattr_engine) {
    return 0;
  }

  /* Look up DelayEngine again, as it may have been disabled in an
   * <IfClass> section.
   */
  c = find_config(main_server->conf, CONF_PARAM, "XattrEngine", FALSE);
  if (c != NULL && *((unsigned int *) c->argv[0]) == FALSE) {
    xattr_engine = FALSE;
  }

  if (!xattr_engine) {
    return 0;
  }
  xattr_reinit_pool();

  return 0;
}

/* Module API tables
 */

static conftable xattr_conftab[] = {
  { "XattrEngine", set_xattrengine, NULL},
  { "XattrList", set_xattrlist, NULL},
  { NULL}
};

static cmdtable xattr_cmdtab[] = {
  { PRE_CMD, C_DELE, G_NONE, xattr_retrive_pre, FALSE, FALSE},
  { PRE_CMD, C_RMD, G_NONE, xattr_retrive_pre, FALSE, FALSE},
  { PRE_CMD, C_XRMD, G_NONE, xattr_retrive_pre, FALSE, FALSE},
  { PRE_CMD, C_RNFR, G_NONE, xattr_retrive_pre, FALSE, FALSE},

  { POST_CMD, C_ANY, G_NONE, xattr_retrive_post, FALSE, FALSE},
  { POST_CMD_ERR, C_ANY, G_NONE, xattr_retrive_post, FALSE, FALSE},

  { 0, NULL}
};

module xattr_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "xattr",

  /* Module configuration handler table */
  xattr_conftab,

  /* Module command handler table */
  xattr_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  xattr_init,

  /* Session initialization function */
  xattr_sess_init,

  /* Module version */
  MOD_XATTR_VERSION
};
