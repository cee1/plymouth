/* ply-utils.c -  random useful functions and macros
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Written by: Ray Strode <rstrode@redhat.com>
 */
#include <config.h>

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <linux/cn_proc.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/filter.h>
#include <assert.h>

#include "ply-list.h"
#include "ply-logger.h"
#include "ply-proc.h"

#ifndef PLY_MAX_COMMAND_LINE_SIZE
#define PLY_MAX_COMMAND_LINE_SIZE 4096
#endif

static struct {
  int ref_cnt;
  int sock_fd;
  ply_fd_watch_t *watch;
  ply_event_loop_t *loop;
  int max_pid;
  int nr_pids;
  ply_list_t *exit_cbs;
} proc_exit_notifier;

union sockaddr_union 
{
  struct sockaddr sa;
  struct sockaddr_nl nl;
};


struct cb_closure
{
  ply_event_handler_t callback;
  void *user_data;
};

static bool
proc_exit_notifier_update_filter (int sock_fd)
{
  struct sock_fprog fprog;
  /* const int ret_cmd_idx = 8; */
  const int drop_cmd_idx = 9;
  struct sock_filter filter[] = {
    /* 0-1: check whether is a netlink message of type "NLMSG_DONE" */
    BPF_STMT (BPF_LD|BPF_H|BPF_ABS,
              offsetof (struct nlmsghdr, nlmsg_type)),
    BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
              htons (NLMSG_DONE), 0, drop_cmd_idx-1-1),

    /* 2-5: check whether is a proc connector message */
    BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
              NLMSG_LENGTH (0) + offsetof (struct cn_msg, id)
                               + offsetof (struct cb_id, idx)),
    BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
              htonl (CN_IDX_PROC), 0, drop_cmd_idx-3-1),
    BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
              NLMSG_LENGTH (0) + offsetof (struct cn_msg, id)
                               + offsetof (struct cb_id, val)),
    BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
              htonl (CN_VAL_PROC), 0, drop_cmd_idx-5-1),

    /* 6-7: filter out proc connector message other than 'PROC_EVENT_EXIT' */
    BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
              NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
                               + offsetof (struct proc_event, what)),
    BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
              htonl (PROC_EVENT_EXIT), 0, drop_cmd_idx-7-1),

    /* 8: the @ret_cmd_idx */
    BPF_STMT (BPF_RET|BPF_K, 0xffffffff),
    /* 9: the @drop_cmd_idx */
    BPF_STMT (BPF_RET|BPF_K, 0),
  };
  
  fprog.filter = filter;
  fprog.len = 10;
  
  if (setsockopt (sock_fd, SOL_SOCKET,
                  SO_ATTACH_FILTER, &fprog, sizeof (fprog)) < 0)
    {
      ply_error ("Failed to set socket filter: %m");
      return false;
    }

  return true;
}

int
ply_proc_exit_notifier_get (void)
{
  int sock_fd = -1;
  if (proc_exit_notifier.ref_cnt++ == 0)
    {
      union sockaddr_union addr;
      struct iovec iov[3];
      struct nlmsghdr *nlmsghdrbuf = alloca (NLMSG_LENGTH (0));
      struct nlmsghdr *nlmsghdr = nlmsghdrbuf;
      struct cn_msg cn_msg;
      enum proc_cn_mcast_op op;

      sock_fd = socket (PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        NETLINK_CONNECTOR);
      if (sock_fd < 0)
        {
          ply_error ("Failed to open proc connector netlink socket: %m");
          goto error;
        }

      proc_exit_notifier_update_filter (sock_fd);

      addr.nl.nl_family = AF_NETLINK;
      addr.nl.nl_pid = getpid ();
      addr.nl.nl_groups = CN_IDX_PROC;

      if (bind (sock_fd, &addr.sa, sizeof (addr.nl)) < 0)
        {
          ply_error ("Failed to bind proc connector netlink addr: %m");
          goto error;
        }
      
      nlmsghdr->nlmsg_len = NLMSG_LENGTH (sizeof (cn_msg) + sizeof (op));
      nlmsghdr->nlmsg_type = NLMSG_DONE;
      nlmsghdr->nlmsg_flags = 0;
      nlmsghdr->nlmsg_seq = 0;
      nlmsghdr->nlmsg_pid = getpid ();

      iov[0].iov_base = nlmsghdrbuf;
      iov[0].iov_len = NLMSG_LENGTH (0);

      cn_msg.id.idx = CN_IDX_PROC;
      cn_msg.id.val = CN_VAL_PROC;
      cn_msg.seq = 0;
      cn_msg.ack = 0;
      cn_msg.len = sizeof (op);

      iov[1].iov_base = &cn_msg;
      iov[1].iov_len = sizeof (cn_msg);

      op = PROC_CN_MCAST_LISTEN;

      iov[2].iov_base = &op;
      iov[2].iov_len = sizeof (op);

      while (writev (sock_fd, iov, 3) < 0)
        {
          if (errno == EINTR || errno == EAGAIN)
            continue;
          ply_error ("Failed to start proc connector: %m");
          goto error;
        }

      proc_exit_notifier.sock_fd = sock_fd;
      proc_exit_notifier.exit_cbs = ply_list_new ();
    }

  return proc_exit_notifier.sock_fd;

error:
  if (sock_fd >= 0)
    while (close (sock_fd) < 0 && errno == EINTR) {}

  return -1;
}

static void
_ply_proc_exit_notifier_reset (void)
{
  ply_list_node_t *n;

  proc_exit_notifier.ref_cnt = 0; 

  /* detach from loop */
  if (ply_proc_exit_notifier_is_attched_event_loop ())
    ply_proc_exit_notifier_attach_event_loop (NULL);

  /* close netlink socket */
  while (close (proc_exit_notifier.sock_fd) < 0 &&
         errno == EINTR) {}
  proc_exit_notifier.sock_fd = -1;

  /* remove exit callbacks */
  n = ply_list_get_first_node (proc_exit_notifier.exit_cbs);
  for (; n; n = ply_list_get_next_node (proc_exit_notifier.exit_cbs, n))
      free (ply_list_node_get_data (n));
  ply_list_free (proc_exit_notifier.exit_cbs);
  proc_exit_notifier.exit_cbs = NULL;
}

void
ply_proc_exit_notifier_put (void)
{
  if (proc_exit_notifier.ref_cnt == 0)
    return;

  if (proc_exit_notifier.ref_cnt-- == 1)
    _ply_proc_exit_notifier_reset ();
}

void
ply_proc_exit_notifier_reset (void)
{
  if (proc_exit_notifier.ref_cnt == 0)
    return;

  _ply_proc_exit_notifier_reset ();
}

bool
ply_proc_exit_notifier_is_attched_event_loop (void)
{
  return proc_exit_notifier.loop != NULL;
}

static void
on_proc_exit (void)
{
  union sockaddr_union addr;
  socklen_t addr_len = sizeof (addr.nl);

#define BUF_SIZE 4096
  struct nlmsghdr *buf = alloca (BUF_SIZE);
  struct nlmsghdr *nlmsghdr;
  ssize_t len;

  len = recvfrom (proc_exit_notifier.sock_fd,
                  buf, BUF_SIZE, 0,
                  &addr.sa, &addr_len);
  if (addr.nl.nl_pid != 0)
    return;
  if (len < 0)
    return;

  for (nlmsghdr = buf; NLMSG_OK (nlmsghdr, (size_t) len);
       nlmsghdr = NLMSG_NEXT (nlmsghdr, len))
    {
      struct cn_msg *cn_msg;
      struct proc_event *ev;

      if ((nlmsghdr->nlmsg_type == NLMSG_ERROR) ||
          (nlmsghdr->nlmsg_type == NLMSG_NOOP))
        continue;

      cn_msg = NLMSG_DATA (nlmsghdr);
      if ((cn_msg->id.idx != CN_IDX_PROC) ||
          (cn_msg->id.val != CN_VAL_PROC))
        continue;

      ev = (struct proc_event *) cn_msg->data;
      switch (ev->what) 
        {
          case PROC_EVENT_EXIT:
            {
              ply_list_node_t *n = ply_list_get_first_node (proc_exit_notifier.exit_cbs);
              for (; n; n = ply_list_get_next_node (proc_exit_notifier.exit_cbs, n))
                {
                  struct cb_closure *cbc = ply_list_node_get_data (n);
                  cbc->callback (cbc->user_data, ev->event_data.exit.process_pid);
                }
            }
            break;
          default:
            break;
        }
    }
}

static void
on_hangup (void)
{
  ply_error ("Netlink socket hangup!");
}

void
ply_proc_exit_notifier_attach_event_loop (ply_event_loop_t *loop)
{
  if (loop == NULL)
    {
      if (proc_exit_notifier.loop)
        {
          assert (proc_exit_notifier.watch);
          ply_event_loop_stop_watching_fd (proc_exit_notifier.loop,
                                           proc_exit_notifier.watch);
        }
      proc_exit_notifier.loop = NULL;
      proc_exit_notifier.watch = NULL;

      return;
    }

  assert (!proc_exit_notifier.loop);
  assert (!proc_exit_notifier.watch);

  proc_exit_notifier.loop = loop;
  proc_exit_notifier.watch = ply_event_loop_watch_fd (
      proc_exit_notifier.loop, proc_exit_notifier.sock_fd,
      PLY_EVENT_LOOP_FD_STATUS_HAS_DATA,
      (ply_event_handler_t) on_proc_exit,
      (ply_event_handler_t) on_hangup,
      NULL);
}

void
ply_proc_exit_notifier_add_exit_cb (ply_event_handler_t cb, void *user_data)
{
  struct cb_closure *cbc;
  assert (cb);

  cbc = malloc (sizeof (struct cb_closure));

  cbc->callback = cb;
  cbc->user_data = user_data;

  ply_list_append_data (proc_exit_notifier.exit_cbs, cbc);
}

char *
ply_get_process_command_line (pid_t pid)
{
  char *path;
  char *command_line;
  ssize_t bytes_read;
  int fd;
  ssize_t i;

  path = NULL;
  command_line = NULL;

  assert (asprintf (&path, "/proc/%ld/cmdline", (long) pid) > 0);

  fd = open (path, O_RDONLY);

  if (fd < 0)
    {
      ply_trace ("Could not open %s: %m", path);
      goto error;
    }

  command_line = calloc (PLY_MAX_COMMAND_LINE_SIZE, sizeof (char));
  bytes_read = read (fd, command_line, PLY_MAX_COMMAND_LINE_SIZE - 1);
  if (bytes_read < 0)
    {
      ply_trace ("Could not read %s: %m", path);
      close (fd);
      goto error;
    }
  close (fd);
  free (path);

  for (i = 0; i < bytes_read - 1; i++)
    {
      if (command_line[i] == '\0')
        command_line[i] = ' ';
    }
  command_line[i] = '\0';

  return command_line;

error:
  free (path);
  free (command_line);
  return NULL;
}

pid_t
ply_get_process_parent_pid (pid_t pid)
{
  char *path;
  FILE *fp;
  int ppid;

  assert (asprintf (&path, "/proc/%ld/stat", (long) pid) > 0);

  ppid = 0;
  fp = fopen (path, "r");

  if (fp == NULL)
    {
      ply_trace ("Could not open %s: %m", path);
      goto out;
    }

  if (fscanf (fp, "%*d %*s %*c %d", &ppid) != 1)
    {
      ply_trace ("Could not parse %s: %m", path);
      goto out;
    }

  if (ppid <= 0)
    {
      ply_trace ("%s is returning invalid parent pid %d", path, ppid);
      ppid = 0;
      goto out;
    }

out:
  free (path);

  if (fp != NULL)
    fclose (fp);

  return (pid_t) ppid;
}


/* vim: set ts=4 sw=4 expandtab autoindent cindent cino={.5s,(0: */
