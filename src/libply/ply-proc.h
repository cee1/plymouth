/* ply-proc.h - random useful functions and macros
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
 * Written By: Ray Strode <rstrode@redhat.com>
 */
#ifndef PLY_PROC_H
#define PLY_PROC_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "ply-event-loop.h"

#ifndef PLY_HIDE_FUNCTION_DECLARATIONS

char *ply_get_process_command_line (pid_t pid);
pid_t ply_get_process_parent_pid (pid_t pid);

int ply_proc_exit_notifier_get (void);
void ply_proc_exit_notifier_put (void);
void ply_proc_exit_notifier_reset (void);
bool ply_proc_exit_notifier_is_attched_event_loop (void);
void ply_proc_exit_notifier_attach_event_loop (ply_event_loop_t *loop);
void ply_proc_exit_notifier_add_exit_cb (ply_event_handler_t cb, void *user_data);
#endif

#endif /* PLY_PROC_H */
/* vim: set ts=4 sw=4 expandtab autoindent cindent cino={.5s,(0: */
