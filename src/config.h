/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights
 * Reserved.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

char *config_err_msg;

struct wg_device;
struct wg_peer;
struct wg_allowedip;

struct config_ctx
{
	struct wg_device *device;
	struct wg_peer *last_peer;
	struct wg_allowedip *last_allowedip;
	bool is_peer_section, is_device_section;
};

struct wg_device *config_read_cmd(char *argv[], int argc);
bool config_read_init(struct config_ctx *ctx, bool append);
bool config_read_line(struct config_ctx *ctx, const char *line);
struct wg_device *config_read_finish(struct config_ctx *ctx);

#define for_each_wgpeer(__dev, __peer) for ((__peer) = (__dev)->first_peer; (__peer); (__peer) = (__peer)->next_peer)
#define for_each_wgallowedip(__peer, __allowedip)                                                                      \
	for ((__allowedip) = (__peer)->first_allowedip; (__allowedip); (__allowedip) = (__allowedip)->next_allowedip)

#endif
