// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019-2020 Icosa Consulting Inc. All Rights Reserved.
 */

#include <stdlib.h>

// Local Includes
#include "config.h"
#include "wireguard.h"

#ifndef WGCLIENT_H
#define WGCLIENT_H
#define WG_API __declspec(dllexport)

#define WG_IF_LEN 16

/* Client Struct */
typedef struct _wgclient
{
	time_t id;
	char memsize[16];
	int result;
	char error[512];
	wg_device device;
} wgclient;

typedef struct _wgstatus
{
	char interface[WG_IF_LEN];
	char peer[WG_KEY_LEN];
	uint64_t rxbytes;
	uint64_t txbytes;
} wgstatus;


extern wgclient *new_client(uint8_t *iface);

/* Key Generators */
extern void get_private_key64(char *privkey, char *error);
extern int get_public_key64(const char *privkey, char *pubkey, char *error);

/* Device Management */
extern int add_wg(uint8_t *iface, uint8_t *privkey, int port, char *error);
extern int del_wg(uint8_t *iface, char *error);
extern int get_wg(uint8_t *iface, void *device, char *error);
extern int set_wg(wg_device *device, char *error);
extern int add_server_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *allowedip, char *error);
extern int add_client_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *endpoint, uint8_t *allowedip, int keepalive, char *error);
extern int del_wg_peer(uint8_t *iface, uint8_t *peerkey, char *error);

#endif /* WGCLIENT_H */
