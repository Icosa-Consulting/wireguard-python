
/*
 *		Copyright (C) 2019-2020 Icosa Consulting Inc. All Rights Reserved.
 *		Portions Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>.
*/

/* System Includes */
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Local Includes */
#include "config.h"
#include "ctype.h"
#include "wglib.h"
#include "wireguard.h"

static inline FILE *capture_stderr(FILE *stream)
{
	char *errfile = "/tmp/wg.err";
	FILE *stderr_new;

	stderr_new = freopen(errfile, "wa", stream);
	dup2(fileno(stderr_new), fileno(stream));

	return stderr_new;
}

static inline size_t get_stderr(FILE *stream, char *buffer)
{
	char *outbuffer;
	size_t buffersize = 0;

	int stderr_old = dup(fileno(stderr));
	printf("SIZE: %d\n", stderr_old);

	fflush(stderr);

	buffersize = ftell(stderr);
	fseek(stderr, 0, SEEK_SET);

	if((outbuffer = calloc(1, buffersize + 1)) == NULL) goto exit_error;

	buffersize = fread(outbuffer, buffersize + 1, 1, stream);
	//if(fgets(outbuffer, buffersize, stream) != NULL)
	//{
		printf("BUFFER: %s\n", outbuffer);
		strcpy(buffer, outbuffer);
		free(outbuffer);
	//}

	dup2(stderr_old, fileno(stream));
	fclose(stream);

exit_error:

	return buffersize;
}

static int check_keysize(char *key, char *error)
{
	int keysize = (sizeof(wg_key_b64_string) - 1); //Trim the NULL
	int count = 0;

	while(key[count] != '\0')
		count++;

	if (!(count == keysize))
	{
		sprintf(error, "Peer key size wrong got %d instead of %d", count, keysize);
		return count;
	}

	return 0;
}

static bool check_keyexists(char *peerkey, char *ifname, char *error)
{
	bool result = false;
	char *device_names, *device_name;
	size_t len;

	device_names = wg_list_device_names();
	if (!device_names)
	{
                sprintf(error, "Unable to get device names");
		goto exit_error;
        }

        wg_for_each_device_name(device_names, device_name, len)
        {
		if (strcmp(ifname, device_name) == 0)
		{
			wg_device *device;
			wg_peer *peer;
			wg_key_b64_string key;
			if (wg_get_device(&device, device_name) < 0) { continue; }

			wg_for_each_peer(device, peer)
			{
				wg_key_to_base64(key, peer->public_key);
				result = (strcmp(key, peerkey) == 0);
			}

			wg_free_device(device);
		}
	}

exit_error:

	free(device_names);
	return result;
}
/*
	Get the Peer interface bytes
	Used in status
*/
static char *ifacebytes(uint64_t b)
{
        static char buf[1024];

        if (b < 1024ULL)
                snprintf(buf, sizeof(buf), "%u B", (unsigned int)b);
        else if (b < 1024ULL * 1024ULL)
                snprintf(buf, sizeof(buf), "%.2f KiB", (double)b / 1024);
        else if (b < 1024ULL * 1024ULL * 1024ULL)
                snprintf(buf, sizeof(buf), "%.2f MiB", (double)b / (1024 * 1024));
        else if (b < 1024ULL * 1024ULL * 1024ULL * 1024ULL)
                snprintf(buf, sizeof(buf), "%.2f GiB", (double)b / (1024 * 1024 * 1024));
        else
                snprintf(buf, sizeof(buf), "%.2f TiB", (double)b / (1024 * 1024 * 1024) / 1024);

        return buf;
}

/*
	Get IP Address as string
*/
static char *ip(const struct wg_allowedip *ip)
{
        static char buf[INET6_ADDRSTRLEN + 1];

        memset(buf, 0, INET6_ADDRSTRLEN + 1);
        if (ip->family == AF_INET)
                inet_ntop(AF_INET, &ip->ip4, buf, INET6_ADDRSTRLEN);
        else if (ip->family == AF_INET6)
                inet_ntop(AF_INET6, &ip->ip6, buf, INET6_ADDRSTRLEN);
        return buf;
}

void list_devices(void)
{
	char *device_names, *device_name;
	size_t len;

	device_names = wg_list_device_names();
	if (!device_names)
	{
		perror("Unable to get device names");
	}
	wg_for_each_device_name(device_names, device_name, len)
	{
		wg_device *device;
		wg_peer *peer;
		wg_key_b64_string key;

		if (wg_get_device(&device, device_name) < 0)
		{
			perror("Unable to get device");
			continue;
		}
		if (device->flags & WGDEVICE_HAS_PUBLIC_KEY)
		{
			wg_key_to_base64(key, device->public_key);
			printf("%s has public key %s\n", device_name, key);
		}
		else
			printf("%s has no public key\n", device_name);
		wg_for_each_peer(device, peer)
		{
			wg_key_to_base64(key, peer->public_key);
			printf(" - peer %s\n", key);
		}
		wg_free_device(device);
	}

	free(device_names);
}

/*

*/
static inline int wg_cmd_config(uint8_t *iface, char *argv[], size_t argc, char *error)
{
	int result = 0;
	struct wg_device *device = NULL;

	if(!(device = config_read_cmd(argv, argc)))
	{
		sprintf(error, "Device command Error: [%s]", config_err_msg);
		result = 1;
		goto exit_error;
	}

	/* Set interface name and set device */
	strncpy(device->name, (char *)iface, IFNAMSIZ - 1);
	device->name[IFNAMSIZ - 1] = '\0';

	if((result = set_wg(device, error)) != 0)
	{
		sprintf(error, "Unable to add peer to interface: %s [code: %d]", iface, result);
	} else {
		sprintf(error, "Added peer to interface: %s", iface);
	}

exit_error:

	wg_free_device(device);
	return result;
}

/*
TODO: Abstract Private Key Generator
*/
static wg_key *s_private_key(void)
{
	wg_key key, *result;
	wg_generate_private_key(key);

	memcpy(result, key, sizeof(wg_key));

	return result;
}

/*
TODO: Abstract Public Key Generator
*/
static wg_key *s_public_key(wg_key privatekey)
{
	wg_key key, *result;
	wg_generate_public_key(key, privatekey);

	memcpy(result, key, sizeof(wg_key));

	return result;
}

/*

*/
extern wgclient *new_client(uint8_t *iface)
{
	int result = 1;
	char error[500];

	wgclient *client = (wgclient *)malloc(sizeof *client);
	if (client != NULL)
	{
		memset(&client->error, 0, sizeof(*client->error));
		memset(&client->device, 0, sizeof(wg_device));

		client->id = time(NULL);
		sprintf(client->memsize, "%ld", (sizeof *client));

		if ((result = get_wg(iface, &client->device, error)) != 0)
		{
			sprintf(client->error, "Error %s", error);
			goto exit_error;
		}
		else
		{
			sprintf(client->error, "Success %s", error);
		}

		client->result = result;

#ifdef DEBUG
		printf("IFINDEX %d PORT %d\n", client->device.ifindex, client->device.listen_port);
#endif
	}
	else
	{
		free(client);
	}


exit_error:

	return client;
}

/*

*/
extern void get_private_key64(char *privkey, char *error)
{
	wg_key_b64_string key;
	wg_key temp_key;

	memset(error, 0, sizeof(*error));
	memset(privkey, 0, sizeof(*privkey));

	// Generate Key and convert to base64
	wg_generate_private_key(temp_key);
	if (temp_key == NULL)
	{
		sprintf(error, "Could not generate private key");
		return;
	}

	wg_key_to_base64(key, temp_key);

	// Copy to buffer
	memmove(privkey, key, sizeof(key));
}

/*


*/
extern int get_public_key64(const char *privkey, char *pubkey, char *error)
{
	wg_key_b64_string pub_key_base64, priv_key_base64;
	wg_key temp_private_key, temp_public_key;
	int result = 0;

	if ((result = check_keysize((char*)privkey, error)) != 0)
	{
		goto exit_error;
	}

	memset(error, 0, sizeof(*error));
	memset(pubkey, 0, sizeof(*pubkey));

	strcpy(priv_key_base64, privkey);
	if ((result = wg_key_from_base64(temp_private_key, priv_key_base64)) != 0)
	{
		sprintf(error, "Could not convert private key %s [code: %d]", privkey, result);
		goto exit_error;
	}

	if ((result = wg_key_is_zero(temp_private_key)) != 0)
	{
		sprintf(error, "Private Key is not set [code: %d]", result);
		goto exit_error;
	}

	wg_generate_public_key(temp_public_key, temp_private_key);
	if ((result = wg_key_is_zero(temp_public_key)) != 0)
	{
		sprintf(error, "Public Key is not set [code: %d]", result);
		goto exit_error;
	}

	wg_key_to_base64(pub_key_base64, temp_public_key);

#if DEBUG
	printf("Key: %s Len: %ld\n", pub_key_base64, sizeof(pub_key_base64));
#endif

	// Copy to buffer
	memmove(pubkey, pub_key_base64, sizeof(pub_key_base64));

exit_error:

	return result;
}

/*

*/
extern int add_wg(uint8_t *iface, uint8_t *privkey, int port, char *error)
{
	int result = 0;
	wg_key_b64_string temp_key_base64;

	memset(error, 0, sizeof(*error));

	if ((result = check_keysize((char*)privkey, error)) != 0)
	{
		goto exit_error;
	}

	/* wg_peer new_peer = { .flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS | WGDEVICE_REPLACE_PEERS }; */
	wg_device new_device = {
				.listen_port = port,
				.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT };

	strncpy(new_device.name, (char *)iface, IFNAMSIZ - 1);
	strcpy(temp_key_base64, (char *)privkey);

	if ((result = wg_key_from_base64(new_device.private_key, temp_key_base64)) != 0)
	{
		sprintf(error, "Could not convert device private key [code: %d]", result);
		goto exit_error;
	}

	if ((result = wg_add_device(new_device.name)) < 0)
	{
		sprintf(error, "Unable to add device interface: %s [code: %d]", new_device.name, result);
		goto exit_error;
	}

	if((result = set_wg(&new_device, error)) != 0) goto exit_error;
	sprintf(error, "Added device [%s], result %d", new_device.name, result);

exit_error:

	return result;
}

/*

*/
extern int del_wg(uint8_t *iface, char *error)
{
	int result = 0;
	if ((result = wg_del_device((char *)iface)) < 0)
	{
		sprintf(error, "Unable to delete device interface: %s [code: %d]", iface, result);
	}

	return result;
}

/*

*/
extern int get_wg(uint8_t *iface, void *device, char *error)
{
	int result = 0;
	wg_device *temp_device = NULL;

	if ((result = wg_get_device(&temp_device, (char *)iface)) < 0)
	{
		sprintf(error, "Unable to get device %s [code: %d]", iface, result);
		goto exit_error;
	}

	sprintf(error, "Wireguard device %s retrieved [code: %d]", iface, result);
	memcpy((wg_device *)device, temp_device, sizeof *temp_device);

	wg_free_device(temp_device);

exit_error:

	return result;
}

/*

*/
extern int set_wg(wg_device *device, char *error)
{
	int result = 0;

	if ((result = wg_set_device(device)) < 0)
	{
		sprintf(error, "Unable to set device %s [code: %d]", device->name, result);
#if DEBUG
		printf("NAME: %s PORT: %d\n", device->name, device->listen_port);
		printf("RESULT: %d\n", result);
#endif
		goto exit_error;
	}

exit_error:

	return result;
}

extern int add_server_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *allowedip, char *error)
{
	int idx = 0, result = 1;
	int arsize = 512;

	char *command = malloc(arsize + 1);
	if (command == NULL) return result;

	char *token;
	wg_key key;
	wg_key_b64_string key_b64;

	if ((result = check_keysize((char*)peerkey, error)) != 0)
	{
		goto exit_error;
	}

	memset(error, 0, sizeof(*error));

	strcpy(key_b64, (char*)peerkey);
	if ((result = wg_key_from_base64(key, key_b64)) != 0)
	{
		sprintf(error, "Peer public key error [code: %d]", result);
		goto exit_error;
	}

	static char *wg_argv[4] = { };

	/* Format the command for config_read_cmd in config.c (Hey it was there waiting to be used!) */
	snprintf(command, arsize, "peer %s allowed-ips %s", key_b64, allowedip);
	while ((token = strsep(&command, " "))){ /* Convert string into tokens*/
		if ((wg_argv[idx] = malloc(strlen(token))))
		{
#ifdef DEBUG
			printf("%ld -> %s\n", strlen(token), token);
#endif
			//Don't add null token
			if (token) {
				strcpy(wg_argv[idx], (char*)token);
				idx++;
			}
		}
	}

	size_t cmdsize = sizeof(wg_argv) / sizeof(wg_argv[0]);
	result = wg_cmd_config(iface, wg_argv, cmdsize, error);

exit_error:

	free(command);
	return result;
}
/*

*/
extern int add_client_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *endpoint, uint8_t *allowedip, int keepalive, char *error)
{
	int idx = 0, result = 1;
	int arsize = 512;

	char *command = malloc(arsize + 1);
	if (command == NULL) return result;

	char *token;
	wg_key key;
	wg_key_b64_string key_b64;

	if ((result = check_keysize((char*)peerkey, error)) != 0)
	{
		goto exit_error;
	}

	memset(error, 0, sizeof(*error));

	strcpy(key_b64, (char*)peerkey);
	if ((result = wg_key_from_base64(key, key_b64)) != 0)
	{
		sprintf(error, "Peer public key error [code: %d]", result);
		goto exit_error;
	}

	static char *wg_argv[8] = { };

	/* Format the command for config_read_cmd in config.c (Hey it was there waiting to be used!) */
	snprintf(command, arsize, "peer %s endpoint %s allowed-ips %s persistent-keepalive %d", key_b64, endpoint, allowedip, keepalive);
	while ((token = strsep(&command, " "))){ /* Convert string into tokens*/
		if ((wg_argv[idx] = malloc(strlen(token))))
		{
#ifdef DEBUG
			printf("%ld -> %s\n", strlen(token), token);
#endif
			//Don't add null token
			if (token) {
				strcpy(wg_argv[idx], (char*)token);
				idx++;
			}
		}
	}

	size_t cmdsize = sizeof(wg_argv) / sizeof(wg_argv[0]);
	result = wg_cmd_config(iface, wg_argv, cmdsize, error);

exit_error:

	free(command);
	return result;
}

/*


*/
extern int del_wg_peer(uint8_t *iface, uint8_t *peerkey, char *error)
{
	int idx = 0, result = 1;
	int arsize = 64;
	struct wg_device *device = NULL;
	char *command = malloc(arsize + 1);
	if (command == NULL) return result;

	char *token;
	wg_key key;
	wg_key_b64_string key_b64;

	if ((result = check_keysize((char*)peerkey, error)) != 0)
	{
		goto exit_error;
	}

	memset(error, 0, sizeof(*error));

	if (!check_keyexists((char *)peerkey, (char *)iface, error))
	{
		sprintf(error, "Found no peer key matching %s", peerkey);
		goto exit_error;
	}

	strcpy(key_b64, (char*)peerkey);
	if ((result = wg_key_from_base64(key, key_b64)) != 0)
	{
		sprintf(error, "Peer public key error [code: %d]", result);
		goto exit_error;
	}

	static char *wg_argv[3] = { };

	/* Format the command for config_read_cmd in config.c */
	snprintf(command, arsize, "peer %s remove", key_b64);
	while ((token = strsep(&command, " "))){ /* Convert string into tokens*/
		if ((wg_argv[idx] = malloc(strlen(token))))
		{
#ifdef DEBUG
			printf("%ld -> %s\n", strlen(token), token);
#endif
			strcpy(wg_argv[idx], (char*)token);
			idx++;
		}
	}

	size_t cmdsize = sizeof(wg_argv) / sizeof(wg_argv[0]);
	if(!(device = config_read_cmd(wg_argv, cmdsize)))
	{
		sprintf(error, "Device command Error: [%s]", config_err_msg);
		result = 1;
		goto exit_error;
	}

	/* Set interface name and set device */
	strncpy(device->name, (char *)iface, IFNAMSIZ - 1);
	device->name[IFNAMSIZ - 1] = '\0';

	if((result = set_wg(device, error)) != 0)
	{
		sprintf(error, "Unable to remove peer from interface: %s [code: %d]", iface, result);
	} else {
		sprintf(error, "Deleted peer from interface: %s [code: %d]", iface, result);
	}

	wg_free_device(device);

exit_error:

	free(command);
	return result;

}
