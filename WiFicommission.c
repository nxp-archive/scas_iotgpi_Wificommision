/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */
//////////////////////////////////////////////////////////////
// Copyright(c) 2017, Volansys Technologies
//
// Description:
/// \file WiFicommission.c
/// \brief This file contains code for transfer network credentials using BLE.
//
//
//////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// Includes
///////////////////////////////////////////////////////////////////////////////

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>


#include "gwutils/debug.h"
#include "gwutils/utils.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"
#include "bluetooth/l2cap.h"
#include "bluetooth/uuid.h"

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"

////////////////////////
/// Defines
///////////////////////

#define UUID_GAP			0x1800
#define UUID_GATT			0x1801

#define UUID_WIFI_CREDENTIAL_SERVICE "ab6713e4-c808-11e6-99fc-cfe271467702"
#define UUID_WIFI_CREDENTIAL_SSID	"acfaab08-c808-11e6-a857-f3160a6da92f"
#define UUID_WIFI_CREDENTIAL_PASSWORD "adf9c714-c808-11e6-a2c6-db82da1eae63"
#define UUID_WIFI_CREDENTIAL_CAPABILITY "b69657aa-c80a-11e6-b18b-673f66215334"
#define UUID_INTERFACE_TYPE "b69657aa-c80a-11e6-b18b-673f66215335"
#define UUID_BR_GUID "cec0db32-8d50-11e7-9529-7ffd19ff8f68"
#define UUID_ERROR_REPORT "f34a9988-8ca2-11e7-9c28-6337f2a10f2d"

#define UDP_PORT_NO 6789
#define MAX_MAC_LEN	13
#define MAX_ID_LEN 128
#define SSID_NAME_MAX_SIZE 30   ///< SSID name maximum string length (including null character)
#define SSID_PASS_MAX_SIZE 64   ///< SSID password string maximum length (including null character)
#define SSID_TYPE_MAX_SIZE 13  ///< SSID type
#define INTERFACE_TYPE_MAX_SIZE 13  ///< INTERFACE type
#define ETH_INTERFACE 1   ///< credential Ethernet interface type
#define WiFi_INTERFACE 2  ///< credential WiFi interface type
#define GSM_INTERFACE 3   ///< credential GSM interface type
#define LED_KEY		5335	///< msg queue id
#define LED2		2		///< LED2 Identification

#define HOST_NAME "localhost"   ///< localhost name
#define MSGSIZE     1024

#define ATT_CID 4
#define MSGSZ           512

#define BLE_ADVERTISE "hciconfig hci0 leadv 0"

// ///////////////////////////////////////////////////////////////////////////
// Global and Static
///////////////////////////////////////////////////////////////////////////////

static const char test_device_name[] = "Bluez"
				"ATT Protocol Operations On GATT Server";
static bool verbose = false;
static bool guid_cb = false;

static char g_br_id[MAX_ID_LEN] = {0};
static char guid[MAX_ID_LEN] = {0};
static char Wifi_ssid[SSID_NAME_MAX_SIZE] = {0};
static char Wifi_password[SSID_PASS_MAX_SIZE] = {0};
static char Wifi_type[SSID_TYPE_MAX_SIZE] = {0};
static char Interface_type[INTERFACE_TYPE_MAX_SIZE] = {0};

//////////////////////////////////////////////////////////////
// Structures, Union, Enumerations, Typedefs
//////////////////////////////////////////////////////////////

struct server {
	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	uint8_t *device_name;
	size_t name_len;

	uint16_t gatt_svc_chngd_handle;
	bool svc_chngd_enabled;
	uint16_t wc_handle;
        uint16_t error_report_handle;
        bool error_report_enabled;
};

typedef struct msgbuf {
         long    mtype;
         char    mtext[MSGSZ];
} message_buf;

//LED2 Behaviour
typedef enum LED2_STATES
{
	SOM_ON,
	COMMISION_WINDOW,
	NFC_TAG_READ_DONE,
	DEVICE_COMMISIONED_SUCCESSFULLY,
	DEVICE_COMMISION_FAILED
}LED2_STATES;

///////////////////////////////////////////////////////////////////////////////
// Function Declaration
///////////////////////////////////////////////////////////////////////////////

/// Get GW's Mac Address
static int get_br_id();

/// Update device LED Behaviour
/// \param[in] led_no : LED No
/// \param[in] state : State of LED
void update_led(int led_no, uint8_t state);


///////////////////////////////////////////////////////////////////////////////
// Function Definitions
///////////////////////////////////////////////////////////////////////////////

static void print_prompt(void)
{
	LOG( DEBUG,"[GATT server]#" );
	fflush(stdout);
}

void update_led(int led_no, uint8_t state)
{
	int msqid_led;
	key_t key;
	unsigned char send_data[256];
	message_buf  rbuf;

	key = LED_KEY;

	if ((msqid_led = msgget(key, IPC_CREAT | 0666)) < 0) {
		perror("msgget");
		exit(1);
	}

	//Prepare packets
	sprintf(send_data,"{\"LED\" : %d, \"state\" : %d}",led_no,state);
	rbuf.mtype = 1;
	rbuf.mtext[0] = strlen(send_data);
	memcpy(&rbuf.mtext[1],send_data,strlen(send_data));

	//Send message in queue
	if (msgsnd(msqid_led, &rbuf, strlen(send_data), IPC_NOWAIT) < 0)
	{
		LOG( ERR ,"%d, %d, %s, %d\n", msqid_led, rbuf.mtype, rbuf.mtext, strlen(rbuf.mtext) );
		perror("msgsnd");
		//exit(1);
	}
}

static int get_br_id()
{
	int fd = 0;
	char buf[256];
	char MAC[MAX_MAC_LEN];
	struct ifreq s;

	//Reset buffer
	bzero(g_br_id, MAX_ID_LEN);
	memset(&buf[0],0,256);
	memset(&MAC[0],0,MAX_MAC_LEN);

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (fd < 0) {
		LOG( ERR, "Failed to create socket\n" );
		return -1;
	}

	strcpy(s.ifr_name, "eth0");
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		snprintf(&MAC[0], MAX_MAC_LEN, "%02X%02X%02X%02X%02X%02X", (unsigned char)s.ifr_addr.sa_data[0],(unsigned char)s.ifr_addr.sa_data[1],(unsigned     char)s.ifr_addr.sa_data[2],(unsigned char)s.ifr_addr.sa_data[3],(unsigned char)s.ifr_addr.sa_data[4],(unsigned char)s.ifr_addr.sa_data[5]);
	}

	//Create BR GUID
	sprintf(g_br_id,"VTBR_%s",MAC);
	LOG( DEBUG ,"BR GUID - %s\n",g_br_id );
	close(fd);
	return 0;
}

static int send_credential(char *buffer)
{
	int sockfd;
	int res = -1;
	int serverlen;
	struct sockaddr_in serveraddr;
	struct hostent *server;

	// socket: create the socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		LOG( ERR , "Failed to create socket\n" );
		return -1;
	}

	// gethostbyname: get the server's DNS entry
	server = gethostbyname(HOST_NAME);
	if (server == NULL) {
		LOG( ERR, "Failed to get hostname\n" );
		close(sockfd);
		return -1;
	}

	// build the server's Internet address
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	bcopy((char *)server->h_addr,
			(char *)&serveraddr.sin_addr.s_addr, server->h_length);
	serveraddr.sin_port = htons(UDP_PORT_NO);

	serverlen = sizeof(serveraddr);

	// Send data to server
	res = sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&serveraddr, serverlen);
	if (res < 0)  {
		LOG( ERR, "Failed to send data to server\n" );
		close(sockfd);
		return -1;
	}
	close(sockfd);

	return 0;
}

static void att_disconnect_cb(int err, void *user_data)
{
	LOG( INFO, "Device disconnected: %s\n", strerror( err ) );

	mainloop_quit();
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	LOG( DEBUG ,"%s %s\n", prefix, str );
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	LOG( DEBUG , "%s %s\n", prefix, str );
}

static void gap_device_name_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	LOG( INFO, "GAP Device Name Read called\n" );

	len = server->name_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->device_name[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_name_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	LOG( INFO, "GAP Device Name Write called\n" );

	/* If the value is being completely truncated, clean up and return */
	if (!(offset + len)) {
		free(server->device_name);
		server->device_name = NULL;
		server->name_len = 0;
		goto done;
	}

	/* Implement this as a variable length attribute value. */
	if (offset > server->name_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (offset + len != server->name_len) {
		uint8_t *name;

		name = realloc(server->device_name, offset + len);
		if (!name) {
			error = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
			goto done;
		}

		server->device_name = name;
		server->name_len = offset + len;
	}

	if (value)
		memcpy(server->device_name + offset, value, len);

done:
	gatt_db_attribute_write_result(attrib, id, error);
}

static void gap_device_name_ext_prop_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t value[2];

	LOG( INFO, "Device Name Extended Properties Read called\n" );

	value[0] = BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
	value[1] = 0;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_service_changed_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	LOG( INFO, "Service Changed Read called\n" );
	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	LOG( INFO , "Service Changed CCC Read called\n" );

	value[0] = server->svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}


static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	LOG( INFO, "Service Changed CCC Write called\n" );

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->svc_chngd_enabled = false;
	else if (value[0] == 0x02)
		server->svc_chngd_enabled = true;
	else
		ecode = 0x80;

	LOG( INFO, "Service Changed Enabled: %s\n",
				server->svc_chngd_enabled ? "true" : "false" );

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void error_report_characteristic_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	value[0] = server->error_report_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}


static void error_report_characteristic_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->error_report_enabled = false;
	else if (value[0] == 0x01)
		server->error_report_enabled = true;
	else
		ecode = 0x80;

	LOG( INFO, "Error report Enabled: %s\n",
				server->error_report_enabled ? "true" : "false" );
done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void guid_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len == 0) {
		LOG( DEBUG, ": 0 bytes\n" );
		return;
	}

	//Reset buffer
	memset(&guid[0],0,MAX_ID_LEN);
	memcpy(guid,value,len);
	guid[len] = '\0';

	LOG( DEBUG, "guid=%s\n", guid );

	guid_cb = true;
done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void WiFi_ssid_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}


	if (len == 0) {
		LOG( DEBUG, ": 0 bytes\n" );
		return;
	}

	//Reset buffer
	memset(&Wifi_ssid[0],0,SSID_NAME_MAX_SIZE);
	memcpy(Wifi_ssid,value,len);
	Wifi_ssid[len] = '\0';

	LOG( DEBUG, "Wifi_ssid=%s\n", Wifi_ssid );
done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void WiFi_password_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;
	char buf=0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len == 0) {
		LOG( DEBUG, ": 0 bytes\n" );
		return;
	}

		memset(&Wifi_password[0],0,SSID_PASS_MAX_SIZE);
		memcpy(Wifi_password,value,len);
		Wifi_password[len] = '\0';

	LOG( DEBUG, "Wifi_password=%s\n", Wifi_password );

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void WiFi_type_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	int buffer_len = 0;
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len == 0) {
		LOG( DEBUG, ": 0 bytes\n" );
		return;
	}
	LOG( DEBUG, " (%u bytes): ", len );

	memset(&Wifi_type[0],0,SSID_TYPE_MAX_SIZE);
	memcpy(Wifi_type,value,len);
	buffer_len = BinToStr(Wifi_type,len);
	Wifi_type[buffer_len] = '\0';

	LOG( DEBUG, "Wifi_type=%s\n", Wifi_type );

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void interface_type_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	int buffer_len = 0;
	char message[MSGSIZE];
	int interfaceType;
	uint8_t ecode = 0;
	uint8_t send_error_report[2] = {0x2d,0x31};
	uint16_t length = 2;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len == 0) {
		LOG( DEBUG, ": 0 bytes\n" );
		return;
	}

	LOG( DEBUG, " (%u bytes): ", len );

	memset(&Interface_type[0],0,INTERFACE_TYPE_MAX_SIZE);
	memcpy(Interface_type,value,len);
	buffer_len = BinToStr(Interface_type,len);
	Interface_type[buffer_len] = '\0';

	if(!guid_cb) {
		memset(&guid[0],0,MAX_ID_LEN);

		//Whenever guid callback is not called, It takes gw mac address as default
		memcpy(guid,g_br_id,strlen(g_br_id));
		guid[strlen(g_br_id)] = '\0';
	}

	LOG( DEBUG, "Interface_type=%s\n", Interface_type );

	interfaceType = atoi(Interface_type);

	//reset buffer
	memset(&message[0],0,MSGSIZE);

	if (interfaceType == ETH_INTERFACE) {
		sprintf(message,"{\"id\":\"%s\"," \
						"\"interfaceType\":%d}",
				guid, interfaceType);
	}
	else if (interfaceType == WiFi_INTERFACE) {
		sprintf(message,"{\"id\":\"%s\"," \
						"\"interfaceType\":%d," \
						"\"ssid\":\"%s\"," \
						"\"pwd\":\"%s\"," \
						"\"key\":\"%s\"}",
				guid, interfaceType, Wifi_ssid, Wifi_password, Wifi_type);
	}
	else if (interfaceType == GSM_INTERFACE) {
		sprintf(message,"{\"id\":\"%s\"," \
						"\"interfaceType\":%d}",
				guid, interfaceType);
	}
	else {
		LOG( ERR, "Invalid Interface_type\n" );
	}

	if(strcmp(g_br_id,guid) != 0)
	{
		//send the failure response to the mobile app.
		bt_gatt_server_send_notification(server->gatt,server->error_report_handle,send_error_report,length);
		LOG( DEBUG, "GUID verification Failed\n" );
		//Update commision failed LED Status
		update_led(LED2,DEVICE_COMMISION_FAILED);
	}
	else
	{
		if (0 < strlen(message)) {
			LOG( DEBUG, "Providing credentials to the Gateway commissioner.\n" );
			LOG( DEBUG, "Message : %s", message );
			send_credential(message);
		}
	}

	guid_cb = false;

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void confirm_write(struct gatt_db_attribute *attr, int err,
							void *user_data)
{
	if (!err)
		return;

	fprintf(stderr, "Error caching attribute %p - err: %d\n", attr, err);
	LOG( ERR, "Error caching attribute %p - err: %d\n", attr, err );
	exit(1);
}

static void populate_gap_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance;

	/* Add the GAP service */
	bt_uuid16_create(&uuid, UUID_GAP);
	service = gatt_db_add_service(server->db, &uuid, true, 6);

	/*
	 * Device Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_name_read_cb,
					gap_device_name_write_cb,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID);
	gatt_db_service_add_descriptor(service, &uuid, BT_ATT_PERM_READ,
					gap_device_name_ext_prop_read_cb,
					NULL, server);

	/*
	 * Appearance characteristic. Reads and writes should obtain the value
	 * from the database.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, server);

	/*
	 * Write the appearance value to the database, since we're not using a
	 * callback.
	 */
	put_le16(128, &appearance);
	gatt_db_attribute_write(tmp, 0, (void *) &appearance,
							sizeof(appearance),
							BT_ATT_OP_WRITE_REQ,
							NULL, confirm_write,
							NULL);

	gatt_db_service_set_active(service, true);
}

static void populate_gatt_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *svc_chngd;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, UUID_GATT);
	service = gatt_db_add_service(server->db, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, server);
	server->gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, server);

	gatt_db_service_set_active(service, true);
}

static int bt_string_to_uuid128(bt_uuid_t *uuid, const char *string)
{
	uint32_t data0, data4;
	uint16_t data1, data2, data3, data5;
	uint128_t u128;
	uint8_t *val = (uint8_t *) &u128;

	if (sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2,
				&data3, &data4, &data5) != 6)
		return -EINVAL;

	data0 = htonl(data0);
	data1 = htons(data1);
	data2 = htons(data2);
	data3 = htons(data3);
	data4 = htonl(data4);
	data5 = htons(data5);

	memcpy(&val[0], &data0, 4);
	memcpy(&val[4], &data1, 2);
	memcpy(&val[6], &data2, 2);
	memcpy(&val[8], &data3, 2);
	memcpy(&val[10], &data4, 4);
	memcpy(&val[14], &data5, 2);

	bt_uuid128_create(uuid, u128);

	return 0;
}

/* Add WiFi credential Service  and its Characteristic*/
static void populate_wc_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service;
	struct gatt_db_attribute *error_report=NULL;

	/* Add WiFi credential Service */
	bt_string_to_uuid128(&uuid, UUID_WIFI_CREDENTIAL_SERVICE);
	service = gatt_db_add_service(server->db, &uuid, true,15);
	server->wc_handle = gatt_db_attribute_get_handle(service);


        /* GUID Characteristic */
	bt_string_to_uuid128(&uuid,UUID_BR_GUID);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL,guid_write_cb,
						server);

	/* WiFi SSID  Characteristic */
	bt_string_to_uuid128(&uuid,UUID_WIFI_CREDENTIAL_SSID);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL,WiFi_ssid_write_cb,
						server);


	/* WiFi PASSWORD  Characteristic */
	bt_string_to_uuid128(&uuid,UUID_WIFI_CREDENTIAL_PASSWORD);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL,WiFi_password_write_cb,
						server);

	/* WiFi capability  Characteristic */
	bt_string_to_uuid128(&uuid,UUID_WIFI_CREDENTIAL_CAPABILITY);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL,WiFi_type_write_cb,
						server);

	/* credential type  Characteristic */
	bt_string_to_uuid128(&uuid,UUID_INTERFACE_TYPE);
	gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL,interface_type_write_cb,server);

        /* Error Report notification Characteristic */
	bt_string_to_uuid128(&uuid,UUID_ERROR_REPORT);
	error_report=gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_NOTIFY,
						NULL,NULL,NULL);

	server->error_report_handle = gatt_db_attribute_get_handle(error_report);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					error_report_characteristic_read_cb,
					error_report_characteristic_write_cb, server);


	gatt_db_service_set_active(service, true);
}

static void populate_db(struct server *server)
{
	populate_gap_service(server);
	populate_gatt_service(server);
	populate_wc_service(server);
}

static struct server *server_create(int fd, uint16_t mtu)
{
	struct server *server;
	size_t name_len = strlen(test_device_name);

	server = new0(struct server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for server\n");
		return NULL;
	}

	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, NULL,
									NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

	server->name_len = name_len + 1;
	server->device_name = malloc(name_len + 1);
	if (!server->device_name) {
		fprintf(stderr, "Failed to allocate memory for device name\n");
		goto fail;
	}

	memcpy(server->device_name, test_device_name, name_len);
	server->device_name[name_len] = '\0';

	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, mtu);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	if (verbose) {
		bt_att_set_debug(server->att, att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb,
							"server: ", NULL);
	}

	/* bt_gatt_server already holds a reference */
	populate_db(server);

	return server;

fail:
	gatt_db_unref(server->db);
	free(server->device_name);
	bt_att_unref(server->att);
	free(server);

	return NULL;
}

static void server_destroy(struct server *server)
{
	bt_gatt_server_unref(server->gatt);
	gatt_db_unref(server->db);
}

static void usage(char *argv[])
{
	LOG( WARNING, "Usage:\n\t%s [options]\n", argv[0] );

	LOG( WARNING,"Options:\n"
		"\t-i, --index <id>\t\tSpecify adapter index, e.g. hci0\n"
		"\t-m, --mtu <mtu>\t\t\tThe ATT MTU to use\n"
		"\t-s, --security-level <sec>\tSet security level (low|"
								"medium|high)\n"
		"\t-t, --type [random|public] \t The source address type\n"
		"\t-v, --verbose\t\t\tEnable extra logging\n"
		"\t-h, --help\t\t\tDisplay help\n" );
}

static struct option main_options[] = {
	{ "index",		1, 0, 'i' },
	{ "mtu",		1, 0, 'm' },
	{ "security-level",	1, 0, 's' },
	{ "type",		1, 0, 't' },
	{ "verbose",		0, 0, 'v' },
	{ "help",		0, 0, 'h' },
	{ }
};

static int l2cap_le_att_listen_and_accept(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	int sk, nsk;
	struct sockaddr_l2 srcaddr, addr;
	socklen_t optlen;
	struct bt_security btsec;
	char ba[18];

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(sk, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	LOG( INFO, "Started listening on ATT channel. Waiting for connections\n" );

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		perror("Accept failed");
		goto fail;
	}

	ba2str(&addr.l2_bdaddr, ba);

	LOG( INFO, "Connect from %s\n", ba );
	close(sk);

	return nsk;

fail:
	close(sk);
	return -1;
}

static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	default:
		break;
	}
}

int main(int argc, char *argv[])
{
	int opt;
	bdaddr_t src_addr;
	int dev_id = -1;
	int fd;
	int sec = BT_SECURITY_LOW;
	uint8_t src_type = BDADDR_LE_PUBLIC;
	uint16_t mtu = 0;
	sigset_t mask;
	struct server *server;

	openlog(argv[0], LOG_PID | LOG_CONS | LOG_NDELAY, LOG_USER);

	LOG( INFO, "Software Version : %s\n", SW_VERSION );

	while ((opt = getopt_long(argc, argv, "+hvs:t:m:i:",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv);
			return EXIT_SUCCESS;
		case 'v':
			verbose = true;
			break;
		case 's':
			if (strcmp(optarg, "low") == 0)
				sec = BT_SECURITY_LOW;
			else if (strcmp(optarg, "medium") == 0)
				sec = BT_SECURITY_MEDIUM;
			else if (strcmp(optarg, "high") == 0)
				sec = BT_SECURITY_HIGH;
			else {
				fprintf(stderr, "Invalid security level\n");
				return EXIT_FAILURE;
			}
			break;
		case 't':
			if (strcmp(optarg, "random") == 0)
				src_type = BDADDR_LE_RANDOM;
			else if (strcmp(optarg, "public") == 0)
				src_type = BDADDR_LE_PUBLIC;
			else {
				fprintf(stderr,
					"Allowed types: random, public\n");
				return EXIT_FAILURE;
			}
			break;
		case 'm': {
			int arg;

			arg = atoi(optarg);
			if (arg <= 0) {
				fprintf(stderr, "Invalid MTU: %d\n", arg);
				return EXIT_FAILURE;
			}

			if (arg > UINT16_MAX) {
				fprintf(stderr, "MTU too large: %d\n", arg);
				return EXIT_FAILURE;
			}

			mtu = (uint16_t) arg;
			break;
		}
		case 'i':
			dev_id = hci_devid(optarg);
			if (dev_id < 0) {
				perror("Invalid adapter");
				return EXIT_FAILURE;
			}

			break;
		default:
			fprintf(stderr, "Invalid option: %c\n", opt);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv -= optind;
	optind = 0;

	if (argc) {
		usage(argv);
		closelog();
		return EXIT_SUCCESS;
	}

	if (dev_id == -1)
		bacpy(&src_addr, BDADDR_ANY);
	else if (hci_devba(dev_id, &src_addr) < 0) {
		perror("Adapter not available");
		return EXIT_FAILURE;
	}

        //Get Gateway mac address
	get_br_id();

	while(1){

		fd = l2cap_le_att_listen_and_accept(&src_addr, sec, src_type);
		if (fd < 0) {
			fprintf(stderr, "Failed to accept L2CAP ATT connection\n");
			return EXIT_FAILURE;
		}

		mainloop_init();

		server = server_create(fd, mtu);
		if (!server) {
			close(fd);
			closelog();
			return EXIT_FAILURE;
		}

		LOG( INFO, "Running GATT server\n" );

		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);

		mainloop_set_signal(&mask, signal_cb, NULL, NULL);

		print_prompt();

		mainloop_run();

		LOG( INFO, "\n\nShutting down...\n" );

		server_destroy(server);
		system(BLE_ADVERTISE);
	}

	closelog();
	return EXIT_SUCCESS;
}
