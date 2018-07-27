/*
 *
 *  DHCP library with GLib integration
 *
 *  Copyright (C) 2009-2014  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <resolv.h>

#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include <linux/if.h>
#include <linux/filter.h>

#include <glib.h>

#include "gdhcp.h"
#include "gdhcp-common.h"
#include "gdhcp-unaligned.h"
#include "gdhcp-ipv4ll.h"
#include "gdhcp-marshal.h"

#define DISCOVER_TIMEOUT 5
#define DISCOVER_RETRIES 6

#define REQUEST_TIMEOUT 5
#define REQUEST_RETRIES 3

typedef enum _listen_mode {
	L_NONE,
	L2,
	L3,
	L_ARP,
} ListenMode;

typedef enum _dhcp_client_state {
	INIT_SELECTING,
	REBOOTING,
	REQUESTING,
	BOUND,
	RENEWING,
	REBINDING,
	RELEASED,
	IPV4LL_PROBE,
	IPV4LL_ANNOUNCE,
	IPV4LL_MONITOR,
	IPV4LL_DEFEND,
	INFORMATION_REQ,
	SOLICITATION,
	REQUEST,
	CONFIRM,
	RENEW,
	REBIND,
	RELEASE,
	DECLINE,
} ClientState;

typedef struct {
	GDHCPType type;
	ClientState state;
	int ifindex;
	char *interface;
	uint8_t mac_address[6];
	uint32_t xid;
	uint32_t server_ip;
	uint32_t requested_ip;
	char *assigned_ip;
	time_t start;
	uint32_t lease_seconds;
	ListenMode listen_mode;
	int listener_sockfd;
	uint8_t retry_times;
	uint8_t ack_retry_times;
	uint8_t conflicts;
	guint timeout;
	guint t1_timeout;
	guint t2_timeout;
	guint lease_timeout;
	guint listener_watch;
	GList *require_list;
	GList *request_list;
	GHashTable *code_value_hash;
	GHashTable *send_value_hash;
	char *last_address;
	unsigned char *duid;
	int duid_len;
	unsigned char *server_duid;
	int server_duid_len;
	uint16_t status_code;
	uint32_t iaid;
	uint32_t T1, T2;
	struct in6_addr ia_na;
	struct in6_addr ia_ta;
	time_t last_request;
	uint32_t expire;
	bool retransmit;
	struct timeval start_time;
	bool request_bcast;
} GDHCPClientPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (GDHCPClient, gdhcp_client, G_TYPE_OBJECT)

/*
enum {
	N_PROPS,
};
*/

enum {
	SIG_LEASE_AVAILABLE,
	SIG_IPV4LL_AVAILABLE,
	SIG_NO_LEASE,
	SIG_LEASE_LOST,
	SIG_IPV4LL_LOST,
	SIG_ADDRESS_CONFLICT,
	SIG_INFORMATION_REQ,
	SIG_SOLICITATION,
	SIG_ADVERTISE,
	SIG_REQUEST,
	SIG_RENEW,
	SIG_REBIND,
	SIG_RELEASE,
	SIG_CONFIRM,
	SIG_DECLINE,
	N_SIGNALS,
};

/* static GParamSpec *properties[N_PROPS]; */
static guint signals[N_SIGNALS];

static void remove_option_value(gpointer data);
static void gdhcp_client_dispose (GObject *object);
static gboolean ipv4ll_first_probe_timeout(gpointer user_data);

static void gdhcp_client_class_init(GDHCPClientClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = gdhcp_client_dispose;

	/**
	 * GDHCPClient::lease_available:
	 *
	 * The "lease-available" signal is called when FIXME.
	 */
	signals[SIG_LEASE_AVAILABLE] = g_signal_new("lease-available",
												G_TYPE_FROM_CLASS(klass),
												G_SIGNAL_RUN_LAST,
												G_STRUCT_OFFSET(GDHCPClientClass, lease_available),
												NULL, NULL,
												g_cclosure_marshal_VOID__VOID,
												G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::ipv4ll_available:
	 *
	 * The "ipv4ll-available" signal is called when FIXME.
	 */
	signals[SIG_IPV4LL_AVAILABLE] = g_signal_new("ipv4ll-available",
												 G_TYPE_FROM_CLASS(klass),
												 G_SIGNAL_RUN_LAST,
												 G_STRUCT_OFFSET(GDHCPClientClass, ipv4ll_available),
												 NULL, NULL,
												 g_cclosure_marshal_VOID__VOID,
												 G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::no_lease:
	 *
	 * The "no-lease" signal is called when FIXME.
	 */
	signals[SIG_NO_LEASE] = g_signal_new("no-lease",
										 G_TYPE_FROM_CLASS(klass),
										 G_SIGNAL_RUN_LAST,
										 G_STRUCT_OFFSET(GDHCPClientClass, no_lease),
										 NULL, NULL,
										 g_cclosure_marshal_VOID__VOID,
										 G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::lease_lost:
	 *
	 * The "lease-lost" signal is called when FIXME.
	 */
	signals[SIG_LEASE_LOST] = g_signal_new("lease-lost",
										   G_TYPE_FROM_CLASS(klass),
										   G_SIGNAL_RUN_LAST,
										   G_STRUCT_OFFSET(GDHCPClientClass, lease_lost),
										   NULL, NULL,
										   g_cclosure_marshal_VOID__VOID,
										   G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::ipv4ll_lost:
	 *
	 * The "ipv4ll-lost" signal is called when FIXME.
	 */
	signals[SIG_IPV4LL_LOST] = g_signal_new("ipv4ll-lost",
											G_TYPE_FROM_CLASS(klass),
											G_SIGNAL_RUN_LAST,
											G_STRUCT_OFFSET(GDHCPClientClass, ipv4ll_lost),
											NULL, NULL,
											g_cclosure_marshal_VOID__VOID,
											G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::address_conflict:
	 *
	 * The "address-conflict" signal is called when FIXME.
	 */
	signals[SIG_ADDRESS_CONFLICT] = g_signal_new("address-conflict",
												 G_TYPE_FROM_CLASS(klass),
												 G_SIGNAL_RUN_LAST,
												 G_STRUCT_OFFSET(GDHCPClientClass, address_conflict),
												 NULL, NULL,
												 g_cclosure_marshal_VOID__VOID,
												 G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::information_req:
	 *
	 * The "information-req" signal is called when FIXME.
	 */
	signals[SIG_INFORMATION_REQ] = g_signal_new("information-req",
												G_TYPE_FROM_CLASS(klass),
												G_SIGNAL_RUN_LAST,
												G_STRUCT_OFFSET(GDHCPClientClass, information_req),
												NULL, NULL,
												g_cclosure_marshal_VOID__VOID,
												G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::solicitation:
	 *
	 * The "solicitation" signal is called when FIXME.
	 */
	signals[SIG_SOLICITATION] = g_signal_new("solicitation",
											 G_TYPE_FROM_CLASS(klass),
											 G_SIGNAL_RUN_LAST,
											 G_STRUCT_OFFSET(GDHCPClientClass, solicitation),
											 NULL, NULL,
											 g_cclosure_marshal_VOID__VOID,
											 G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::advertise:
	 *
	 * The "advertise" signal is called when FIXME.
	 */
	signals[SIG_ADVERTISE] = g_signal_new("advertise",
										  G_TYPE_FROM_CLASS(klass),
										  G_SIGNAL_RUN_LAST,
										  G_STRUCT_OFFSET(GDHCPClientClass, advertise),
										  NULL, NULL,
										  g_cclosure_marshal_VOID__VOID,
										  G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::request:
	 *
	 * The "request" signal is called when FIXME.
	 */
	signals[SIG_REQUEST] = g_signal_new("request",
										G_TYPE_FROM_CLASS(klass),
										G_SIGNAL_RUN_LAST,
										G_STRUCT_OFFSET(GDHCPClientClass, request),
										NULL, NULL,
										g_cclosure_marshal_VOID__VOID,
										G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::renew:
	 *
	 * The "renew" signal is called when FIXME.
	 */
	signals[SIG_RENEW] = g_signal_new("renew",
									  G_TYPE_FROM_CLASS(klass),
									  G_SIGNAL_RUN_LAST,
									  G_STRUCT_OFFSET(GDHCPClientClass, renew),
									  NULL, NULL,
									  g_cclosure_marshal_VOID__VOID,
									  G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::rebind:
	 *
	 * The "rebind" signal is called when FIXME.
	 */
	signals[SIG_REBIND] = g_signal_new("rebind",
									   G_TYPE_FROM_CLASS(klass),
									   G_SIGNAL_RUN_LAST,
									   G_STRUCT_OFFSET(GDHCPClientClass, rebind),
									   NULL, NULL,
									   g_cclosure_marshal_VOID__VOID,
									   G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::release:
	 *
	 * The "release" signal is called when FIXME.
	 */
	signals[SIG_RELEASE] = g_signal_new("release",
										G_TYPE_FROM_CLASS(klass),
										G_SIGNAL_RUN_LAST,
										G_STRUCT_OFFSET(GDHCPClientClass, release),
										NULL, NULL,
										g_cclosure_marshal_VOID__VOID,
										G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::confirm:
	 *
	 * The "confirm" signal is called when FIXME.
	 */
	signals[SIG_CONFIRM] = g_signal_new("confirm",
										G_TYPE_FROM_CLASS(klass),
										G_SIGNAL_RUN_LAST,
										G_STRUCT_OFFSET(GDHCPClientClass, confirm),
										NULL, NULL,
										g_cclosure_marshal_VOID__VOID,
										G_TYPE_NONE, 0);

	/**
	 * GDHCPClient::decline:
	 *
	 * The "decline" signal is called when FIXME.
	 */
	signals[SIG_DECLINE] = g_signal_new("decline",
										G_TYPE_FROM_CLASS(klass),
										G_SIGNAL_RUN_LAST,
										G_STRUCT_OFFSET(GDHCPClientClass, decline),
										NULL, NULL,
										g_cclosure_marshal_VOID__VOID,
										G_TYPE_NONE, 0);
}

static void gdhcp_client_init (GDHCPClient *dhcp_client)
{
}

static void gdhcp_client_dispose(GObject *object)
{
	GDHCPClient *dhcp_client = (GDHCPClient *)object;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	gdhcp_client_stop(dhcp_client);

	g_free(priv->interface);
	g_free(priv->assigned_ip);
	g_free(priv->last_address);
	g_free(priv->duid);
	g_free(priv->server_duid);

	g_list_free(priv->request_list);
	g_list_free(priv->require_list);

	g_hash_table_destroy(priv->code_value_hash);
	g_hash_table_destroy(priv->send_value_hash);

	G_OBJECT_CLASS (gdhcp_client_parent_class)->dispose(object);
}

static inline void debug(GDHCPClient *client, const char *format, ...)
{
#if 0
	char str[256];
	va_list ap;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		printf(str);

	va_end(ap);
#endif
}

/* Initialize the packet with the proper defaults */
static void init_packet(GDHCPClient *dhcp_client, gpointer pkt, char type)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (priv->type == G_DHCP_IPV6)
		dhcpv6_init_header(pkt, type);
	else {
		struct dhcp_packet *packet = pkt;
		dhcp_init_header(pkt, type);
		memcpy(packet->chaddr, priv->mac_address, 6);
	}
}

static void add_request_options(GDHCPClient *dhcp_client, struct dhcp_packet *packet)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	int len = 0;
	GList *list;
	uint8_t code;
	int end = dhcp_end_option(packet->options);

	for (list = priv->request_list; list; list = list->next) {
		code = (uint8_t) GPOINTER_TO_INT(list->data);
		packet->options[end + OPT_DATA + len] = code;
		len++;
	}

	if (len) {
		packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
		packet->options[end + OPT_LEN] = len;
		packet->options[end + OPT_DATA + len] = DHCP_END;
	}
}

struct hash_params {
	unsigned char *buf;
	int max_buf;
	unsigned char **ptr_buf;
};

static void add_dhcpv6_binary_option(gpointer key, gpointer value,
					gpointer user_data)
{
	uint8_t *option = value;
	uint16_t len;
	struct hash_params *params = user_data;

	/* option[0][1] contains option code */
	len = option[2] << 8 | option[3];

	if ((*params->ptr_buf + len + 2 + 2) > (params->buf + params->max_buf))
		return;

	memcpy(*params->ptr_buf, option, len + 2 + 2);
	(*params->ptr_buf) += len + 2 + 2;
}

static void add_dhcpv6_send_options(GDHCPClient *dhcp_client,
				unsigned char *buf, int max_buf,
				unsigned char **ptr_buf)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	struct hash_params params = {
		.buf = buf,
		.max_buf = max_buf,
		.ptr_buf = ptr_buf
	};

	if (priv->type != G_DHCP_IPV6)
		return;

	g_hash_table_foreach(priv->send_value_hash, add_dhcpv6_binary_option, &params);

	*ptr_buf = *params.ptr_buf;
}

static void copy_option(uint8_t *buf, uint16_t code, uint16_t len, uint8_t *msg)
{
	buf[0] = code >> 8;
	buf[1] = code & 0xff;
	buf[2] = len >> 8;
	buf[3] = len & 0xff;
	if (len > 0 && msg)
		memcpy(&buf[4], msg, len);
}

static int32_t get_time_diff(struct timeval *tv)
{
	struct timeval now;
	int32_t hsec;

	gettimeofday(&now, NULL);

	hsec = (now.tv_sec - tv->tv_sec) * 100;
	hsec += (now.tv_usec - tv->tv_usec) / 10000;

	return hsec;
}

static void remove_timeouts(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (priv->timeout > 0)
		g_source_remove(priv->timeout);
	if (priv->t1_timeout > 0)
		g_source_remove(priv->t1_timeout);
	if (priv->t2_timeout > 0)
		g_source_remove(priv->t2_timeout);
	if (priv->lease_timeout > 0)
		g_source_remove(priv->lease_timeout);

	priv->timeout = 0;
	priv->t1_timeout = 0;
	priv->t2_timeout = 0;
	priv->lease_timeout = 0;
}

static void add_dhcpv6_request_options(GDHCPClient *dhcp_client,
				struct dhcpv6_packet *packet,
				unsigned char *buf, int max_buf,
				unsigned char **ptr_buf)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GList *list;
	uint16_t code, value;
	bool added;
	int32_t diff;
	int len;

	g_assert(priv->type == G_DHCP_IPV6);

	for (list = priv->request_list; list; list = list->next) {
		code = (uint16_t) GPOINTER_TO_INT(list->data);
		added = false;

		switch (code) {
			case GDHCP_V6_CLIENTID:
				if (!priv->duid)
					return;

				len = 2 + 2 + priv->duid_len;
				if ((*ptr_buf + len) > (buf + max_buf)) {
					debug(dhcp_client, "Too long dhcpv6 message when writing client id option");
					return;
				}

				copy_option(*ptr_buf, GDHCP_V6_CLIENTID, priv->duid_len, priv->duid);
				(*ptr_buf) += len;
				added = true;
				break;

			case GDHCP_V6_SERVERID:
				if (!priv->server_duid)
					break;

				len = 2 + 2 + priv->server_duid_len;
				if ((*ptr_buf + len) > (buf + max_buf)) {
					debug(dhcp_client, "Too long dhcpv6 message when writing server id option");
					return;
				}

				copy_option(*ptr_buf, GDHCP_V6_SERVERID, priv->server_duid_len, priv->server_duid);
				(*ptr_buf) += len;
				added = true;
				break;

			case GDHCP_V6_RAPID_COMMIT:
				len = 2 + 2;
				if ((*ptr_buf + len) > (buf + max_buf)) {
					debug(dhcp_client, "Too long dhcpv6 message when writing rapid commit option");
					return;
				}

				copy_option(*ptr_buf, GDHCP_V6_RAPID_COMMIT, 0, 0);
				(*ptr_buf) += len;
				added = true;
				break;

			case GDHCP_V6_ORO:
				break;

			case GDHCP_V6_ELAPSED_TIME:
				if (!priv->retransmit) {
					/*
					* Initial message, elapsed time is 0.
					*/
					diff = 0;
				} else {
					diff = get_time_diff(&priv->start_time);
					if (diff < 0 || diff > 0xffff)
						diff = 0xffff;
				}

				len = 2 + 2 + 2;
				if ((*ptr_buf + len) > (buf + max_buf)) {
					debug(dhcp_client, "Too long dhcpv6 message when writing elapsed time option");
					return;
				}

				value = htons((uint16_t)diff);
				copy_option(*ptr_buf, GDHCP_V6_ELAPSED_TIME, 2, (uint8_t *)&value);
				(*ptr_buf) += len;
				added = true;
				break;

			case GDHCP_V6_DNS_SERVERS:
				break;

			case GDHCP_V6_DOMAIN_LIST:
				break;

			case GDHCP_V6_SNTP_SERVERS:
				break;

			default:
				break;
		}

		if (added)
			debug(dhcp_client, "option %d len %d added", code, len);
	}
}

static void add_binary_option(gpointer key, gpointer value, gpointer user_data)
{
	uint8_t *option = value;
	struct dhcp_packet *packet = user_data;

	dhcp_add_binary_option(packet, option);
}

static void add_send_options(GDHCPClient *dhcp_client, struct dhcp_packet *packet)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	g_hash_table_foreach(priv->send_value_hash, add_binary_option, packet);
}

/*
 * Return an RFC 951- and 2131-complaint BOOTP 'secs' value that
 * represents the number of seconds elapsed from the start of
 * attempting DHCP to satisfy some DHCP servers that allow for an
 * "authoritative" reply before responding.
 */
static uint16_t dhcp_attempt_secs(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return htons(MIN(time(NULL) - priv->start, UINT16_MAX));
}

static int send_discover(GDHCPClient *dhcp_client, uint32_t requested)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP discover request");

	init_packet(dhcp_client, &packet, DHCPDISCOVER);

	packet.xid = priv->xid;
	packet.secs = dhcp_attempt_secs(dhcp_client);

	if (requested)
		dhcp_add_option_uint32(&packet, DHCP_REQUESTED_IP, requested);

	/* Explicitly saying that we want RFC-compliant packets helps
	 * some buggy DHCP servers to NOT send bigger packets */
	dhcp_add_option_uint16(&packet, DHCP_MAX_SIZE, 576);

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	/*
	 * If we do not get a reply to DISCOVER packet, then we try with
	 * broadcast flag set. So first packet is sent without broadcast flag,
	 * first retry is with broadcast flag, second retry is without it etc.
	 * Reason is various buggy routers/AP that either eat the other or vice
	 * versa. In the receiving side we then find out what kind of packet
	 * the server can send.
	 */
	return dhcp_send_raw_packet(&packet, INADDR_ANY, CLIENT_PORT,
				INADDR_BROADCAST, SERVER_PORT,
				MAC_BCAST_ADDR, priv->ifindex,
				priv->retry_times % 2);
}

static int send_request(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP request (state %d)", priv->state);

	init_packet(dhcp_client, &packet, DHCPREQUEST);

	packet.xid = priv->xid;
	packet.secs = dhcp_attempt_secs(dhcp_client);

	if (priv->state == REQUESTING || priv->state == REBOOTING)
		dhcp_add_option_uint32(&packet, DHCP_REQUESTED_IP, priv->requested_ip);

	if (priv->state == REQUESTING)
		dhcp_add_option_uint32(&packet, DHCP_SERVER_ID, priv->server_ip);

	dhcp_add_option_uint16(&packet, DHCP_MAX_SIZE, 576);

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	if (priv->state == RENEWING || priv->state == REBINDING)
		packet.ciaddr = htonl(priv->requested_ip);

	if (priv->state == RENEWING)
		return dhcp_send_kernel_packet(&packet,
				priv->requested_ip, CLIENT_PORT,
				priv->server_ip, SERVER_PORT);

	return dhcp_send_raw_packet(&packet, INADDR_ANY, CLIENT_PORT,
				INADDR_BROADCAST, SERVER_PORT,
				MAC_BCAST_ADDR, priv->ifindex,
				priv->request_bcast);
}

static int send_release(GDHCPClient *dhcp_client, uint32_t server, uint32_t ciaddr)
{
	struct dhcp_packet packet;
	uint64_t rand;

	debug(dhcp_client, "sending DHCP release request");

	init_packet(dhcp_client, &packet, DHCPRELEASE);
	dhcp_get_random(&rand);
	packet.xid = rand;
	packet.ciaddr = htonl(ciaddr);

	dhcp_add_option_uint32(&packet, DHCP_SERVER_ID, server);

	return dhcp_send_kernel_packet(&packet, ciaddr, CLIENT_PORT, server, SERVER_PORT);
}

static int switch_listening_mode(GDHCPClient *dhcp_client, ListenMode listen_mode);
static gboolean ipv4ll_probe_timeout(gpointer user_data);
static gboolean ipv4ll_announce_timeout(gpointer user_data);
static gboolean ipv4ll_defend_timeout(gpointer user_data);

static void send_probe_packet(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	guint timeout;

	/* if requested_ip is not valid, pick a new address */
	if (priv->requested_ip == 0) {
		debug(dhcp_client, "pick a new random address");
		priv->requested_ip = ipv4ll_random_ip();
	}

	debug(dhcp_client, "sending IPV4LL probe request");

	if (priv->retry_times == 1) {
		priv->state = IPV4LL_PROBE;
		switch_listening_mode(dhcp_client, L_ARP);
	}

	ipv4ll_send_arp_packet(priv->mac_address,
				0,
				priv->requested_ip,
				priv->ifindex);

	if (priv->retry_times < PROBE_NUM) {
		/* add a random timeout in range of PROBE_MIN to PROBE_MAX */
		timeout = ipv4ll_random_delay_ms(PROBE_MAX - PROBE_MIN);
		timeout += PROBE_MIN * 1000;
	} else
		timeout = (ANNOUNCE_WAIT * 1000);

	priv->timeout = g_timeout_add_full(G_PRIORITY_HIGH,
						 timeout,
						 ipv4ll_probe_timeout,
						 dhcp_client,
						 NULL);
}

static void send_announce_packet(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "sending IPV4LL announce request");

	ipv4ll_send_arp_packet(priv->mac_address,
				priv->requested_ip,
				priv->requested_ip,
				priv->ifindex);

	remove_timeouts(dhcp_client);

	if (priv->state == IPV4LL_DEFEND)
		priv->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							DEFEND_INTERVAL,
							ipv4ll_defend_timeout,
							dhcp_client,
							NULL);
	else
		priv->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							ANNOUNCE_INTERVAL,
							ipv4ll_announce_timeout,
							dhcp_client,
							NULL);
}

static void get_interface_mac_address(int index, uint8_t *mac_address)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		perror("Open socket error");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		goto done;
	}

	err = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		perror("Get mac address error");
		goto done;
	}

	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

done:
	close(sk);
}

void gdhcp_v6_client_set_retransmit(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	priv->retransmit = true;
}

void gdhcp_v6_client_clear_retransmit(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	priv->retransmit = false;
}

int gdhcp_v6_create_duid(GDHCPDuidType duid_type, int index, int type,
			unsigned char **duid, int *duid_len)
{
	time_t duid_time;

	switch (duid_type) {
		case GDHCP_V6_DUID_LLT:
			*duid_len = 2 + 2 + 4 + ETH_ALEN;
			*duid = g_try_malloc(*duid_len);
			if (!*duid)
				return -ENOMEM;

			(*duid)[0] = 0;
			(*duid)[1] = 1;
			get_interface_mac_address(index, &(*duid)[2 + 2 + 4]);
			(*duid)[2] = 0;
			(*duid)[3] = type;
			duid_time = time(NULL) - DUID_TIME_EPOCH;
			(*duid)[4] = duid_time >> 24;
			(*duid)[5] = duid_time >> 16;
			(*duid)[6] = duid_time >> 8;
			(*duid)[7] = duid_time & 0xff;
			break;
		case GDHCP_V6_DUID_EN:
			return -EINVAL;
		case GDHCP_V6_DUID_LL:
			*duid_len = 2 + 2 + ETH_ALEN;
			*duid = g_try_malloc(*duid_len);
			if (!*duid)
				return -ENOMEM;

			(*duid)[0] = 0;
			(*duid)[1] = 3;
			get_interface_mac_address(index, &(*duid)[2 + 2]);
			(*duid)[2] = 0;
			(*duid)[3] = type;
			break;
	}

	return 0;
}

static gchar *convert_to_hex(unsigned char *buf, int len)
{
	gchar *ret = g_try_malloc(len * 2 + 1);
	int i;

	for (i = 0; ret && i < len; i++)
		g_snprintf(ret + i * 2, 3, "%02x", buf[i]);

	return ret;
}

int gdhcp_v6_client_set_duid(GDHCPClient *dhcp_client, unsigned char *duid, int duid_len)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	g_free(priv->duid);

	priv->duid = duid;
	priv->duid_len = duid_len;

	{
		gchar *hex = convert_to_hex(duid, duid_len);
		debug(dhcp_client, "DUID(%d) %s", duid_len, hex);
		g_free(hex);
	}

	return 0;
}

/**
 * gdhcp_v6_client_set_pd:
 * @dhcp_client:
 * @T1:
 * @T2:
 * prefixes:
 *
 * Returns:
 */
int gdhcp_v6_client_set_pd(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, GSList *prefixes)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint8_t options[1452];
	unsigned int max_buf = sizeof(options);
	int len, count = g_slist_length(prefixes);

	g_assert(priv->type == G_DHCP_IPV6);

	gdhcp_client_set_request(dhcp_client, GDHCP_V6_IA_PD);

	memset(options, 0, sizeof(options));

	options[0] = priv->iaid >> 24;
	options[1] = priv->iaid >> 16;
	options[2] = priv->iaid >> 8;
	options[3] = priv->iaid;

	if (T1) {
		uint32_t t = htonl(*T1);
		memcpy(&options[4], &t, 4);
	}

	if (T2) {
		uint32_t t = htonl(*T2);
		memcpy(&options[8], &t, 4);
	}

	len = 12;

	if (count > 0) {
		GSList *list;

		for (list = prefixes; list; list = list->next) {
			GDHCPIAPrefix *prefix = list->data;
			uint8_t sub_option[4+4+1+16];

			if ((len + 2 + 2 + sizeof(sub_option)) >= max_buf) {
				debug(dhcp_client, "Too long dhcpv6 message when writing IA prefix option");
				return -EINVAL;
			}

			memset(&sub_option, 0, sizeof(sub_option));

			/* preferred and validity time are left zero */

			sub_option[8] = prefix->prefixlen;
			memcpy(&sub_option[9], &prefix->prefix, 16);

			copy_option(&options[len], GDHCP_V6_IA_PREFIX,
				sizeof(sub_option), sub_option);
			len += 2 + 2 + sizeof(sub_option);
		}
	}

	gdhcp_v6_client_set_send(dhcp_client, GDHCP_V6_IA_PD, options, len);

	return 0;
}

uint32_t gdhcp_v6_client_get_iaid(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	return priv->iaid;
}

void gdhcp_v6_client_set_iaid(GDHCPClient *dhcp_client, uint32_t iaid)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	priv->iaid = iaid;
}

void gdhcp_v6_client_create_iaid(GDHCPClient *dhcp_client, int index, unsigned char *iaid)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint8_t buf[6];

	get_interface_mac_address(index, buf);

	memcpy(iaid, &buf[2], 4);
	priv->iaid = iaid[0] << 24 | iaid[1] << 16 | iaid[2] << 8 | iaid[3];
}

int gdhcp_v6_client_get_timeouts(GDHCPClient *dhcp_client,
				uint32_t *T1, uint32_t *T2,
				time_t *started,
				time_t *expire)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	if (T1)
		*T1 = (priv->expire == 0xffffffff) ? 0xffffffff : priv->T1;

	if (T2)
		*T2 = (priv->expire == 0xffffffff) ? 0xffffffff : priv->T2;

	if (started)
		*started = priv->last_request;

	if (expire)
		*expire = (priv->expire == 0xffffffff) ? 0xffffffff : priv->last_request + priv->expire;

	return 0;
}

static uint8_t *create_iaaddr(GDHCPClient *dhcp_client, uint8_t *buf, uint16_t len)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	buf[0] = 0;
	buf[1] = GDHCP_V6_IAADDR;
	buf[2] = 0;
	buf[3] = len;
	memcpy(&buf[4], &priv->ia_na, 16);
	memset(&buf[20], 0, 4); /* preferred */
	memset(&buf[24], 0, 4); /* valid */
	return buf;
}

static uint8_t *append_iaaddr(GDHCPClient *dhcp_client, uint8_t *buf, const char *address)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, address, &addr) != 1)
		return NULL;

	buf[0] = 0;
	buf[1] = GDHCP_V6_IAADDR;
	buf[2] = 0;
	buf[3] = 24;
	memcpy(&buf[4], &addr, 16);
	memset(&buf[20], 0, 4); /* preferred */
	memset(&buf[24], 0, 4); /* valid */
	return &buf[28];
}

static void put_iaid(GDHCPClient *dhcp_client, int index, uint8_t *buf)
{
	uint32_t iaid;

	iaid = gdhcp_v6_client_get_iaid(dhcp_client);
	if (iaid == 0) {
		gdhcp_v6_client_create_iaid(dhcp_client, index, buf);
		return;
	}

	buf[0] = iaid >> 24;
	buf[1] = iaid >> 16;
	buf[2] = iaid >> 8;
	buf[3] = iaid;
}

int gdhcp_v6_client_set_ia(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			bool add_iaaddr, const char *ia_na)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (code == GDHCP_V6_IA_TA) {
		uint8_t ia_options[4];

		put_iaid(dhcp_client, index, ia_options);

		gdhcp_client_set_request(dhcp_client, GDHCP_V6_IA_TA);
		gdhcp_v6_client_set_send(dhcp_client, GDHCP_V6_IA_TA,
					ia_options, sizeof(ia_options));

	} else if (code == GDHCP_V6_IA_NA) {
		struct in6_addr addr;

		gdhcp_client_set_request(dhcp_client, GDHCP_V6_IA_NA);

		/*
		 * If caller has specified the IPv6 address it wishes to
		 * to use (ia_na != NULL and address is valid), then send
		 * the address to server.
		 * If caller did not specify the address (ia_na == NULL) and
		 * if the current address is not set, then we should not send
		 * the address sub-option.
		 */
		if (add_iaaddr && ((!ia_na &&
			!IN6_IS_ADDR_UNSPECIFIED(&priv->ia_na))
			|| (ia_na &&
				inet_pton(AF_INET6, ia_na, &addr) == 1))) {
#define IAADDR_LEN (16+4+4)
			uint8_t ia_options[4+4+4+2+2+IAADDR_LEN];

			if (ia_na)
				memcpy(&priv->ia_na, &addr,
						sizeof(struct in6_addr));

			put_iaid(dhcp_client, index, ia_options);

			if (T1) {
				ia_options[4] = *T1 >> 24;
				ia_options[5] = *T1 >> 16;
				ia_options[6] = *T1 >> 8;
				ia_options[7] = *T1;
			} else
				memset(&ia_options[4], 0x00, 4);

			if (T2) {
				ia_options[8] = *T2 >> 24;
				ia_options[9] = *T2 >> 16;
				ia_options[10] = *T2 >> 8;
				ia_options[11] = *T2;
			} else
				memset(&ia_options[8], 0x00, 4);

			create_iaaddr(dhcp_client, &ia_options[12],
					IAADDR_LEN);

			gdhcp_v6_client_set_send(dhcp_client, GDHCP_V6_IA_NA,
					ia_options, sizeof(ia_options));
		} else {
			uint8_t ia_options[4+4+4];

			put_iaid(dhcp_client, index, ia_options);

			memset(&ia_options[4], 0x00, 4); /* T1 (4 bytes) */
			memset(&ia_options[8], 0x00, 4); /* T2 (4 bytes) */

			gdhcp_v6_client_set_send(dhcp_client, GDHCP_V6_IA_NA,
					ia_options, sizeof(ia_options));
		}

	} else
		return -EINVAL;

	return 0;
}

int gdhcp_v6_client_set_ias(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			GSList *addresses)
{
	GSList *list;
	uint8_t *ia_options, *pos;
	int len, count, total_len;

	count = g_slist_length(addresses);
	if (count == 0)
		return -EINVAL;

	gdhcp_client_set_request(dhcp_client, code);

	if (code == GDHCP_V6_IA_TA)
		len = 4;         /* IAID */
	else if (code == GDHCP_V6_IA_NA)
		len = 4 + 4 + 4; /* IAID + T1 + T2 */
	else
		return -EINVAL;

	total_len = len + count * (2 + 2 + 16 + 4 + 4);
	ia_options = g_try_malloc0(total_len);
	if (!ia_options)
		return -ENOMEM;

	put_iaid(dhcp_client, index, ia_options);

	pos = &ia_options[len]; /* skip the IA_NA or IA_TA */

	for (list = addresses; list; list = list->next) {
		pos = append_iaaddr(dhcp_client, pos, list->data);
		if (!pos)
			break;
	}

	if (code == GDHCP_V6_IA_NA) {
		if (T1) {
			ia_options[4] = *T1 >> 24;
			ia_options[5] = *T1 >> 16;
			ia_options[6] = *T1 >> 8;
			ia_options[7] = *T1;
		} else
			memset(&ia_options[4], 0x00, 4);

		if (T2) {
			ia_options[8] = *T2 >> 24;
			ia_options[9] = *T2 >> 16;
			ia_options[10] = *T2 >> 8;
			ia_options[11] = *T2;
		} else
			memset(&ia_options[8], 0x00, 4);
	}

	gdhcp_v6_client_set_send(dhcp_client, code, ia_options, total_len);

	g_free(ia_options);

	return 0;
}

int gdhcp_v6_client_set_oro(GDHCPClient *dhcp_client, int args, ...)
{
	va_list va;
	int i, j, len = sizeof(uint16_t) * args;
	uint8_t *values;

	values = g_try_malloc(len);
	if (!values)
		return -ENOMEM;

	va_start(va, args);
	for (i = 0, j = 0; i < args; i++) {
		uint16_t value = va_arg(va, int);
		values[j++] = value >> 8;
		values[j++] = value & 0xff;
	}
	va_end(va);

	gdhcp_v6_client_set_send(dhcp_client, GDHCP_V6_ORO, values, len);

	g_free(values);

	return 0;
}

static int send_dhcpv6_msg(GDHCPClient *dhcp_client, int type, char *msg)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	struct dhcpv6_packet *packet;
	uint8_t buf[MAX_DHCPV6_PKT_SIZE];
	unsigned char *ptr;
	int ret, max_buf;

	memset(buf, 0, sizeof(buf));
	packet = (struct dhcpv6_packet *)&buf[0];
	ptr = buf + sizeof(struct dhcpv6_packet);

	init_packet(dhcp_client, packet, type);

	if (!priv->retransmit) {
		priv->xid = packet->transaction_id[0] << 16 |
				packet->transaction_id[1] << 8 |
				packet->transaction_id[2];
		gettimeofday(&priv->start_time, NULL);
	} else {
		packet->transaction_id[0] = priv->xid >> 16;
		packet->transaction_id[1] = priv->xid >> 8 ;
		packet->transaction_id[2] = priv->xid;
	}

	gdhcp_client_set_request(dhcp_client, GDHCP_V6_ELAPSED_TIME);

	debug(dhcp_client, "sending DHCPv6 %s message xid 0x%04x", msg, priv->xid);

	max_buf = MAX_DHCPV6_PKT_SIZE - sizeof(struct dhcpv6_packet);

	add_dhcpv6_request_options(dhcp_client, packet, buf, max_buf, &ptr);

	add_dhcpv6_send_options(dhcp_client, buf, max_buf, &ptr);

	ret = dhcpv6_send_packet(priv->ifindex, packet, ptr - buf);

	debug(dhcp_client, "sent %d pkt %p len %d", ret, packet, ptr - buf);
	return ret;
}

static int send_solicitation(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_SOLICIT, "solicit");
}

static int send_dhcpv6_request(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_REQUEST, "request");
}

static int send_dhcpv6_confirm(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_CONFIRM, "confirm");
}

static int send_dhcpv6_renew(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_RENEW, "renew");
}

static int send_dhcpv6_rebind(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_REBIND, "rebind");
}

static int send_dhcpv6_decline(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_DECLINE, "decline");
}

static int send_dhcpv6_release(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_RELEASE, "release");
}

static int send_information_req(GDHCPClient *dhcp_client)
{
	return send_dhcpv6_msg(dhcp_client, DHCPV6_INFORMATION_REQ, "information-req");
}

static void remove_value(gpointer data, gpointer user_data)
{
	char *value = data;
	g_free(value);
}

static void remove_option_value(gpointer data)
{
	GList *option_value = data;

	g_list_foreach(option_value, remove_value, NULL);
	g_list_free(option_value);
}

/**
 * gdhcp_client_new:
 * @type:
 * @ifindex:
 *
 * Creates a new #GDHCPClient instance.
 *
 * Returns: (transfer full): A newly created #GDHCPClient
 */
GDHCPClient *gdhcp_client_new(GDHCPType type, int ifindex, GError **error)
{
	GDHCPClient *dhcp_client;
	GDHCPClientPrivate *priv;

	g_assert(type == G_DHCP_IPV4 || type == G_DHCP_IPV6 || type == G_DHCP_IPV4LL);
	g_assert(ifindex > 0);

	dhcp_client = g_object_new(GDHCP_TYPE_CLIENT, NULL);
	if (!dhcp_client) {
		return NULL;
	}

	priv = gdhcp_client_get_instance_private(dhcp_client);

	priv->interface = get_interface_name(ifindex);
	if (!priv->interface) {
		g_object_unref(dhcp_client);
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"Interface unavailable");
		return NULL;
	}

	if (!interface_is_up(ifindex)) {
		g_free(priv->interface);
		g_object_unref(dhcp_client);
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"Interface down");
		return NULL;
	}

	get_interface_mac_address(ifindex, priv->mac_address);

	priv->listener_sockfd = -1;
	priv->listen_mode = L_NONE;
	priv->type = type;
	priv->ifindex = ifindex;
	priv->listener_watch = 0;
	priv->retry_times = 0;
	priv->ack_retry_times = 0;
	priv->code_value_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, remove_option_value);
	priv->send_value_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	priv->request_list = NULL;
	priv->require_list = NULL;
	priv->duid = NULL;
	priv->duid_len = 0;
	priv->last_request = time(NULL);
	priv->expire = 0;
	priv->request_bcast = false;

	return dhcp_client;
}

#define SERVER_AND_CLIENT_PORTS  ((67 << 16) + 68)

static int dhcp_l2_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	/*
	 * Comment:
	 *
	 *	I've selected not to see LL header, so BPF doesn't see it, too.
	 *	The filter may also pass non-IP and non-ARP packets, but we do
	 *	a more complete check when receiving the message in userspace.
	 *
	 * and filter shamelessly stolen from:
	 *
	 *	http://www.flamewarmaster.de/software/dhcpclient/
	 *
	 * There are a few other interesting ideas on that page (look under
	 * "Motivation").  Use of netlink events is most interesting.  Think
	 * of various network servers listening for events and reconfiguring.
	 * That would obsolete sending HUP signals and/or make use of restarts.
	 *
	 * Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
	 * License: GPL v2.
	 *
	 * TODO: make conditional?
	 */
	static const struct sock_filter filter_instr[] = {
		/* check for udp */
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
		/* L5, L1, is UDP? */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 2, 0),
		/* ugly check for arp on ethernet-like and IPv4 */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 2), /* L1: */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x08000604, 3, 4),/* L3, L4 */
		/* skip IP header */
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* L5: */
		/* check udp source and destination ports */
		BPF_STMT(BPF_LD|BPF_W|BPF_IND, 0),
		/* L3, L4 */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SERVER_AND_CLIENT_PORTS, 0, 1),
		/* returns */
		BPF_STMT(BPF_RET|BPF_K, 0x0fffffff), /* L3: pass */
		BPF_STMT(BPF_RET|BPF_K, 0), /* L4: reject */
	};

	static const struct sock_fprog filter_prog = {
		.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
		/* casting const away: */
		.filter = (struct sock_filter *) filter_instr,
	};

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (SERVER_PORT == 67 && CLIENT_PORT == 68)
		/* Use only if standard ports are in use */
		setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
							sizeof(filter_prog));

	memset(&sock, 0, sizeof(sock));
	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IP);
	sock.sll_ifindex = ifindex;

	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) != 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

static bool sanity_check(struct ip_udp_dhcp_packet *packet, int bytes)
{
	if (packet->ip.protocol != IPPROTO_UDP)
		return false;

	if (packet->ip.version != IPVERSION)
		return false;

	if (packet->ip.ihl != sizeof(packet->ip) >> 2)
		return false;

	if (packet->udp.dest != htons(CLIENT_PORT))
		return false;

	if (ntohs(packet->udp.len) != (uint16_t)(bytes - sizeof(packet->ip)))
		return false;

	return true;
}

static int dhcp_recv_l2_packet(struct dhcp_packet *dhcp_pkt, int fd,
				struct sockaddr_in *dst_addr)
{
	int bytes;
	struct ip_udp_dhcp_packet packet;
	uint16_t check;

	memset(&packet, 0, sizeof(packet));

	bytes = read(fd, &packet, sizeof(packet));
	if (bytes < 0)
		return -1;

	if (bytes < (int) (sizeof(packet.ip) + sizeof(packet.udp)))
		return -1;

	if (bytes < ntohs(packet.ip.tot_len))
		/* packet is bigger than sizeof(packet), we did partial read */
		return -1;

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

	if (!sanity_check(&packet, bytes))
		return -1;

	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != dhcp_checksum(&packet.ip, sizeof(packet.ip)))
		return -1;

	/* verify UDP checksum. IP header has to be modified for this */
	memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
	packet.ip.tot_len = packet.udp.len; /* yes, this is needed */
	check = packet.udp.check;
	packet.udp.check = 0;
	if (check && check != dhcp_checksum(&packet, bytes))
		return -1;

	memcpy(dhcp_pkt, &packet.data, bytes - (sizeof(packet.ip) +
							sizeof(packet.udp)));

	if (dhcp_pkt->cookie != htonl(DHCP_MAGIC))
		return -1;

	dst_addr->sin_addr.s_addr = packet.ip.daddr;

	return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
}

static void ipv4ll_start(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	guint timeout;

	remove_timeouts(dhcp_client);

	switch_listening_mode(dhcp_client, L_NONE);
	priv->retry_times = 0;
	priv->requested_ip = 0;

	priv->requested_ip = ipv4ll_random_ip();

	/* first wait a random delay to avoid storm of arp request on boot */
	timeout = ipv4ll_random_delay_ms(PROBE_WAIT);

	priv->retry_times++;
	priv->timeout = g_timeout_add_full(G_PRIORITY_HIGH,
						timeout,
						ipv4ll_first_probe_timeout,
						dhcp_client,
						NULL);
}

static void ipv4ll_stop(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	switch_listening_mode(dhcp_client, L_NONE);

	remove_timeouts(dhcp_client);

	if (priv->listener_watch > 0) {
		g_source_remove(priv->listener_watch);
		priv->listener_watch = 0;
	}

	priv->state = IPV4LL_PROBE;
	priv->retry_times = 0;
	priv->requested_ip = 0;

	g_free(priv->assigned_ip);
	priv->assigned_ip = NULL;
}

static int ipv4ll_recv_arp_packet(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	int bytes;
	struct ether_arp arp;
	uint32_t ip_requested;
	int source_conflict;
	int target_conflict;

	memset(&arp, 0, sizeof(arp));
	bytes = read(priv->listener_sockfd, &arp, sizeof(arp));
	if (bytes < 0)
		return bytes;

	if (arp.arp_op != htons(ARPOP_REPLY) &&
			arp.arp_op != htons(ARPOP_REQUEST))
		return -EINVAL;

	if (memcmp(arp.arp_sha, priv->mac_address, ETH_ALEN) == 0)
		return 0;

	ip_requested = htonl(priv->requested_ip);
	source_conflict = !memcmp(arp.arp_spa, &ip_requested,
						sizeof(ip_requested));

	target_conflict = !memcmp(arp.arp_tpa, &ip_requested,
				sizeof(ip_requested));

	if (!source_conflict && !target_conflict)
		return 0;

	priv->conflicts++;

	debug(dhcp_client, "IPV4LL conflict detected");

	if (priv->state == IPV4LL_MONITOR) {
		if (!source_conflict)
			return 0;
		priv->state = IPV4LL_DEFEND;
		debug(dhcp_client, "DEFEND mode conflicts : %d",
			priv->conflicts);
		/* Try to defend with a single announce */
		send_announce_packet(dhcp_client);
		return 0;
	}

	if (priv->state == IPV4LL_DEFEND) {
		if (!source_conflict)
			return 0;
		else
			g_signal_emit (dhcp_client, signals[SIG_IPV4LL_LOST], 0);
	}

	ipv4ll_stop(dhcp_client);

	if (priv->conflicts < MAX_CONFLICTS) {
		/* restart whole state machine */
		priv->retry_times++;
		priv->timeout = g_timeout_add_full(G_PRIORITY_HIGH,
							ipv4ll_random_delay_ms(PROBE_WAIT),
							ipv4ll_first_probe_timeout,
							dhcp_client,
							NULL);
	} else {
		/* Here we got a lot of conflicts, RFC3927 states that we have
		* to wait RATE_LIMIT_INTERVAL before retrying,
		* but we just report failure.
		*/
		g_signal_emit (dhcp_client, signals[SIG_NO_LEASE], 0);
	}

	return 0;
}

static bool check_package_owner(GDHCPClient *dhcp_client, gpointer pkt)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (priv->type == G_DHCP_IPV6) {
		struct dhcpv6_packet *packet6 = pkt;
		uint32_t xid;

		if (!packet6)
			return false;

		xid = packet6->transaction_id[0] << 16 |
			packet6->transaction_id[1] << 8 |
			packet6->transaction_id[2];

		if (xid != priv->xid)
			return false;
	} else {
		struct dhcp_packet *packet = pkt;

		if (packet->xid != priv->xid)
			return false;

		if (packet->hlen != 6)
			return false;

		if (memcmp(packet->chaddr, priv->mac_address, 6))
			return false;
	}

	return true;
}

static void start_request(GDHCPClient *dhcp_client);

static gboolean request_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "request timeout (retries %d)", priv->retry_times);

	priv->retry_times++;

	start_request(dhcp_client);

	return FALSE;
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition, gpointer user_data);

static int switch_listening_mode(GDHCPClient *dhcp_client, ListenMode listen_mode)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GIOChannel *listener_channel;
	int listener_sockfd;

	if (priv->listen_mode == listen_mode)
		return 0;

	debug(dhcp_client, "switch listening mode (%d ==> %d)", priv->listen_mode, listen_mode);

	if (priv->listen_mode != L_NONE) {
		if (priv->listener_watch > 0)
			g_source_remove(priv->listener_watch);
		priv->listen_mode = L_NONE;
		priv->listener_sockfd = -1;
		priv->listener_watch = 0;
	}

	if (listen_mode == L_NONE)
		return 0;

	if (listen_mode == L2)
		listener_sockfd = dhcp_l2_socket(priv->ifindex);
	else if (listen_mode == L3) {
		if (priv->type == G_DHCP_IPV6)
			listener_sockfd = dhcp_l3_socket(DHCPV6_CLIENT_PORT, priv->interface, AF_INET6);
		else
			listener_sockfd = dhcp_l3_socket(CLIENT_PORT, priv->interface, AF_INET);
	} else if (listen_mode == L_ARP)
		listener_sockfd = ipv4ll_arp_socket(priv->ifindex);
	else
		return -EIO;

	if (listener_sockfd < 0)
		return -EIO;

	listener_channel = g_io_channel_unix_new(listener_sockfd);
	if (!listener_channel) {
		/* Failed to create listener channel */
		close(listener_sockfd);
		return -EIO;
	}

	priv->listen_mode = listen_mode;
	priv->listener_sockfd = listener_sockfd;

	g_io_channel_set_close_on_unref(listener_channel, TRUE);
	priv->listener_watch = g_io_add_watch_full(listener_channel, G_PRIORITY_HIGH,
								G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
								listener_event, dhcp_client, NULL);
	g_io_channel_unref(listener_channel);

	return 0;
}

static void start_request(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "start request (retries %d)", priv->retry_times);

	if (priv->retry_times == REQUEST_RETRIES) {
		g_signal_emit (dhcp_client, signals[SIG_NO_LEASE], 0);
		return;
	}

	if (priv->retry_times == 0) {
		priv->state = REQUESTING;
		switch_listening_mode(dhcp_client, L2);
	}

	send_request(dhcp_client);

	priv->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							REQUEST_TIMEOUT,
							request_timeout,
							dhcp_client,
							NULL);
}

static uint32_t get_lease(struct dhcp_packet *packet)
{
	uint8_t *option;
	uint32_t lease_seconds;

	option = dhcp_get_option(packet, DHCP_LEASE_TIME);
	if (!option)
		return 3600;

	lease_seconds = get_be32(option);

	if (lease_seconds < 10)
		lease_seconds = 10;

	return lease_seconds;
}

static void restart_dhcp(GDHCPClient *dhcp_client, int retry_times)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "restart DHCP (retries %d)", retry_times);

	remove_timeouts(dhcp_client);

	priv->retry_times = retry_times;
	priv->requested_ip = 0;
	priv->state = INIT_SELECTING;
	switch_listening_mode(dhcp_client, L2);

	gdhcp_client_start(dhcp_client, priv->last_address);
}

static gboolean start_expire(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	debug(dhcp_client, "lease expired");

	/* remove all timeouts if they are set */
	remove_timeouts(dhcp_client);

	restart_dhcp(dhcp_client, 0);

	/* ip need to be cleared */
	g_signal_emit (dhcp_client, signals[SIG_LEASE_LOST], 0);

	return false;
}

static gboolean continue_rebound(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint64_t rand;

	switch_listening_mode(dhcp_client, L2);
	send_request(dhcp_client);

	if (priv->t2_timeout> 0) {
		g_source_remove(priv->t2_timeout);
		priv->t2_timeout = 0;
	}

	/* recalculate remaining rebind time */
	priv->T2 >>= 1;
	if (priv->T2 > 60) {
		dhcp_get_random(&rand);
		priv->t2_timeout = g_timeout_add_full(G_PRIORITY_HIGH,
								priv->T2 * 1000 + (rand % 2000) - 1000,
								continue_rebound,
								dhcp_client,
								NULL);
	}

	return FALSE;
}

static gboolean start_rebound(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	/* remove renew timer */
	if (priv->t1_timeout > 0)
		g_source_remove(priv->t1_timeout);

	debug(dhcp_client, "start rebound");
	priv->state = REBINDING;

	/* calculate total rebind time */
	priv->T2 = priv->expire - priv->T2;

	/* send the first rebound and reschedule */
	continue_rebound(user_data);

	return FALSE;
}

static gboolean continue_renew (gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint64_t rand;

	switch_listening_mode(dhcp_client, L3);
	send_request(dhcp_client);

	if (priv->t1_timeout > 0)
		g_source_remove(priv->t1_timeout);

	priv->t1_timeout = 0;

	priv->T1 >>= 1;

	if (priv->T1 > 60) {
		dhcp_get_random(&rand);
		priv->t1_timeout = g_timeout_add_full(G_PRIORITY_HIGH,
								priv->T1 * 1000 + (rand % 2000) - 1000,
								continue_renew,
								dhcp_client,
								NULL);
	}

	return FALSE;
}
static gboolean start_renew(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "start renew");
	priv->state = RENEWING;

	/* calculate total renew period */
	priv->T1 = priv->T2 - priv->T1;

	/* send first renew and reschedule for half the remaining time */
	continue_renew(user_data);

	return FALSE;
}

static void start_bound(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "start bound");

	priv->state = BOUND;

	remove_timeouts(dhcp_client);

	/*
	 *TODO: T1 and T2 should be set through options instead of
	 * defaults as they are here.
	 */

	priv->T1 = priv->lease_seconds >> 1;
	priv->T2 = priv->lease_seconds * 0.875;
	priv->expire = priv->lease_seconds;

	priv->t1_timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							priv->T1,
							start_renew, dhcp_client,
							NULL);

	priv->t2_timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							priv->T2,
							start_rebound, dhcp_client,
							NULL);

	priv->lease_timeout= g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							priv->expire,
							start_expire, dhcp_client,
							NULL);
}

static gboolean restart_dhcp_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "restart DHCP timeout");

	if (priv->state == REBOOTING) {
		g_free(priv->last_address);
		priv->last_address = NULL;
		restart_dhcp(dhcp_client, 0);
	} else {
		priv->ack_retry_times++;
		restart_dhcp(dhcp_client, priv->ack_retry_times);
	}
	return FALSE;
}

static char *get_ip(uint32_t ip)
{
	struct in_addr addr;

	addr.s_addr = ip;

	return g_strdup(inet_ntoa(addr));
}

/* get a rough idea of how long an option will be */
static const uint8_t len_of_option_as_string[] = {
	[OPTION_IP] = sizeof("255.255.255.255 "),
	[OPTION_STRING] = 1,
	[OPTION_U8] = sizeof("255 "),
	[OPTION_U16] = sizeof("65535 "),
	[OPTION_U32] = sizeof("4294967295 "),
};

static int sprint_nip(char *dest, const char *pre, const uint8_t *ip)
{
	return sprintf(dest, "%s%u.%u.%u.%u", pre, ip[0], ip[1], ip[2], ip[3]);
}

/* Create "opt_value1 option_value2 ..." string */
static char *malloc_option_value_string(uint8_t *option, GDHCPOptionType type)
{
	unsigned upper_length;
	int len, optlen;
	char *dest, *ret;

	len = option[OPT_LEN - OPT_DATA];
	type &= OPTION_TYPE_MASK;
	optlen = dhcp_option_lengths[type];
	if (optlen == 0)
		return NULL;
	upper_length = len_of_option_as_string[type] *
			((unsigned)len / (unsigned)optlen);
	dest = ret = g_malloc(upper_length + 1);
	if (!ret)
		return NULL;

	while (len >= optlen) {
		switch (type) {
		case OPTION_IP:
			dest += sprint_nip(dest, "", option);
			break;
		case OPTION_U16: {
			uint16_t val_u16 = get_be16(option);
			dest += sprintf(dest, "%u", val_u16);
			break;
		}
		case OPTION_U32: {
			uint32_t val_u32 = get_be32(option);
			dest += sprintf(dest, "%u", val_u32);
			break;
		}
		case OPTION_STRING:
			memcpy(dest, option, len);
			dest[len] = '\0';
			return ret;
		default:
			break;
		}
		option += optlen;
		len -= optlen;
		if (len <= 0)
			break;
		*dest++ = ' ';
		*dest = '\0';
	}

	return ret;
}

static GList *get_option_value_list(char *value, GDHCPOptionType type)
{
	char *pos = value;
	GList *list = NULL;

	if (!pos)
		return NULL;

	if (type == OPTION_STRING)
		return g_list_append(list, g_strdup(value));

	while ((pos = strchr(pos, ' '))) {
		*pos = '\0';

		list = g_list_append(list, g_strdup(value));

		value = ++pos;
	}

	list = g_list_append(list, g_strdup(value));

	return list;
}

static inline uint32_t get_uint32(unsigned char *value)
{
	return value[0] << 24 | value[1] << 16 |
		value[2] << 8 | value[3];
}

static inline uint16_t get_uint16(unsigned char *value)
{
	return value[0] << 8 | value[1];
}

static GList *add_prefix(GDHCPClient *dhcp_client, GList *list,
			struct in6_addr *addr,
			unsigned char prefixlen, uint32_t preferred,
			uint32_t valid)
{
	GDHCPIAPrefix *ia_prefix;

	ia_prefix = g_try_new(GDHCPIAPrefix, 1);
	if (!ia_prefix)
		return list;

	{
		char addr_str[INET6_ADDRSTRLEN + 1];
		inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
		debug(dhcp_client, "prefix %s/%d preferred %u valid %u", addr_str, prefixlen, preferred, valid);
	}

	memcpy(&ia_prefix->prefix, addr, sizeof(struct in6_addr));
	ia_prefix->prefixlen = prefixlen;
	ia_prefix->preferred = preferred;
	ia_prefix->valid = valid;
	ia_prefix->expire = time(NULL) + valid;

	return g_list_prepend(list, ia_prefix);
}

static GList *get_addresses(GDHCPClient *dhcp_client,
				int code, int len,
				unsigned char *value,
				uint16_t *status)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GList *list = NULL;
	struct in6_addr addr;
	uint32_t iaid, T1 = 0, T2 = 0, preferred = 0, valid = 0;
	uint16_t option_len, option_code, st = 0, max_len;
	int addr_count = 0, prefix_count = 0, i, pos;
	unsigned char prefixlen;
	unsigned int shortest_valid = 0;
	uint8_t *option;
	char *str;

	if (!value || len < 4)
		return NULL;

	iaid = get_uint32(&value[0]);
	if (priv->iaid != iaid)
		return NULL;

	if (code == GDHCP_V6_IA_NA || code == GDHCP_V6_IA_PD) {
		T1 = get_uint32(&value[4]);
		T2 = get_uint32(&value[8]);

		if (T1 > T2)
			/* IA_NA: RFC 3315, 22.4 */
			/* IA_PD: RFC 3633, ch 9 */
			return NULL;

		pos = 12;
	} else
		pos = 4;

	if (len <= pos)
		return NULL;

	max_len = len - pos;

	debug(dhcp_client, "header %d sub-option max len %d", pos, max_len);

	/* We have more sub-options in this packet. */
	do {
		option = dhcpv6_get_sub_option(&value[pos], max_len,
					&option_code, &option_len);

		debug(dhcp_client, "pos %d option %p code %d len %d",
			pos, option, option_code, option_len);

		if (!option)
			break;

		if (pos >= len)
			break;

		switch (option_code) {
		case GDHCP_V6_IAADDR:
			i = 0;
			memcpy(&addr, &option[0], sizeof(addr));
			i += sizeof(addr);
			preferred = get_uint32(&option[i]);
			i += 4;
			valid = get_uint32(&option[i]);

			addr_count++;
			break;

		case GDHCP_V6_STATUS_CODE:
			st = get_uint16(&option[0]);
			debug(dhcp_client, "error code %d", st);
			if (option_len > 2) {
				str = g_strndup((gchar *)&option[2], option_len - 2);
				debug(dhcp_client, "error text: %s", str);
				g_free(str);
			}

			*status = st;
			break;

		case GDHCP_V6_IA_PREFIX:
			i = 0;
			preferred = get_uint32(&option[i]);
			i += 4;
			valid = get_uint32(&option[i]);
			i += 4;
			prefixlen = option[i];
			i += 1;
			memcpy(&addr, &option[i], sizeof(addr));
			i += sizeof(addr);
			if (preferred < valid) {
				/* RFC 3633, ch 10 */
				list = add_prefix(dhcp_client, list, &addr, prefixlen, preferred, valid);
				if (shortest_valid > valid)
					shortest_valid = valid;
				prefix_count++;
			}
			break;
		}

		pos += 2 + 2 + option_len;

	} while (pos < len);

	if (addr_count > 0 && st == 0) {
		/* We only support one address atm */
		char addr_str[INET6_ADDRSTRLEN + 1];

		if (preferred > valid)
			/* RFC 3315, 22.6 */
			return NULL;

		priv->T1 = T1;
		priv->T2 = T2;

		inet_ntop(AF_INET6, &addr, addr_str, INET6_ADDRSTRLEN);
		debug(dhcp_client, "address count %d addr %s T1 %u T2 %u",
			addr_count, addr_str, T1, T2);

		list = g_list_append(list, g_strdup(addr_str));

		if (code == GDHCP_V6_IA_NA)
			memcpy(&priv->ia_na, &addr, sizeof(struct in6_addr));
		else
			memcpy(&priv->ia_ta, &addr, sizeof(struct in6_addr));

		if (valid != priv->expire)
			priv->expire = valid;
	}

	if (prefix_count > 0 && list) {
		/*
		 * This means we have a list of prefixes to delegate.
		 */
		list = g_list_reverse(list);

		debug(dhcp_client, "prefix count %d T1 %u T2 %u", prefix_count, T1, T2);

		priv->T1 = T1;
		priv->T2 = T2;

		priv->expire = shortest_valid;
	}

	if (status && *status != 0)
		debug(dhcp_client, "status %d", *status);

	return list;
}

static GList *get_domains(int maxlen, unsigned char *value)
{
	GList *list = NULL;
	int pos = 0;
	unsigned char *c;
	char dns_name[NS_MAXDNAME + 1];

	if (!value || maxlen < 3)
		return NULL;

	while (pos < maxlen) {
		strncpy(dns_name, (char *)&value[pos], NS_MAXDNAME);

		c = (unsigned char *)dns_name;
		while (c && *c) {
			int jump;
			jump = *c;
			*c = '.';
			c += jump + 1;
		}
		list = g_list_prepend(list, g_strdup(&dns_name[1]));
		pos += (char *)c - dns_name + 1;
	}

	return g_list_reverse(list);
}

static GList *get_dhcpv6_option_value_list(GDHCPClient *dhcp_client,
					int code, int len,
					unsigned char *value,
					uint16_t *status)
{
	GList *list = NULL;
	char *str;
	int i;

	if (!value)
		return NULL;

	switch (code) {
	case GDHCP_V6_DNS_SERVERS:	/* RFC 3646, chapter 3 */
	case GDHCP_V6_SNTP_SERVERS:	/* RFC 4075, chapter 4 */
		if (len % 16) {
			debug(dhcp_client,
				"%s server list length (%d) is invalid",
				code == GDHCP_V6_DNS_SERVERS ? "DNS" : "SNTP",
				len);
			return NULL;
		}
		for (i = 0; i < len; i += 16) {

			str = g_try_malloc0(INET6_ADDRSTRLEN+1);
			if (!str)
				return list;

			if (!inet_ntop(AF_INET6, &value[i], str,
					INET6_ADDRSTRLEN))
				g_free(str);
			else
				list = g_list_append(list, str);
		}
		break;

	case GDHCP_V6_IA_NA:		/* RFC 3315, chapter 22.4 */
	case GDHCP_V6_IA_TA:		/* RFC 3315, chapter 22.5 */
	case GDHCP_V6_IA_PD:		/* RFC 3633, chapter 9 */
		list = get_addresses(dhcp_client, code, len, value, status);
		break;

	case GDHCP_V6_DOMAIN_LIST:
		list = get_domains(len, value);
		break;

	default:
		break;
	}

	return list;
}

static void get_dhcpv6_request(GDHCPClient *dhcp_client,
				struct dhcpv6_packet *packet,
				uint16_t pkt_len, uint16_t *status)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GList *list, *value_list;
	uint8_t *option;
	uint16_t code;
	uint16_t option_len;

	for (list = priv->request_list; list; list = list->next) {
		code = (uint16_t) GPOINTER_TO_INT(list->data);

		option = dhcpv6_get_option(packet, pkt_len, code, &option_len,
						NULL);
		if (!option) {
			g_hash_table_remove(priv->code_value_hash,
						GINT_TO_POINTER((int) code));
			continue;
		}

		value_list = get_dhcpv6_option_value_list(dhcp_client, code,
						option_len, option, status);

		debug(dhcp_client, "code %d %p len %d list %p", code, option,
			option_len, value_list);

		if (!value_list)
			g_hash_table_remove(priv->code_value_hash,
						GINT_TO_POINTER((int) code));
		else
			g_hash_table_insert(priv->code_value_hash,
				GINT_TO_POINTER((int) code), value_list);
	}
}

static void get_request(GDHCPClient *dhcp_client, struct dhcp_packet *packet)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GDHCPOptionType type;
	GList *list, *value_list;
	char *option_value;
	uint8_t *option;
	uint8_t code;

	for (list = priv->request_list; list; list = list->next) {
		code = (uint8_t) GPOINTER_TO_INT(list->data);

		option = dhcp_get_option(packet, code);
		if (!option) {
			g_hash_table_remove(priv->code_value_hash,
						GINT_TO_POINTER((int) code));
			continue;
		}

		type =  dhcp_get_code_type(code);

		option_value = malloc_option_value_string(option, type);
		if (!option_value)
			g_hash_table_remove(priv->code_value_hash,
						GINT_TO_POINTER((int) code));

		value_list = get_option_value_list(option_value, type);

		g_free(option_value);

		if (!value_list)
			g_hash_table_remove(priv->code_value_hash,
						GINT_TO_POINTER((int) code));
		else
			g_hash_table_insert(priv->code_value_hash,
				GINT_TO_POINTER((int) code), value_list);
	}
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	struct sockaddr_in dst_addr = { 0 };
	struct dhcp_packet packet;
	struct dhcpv6_packet *packet6 = NULL;
	uint8_t *message_type = NULL, *client_id = NULL, *option,
		*server_id = NULL;
	uint16_t option_len = 0, status = 0;
	uint32_t xid = 0;
	gpointer pkt;
	unsigned char buf[MAX_DHCPV6_PKT_SIZE];
	uint16_t pkt_len = 0;
	int count;
	int re;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		priv->listener_watch = 0;
		return FALSE;
	}

	if (priv->listen_mode == L_NONE)
		return FALSE;

	pkt = &packet;

	priv->status_code = 0;

	if (priv->listen_mode == L2) {
		re = dhcp_recv_l2_packet(&packet,
					priv->listener_sockfd,
					&dst_addr);
		xid = packet.xid;
	} else if (priv->listen_mode == L3) {
		if (priv->type == G_DHCP_IPV6) {
			re = dhcpv6_recv_l3_packet(&packet6, buf, sizeof(buf),
						priv->listener_sockfd);
			if (re < 0)
			    return TRUE;
			pkt_len = re;
			pkt = packet6;
			xid = packet6->transaction_id[0] << 16 |
				packet6->transaction_id[1] << 8 |
				packet6->transaction_id[2];
		} else {
			re = dhcp_recv_l3_packet(&packet,
						priv->listener_sockfd);
			xid = packet.xid;
		}
	} else if (priv->listen_mode == L_ARP) {
		ipv4ll_recv_arp_packet(dhcp_client);
		return TRUE;
	} else
		re = -EIO;

	if (re < 0)
		return TRUE;

	if (!check_package_owner(dhcp_client, pkt))
		return TRUE;

	if (priv->type == G_DHCP_IPV6) {
		if (!packet6)
			return TRUE;

		count = 0;
		client_id = dhcpv6_get_option(packet6, pkt_len,
				GDHCP_V6_CLIENTID, &option_len,	&count);

		if (!client_id || count == 0 || option_len == 0 ||
				memcmp(priv->duid, client_id,
					priv->duid_len) != 0) {
			debug(dhcp_client,
				"client duid error, discarding msg %p/%d/%d",
				client_id, option_len, count);
			return TRUE;
		}

		option = dhcpv6_get_option(packet6, pkt_len,
				GDHCP_V6_STATUS_CODE, &option_len, NULL);
		if (option != 0 && option_len > 0) {
			status = option[0]<<8 | option[1];
			if (status != 0) {
				debug(dhcp_client, "error code %d", status);
				if (option_len > 2) {
					gchar *txt = g_strndup(
						(gchar *)&option[2],
						option_len - 2);
					debug(dhcp_client, "error text: %s", txt);
					g_free(txt);
				}
			}
			priv->status_code = status;
		}
	} else {
		message_type = dhcp_get_option(&packet, DHCP_MESSAGE_TYPE);
		if (!message_type)
			return TRUE;
	}

	debug(dhcp_client, "received DHCP packet xid 0x%04x "
		"(current state %d)", ntohl(xid), priv->state);

	switch (priv->state) {
		case INIT_SELECTING:
			if (*message_type != DHCPOFFER)
				return TRUE;

			remove_timeouts(dhcp_client);
			priv->timeout = 0;
			priv->retry_times = 0;

			option = dhcp_get_option(&packet, DHCP_SERVER_ID);
			priv->server_ip = get_be32(option);
			priv->requested_ip = ntohl(packet.yiaddr);

			priv->state = REQUESTING;

			if (dst_addr.sin_addr.s_addr == INADDR_BROADCAST)
				priv->request_bcast = true;
			else
				priv->request_bcast = false;

			debug(dhcp_client, "init ip %s -> %sadding broadcast flag",
				inet_ntoa(dst_addr.sin_addr),
				priv->request_bcast ? "" : "not ");

			start_request(dhcp_client);

			return TRUE;
		case REBOOTING:
			if (dst_addr.sin_addr.s_addr == INADDR_BROADCAST)
				priv->request_bcast = true;
			else
				priv->request_bcast = false;

			debug(dhcp_client, "ip %s -> %sadding broadcast flag",
				inet_ntoa(dst_addr.sin_addr),
				priv->request_bcast ? "" : "not ");
			/* fall through */
		case REQUESTING:
		case RENEWING:
		case REBINDING:
			if (*message_type == DHCPACK) {
				priv->retry_times = 0;

				remove_timeouts(dhcp_client);

				priv->lease_seconds = get_lease(&packet);

				get_request(dhcp_client, &packet);

				switch_listening_mode(dhcp_client, L_NONE);

				g_free(priv->assigned_ip);
				priv->assigned_ip = get_ip(packet.yiaddr);

				if (priv->state == REBOOTING) {
					option = dhcp_get_option(&packet,
								DHCP_SERVER_ID);
					priv->server_ip = get_be32(option);
				}

				/* Address should be set up here */
				g_signal_emit (dhcp_client, signals[SIG_LEASE_AVAILABLE], 0);

				start_bound(dhcp_client);
			} else if (*message_type == DHCPNAK) {
				priv->retry_times = 0;

				remove_timeouts(dhcp_client);

				priv->timeout = g_timeout_add_seconds_full(
									G_PRIORITY_HIGH, 3,
									restart_dhcp_timeout,
									dhcp_client,
									NULL);
			}

			break;
		case SOLICITATION:
			if (priv->type != G_DHCP_IPV6)
				return TRUE;

			if (packet6->message != DHCPV6_REPLY &&
					packet6->message != DHCPV6_ADVERTISE)
				return TRUE;

			count = 0;
			server_id = dhcpv6_get_option(packet6, pkt_len,
					GDHCP_V6_SERVERID, &option_len,	&count);
			if (!server_id || count != 1 || option_len == 0) {
				/* RFC 3315, 15.10 */
				debug(dhcp_client,
					"server duid error, discarding msg %p/%d/%d",
					server_id, option_len, count);
				return TRUE;
			}
			priv->server_duid = g_try_malloc(option_len);
			if (!priv->server_duid)
				return TRUE;
			memcpy(priv->server_duid, server_id, option_len);
			priv->server_duid_len = option_len;

			if (packet6->message == DHCPV6_REPLY) {
				uint8_t *rapid_commit;
				count = 0;
				option_len = 0;
				rapid_commit = dhcpv6_get_option(packet6, pkt_len,
								GDHCP_V6_RAPID_COMMIT,
								&option_len, &count);
				if (!rapid_commit || option_len != 0 ||
									count != 1)
					/* RFC 3315, 17.1.4 */
					return TRUE;
			}

			switch_listening_mode(dhcp_client, L_NONE);

			if (priv->status_code == 0)
				get_dhcpv6_request(dhcp_client, packet6, pkt_len,
						&priv->status_code);

			if (packet6->message == DHCPV6_ADVERTISE) {
				g_signal_emit (dhcp_client, signals[SIG_ADVERTISE], 0);
				return TRUE;
			}

			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_SOLICITATION], 0, FALSE)) {
				/*
				* The dhcp_client might not be valid after the
				* callback call so just return immediately.
				*/
				g_signal_emit (dhcp_client, signals[SIG_SOLICITATION], 0);
				return TRUE;
			}
			break;
		case REBIND:
			if (priv->type != G_DHCP_IPV6)
				return TRUE;

			server_id = dhcpv6_get_option(packet6, pkt_len,
					GDHCP_V6_SERVERID, &option_len,	&count);
			if (!priv->server_duid && server_id &&
									count == 1) {
				/*
				* If we do not have server duid yet, then get it now.
				* Prefix delegation renew support needs it.
				*/
				priv->server_duid = g_try_malloc(option_len);
				if (!priv->server_duid)
					return TRUE;
				memcpy(priv->server_duid, server_id, option_len);
				priv->server_duid_len = option_len;
			}
			/* fall through */
		case INFORMATION_REQ:
		case REQUEST:
		case RENEW:
		case RELEASE:
		case CONFIRM:
		case DECLINE:
			if (priv->type != G_DHCP_IPV6)
				return TRUE;

			if (packet6->message != DHCPV6_REPLY)
				return TRUE;

			count = 0;
			option_len = 0;
			server_id = dhcpv6_get_option(packet6, pkt_len,
					GDHCP_V6_SERVERID, &option_len, &count);
			if (!server_id || count != 1 || option_len == 0 ||
					(priv->server_duid_len > 0 &&
					memcmp(priv->server_duid, server_id,
						priv->server_duid_len) != 0)) {
				/* RFC 3315, 15.10 */
				debug(dhcp_client,
					"server duid error, discarding msg %p/%d/%d",
					server_id, option_len, count);
				return TRUE;
			}

			switch_listening_mode(dhcp_client, L_NONE);

			get_dhcpv6_request(dhcp_client, packet6, pkt_len, &priv->status_code);

			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_INFORMATION_REQ], 0, FALSE)) {
				/*
				* The dhcp_client might not be valid after the
				* callback call so just return immediately.
				*/
				g_signal_emit (dhcp_client, signals[SIG_INFORMATION_REQ], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_REQUEST], 0, FALSE)) {
				g_signal_emit (dhcp_client, signals[SIG_REQUEST], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_RENEW], 0, FALSE)) {
				g_signal_emit (dhcp_client, signals[SIG_RENEW], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_REBIND], 0, FALSE)) {
				g_signal_emit (dhcp_client, signals[SIG_REBIND], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_RELEASE], 0, FALSE)) {
				g_signal_emit (dhcp_client, signals[SIG_RELEASE], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_DECLINE], 0, FALSE)) {
				g_signal_emit (dhcp_client, signals[SIG_DECLINE], 0);
				return TRUE;
			}
			if (g_signal_has_handler_pending (dhcp_client, signals[SIG_CONFIRM], 0, FALSE)) {
				count = 0;
				server_id = dhcpv6_get_option(packet6, pkt_len,
							GDHCP_V6_SERVERID, &option_len,
							&count);
				if (!server_id || count != 1 ||
								option_len == 0) {
					/* RFC 3315, 15.10 */
					debug(dhcp_client,
						"confirm server duid error, "
						"discarding msg %p/%d/%d",
						server_id, option_len, count);
					return TRUE;
				}
				priv->server_duid = g_try_malloc(option_len);
				if (!priv->server_duid)
					return TRUE;
				memcpy(priv->server_duid, server_id, option_len);
				priv->server_duid_len = option_len;

				g_signal_emit (dhcp_client, signals[SIG_CONFIRM], 0);
				return TRUE;
			}
			break;
		default:
			break;
	}

	debug(dhcp_client, "processed DHCP packet (new state %d)", priv->state);

	return TRUE;
}

static gboolean discover_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	priv->retry_times++;

	/*
	 * We do not send the REQUESTED IP option if we are retrying because
	 * if the server is non-authoritative it will ignore the request if the
	 * option is present.
	 */
	gdhcp_client_start(dhcp_client, NULL);

	return FALSE;
}

static gboolean reboot_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	priv->retry_times = 0;
	priv->requested_ip = 0;
	priv->state = INIT_SELECTING;

	/*
	 * We do not send the REQUESTED IP option because the server didn't
	 * respond when we send DHCPREQUEST with the REQUESTED IP option in
	 * init-reboot state
	 */
	gdhcp_client_start(dhcp_client, NULL);

	return FALSE;
}

static gboolean ipv4ll_defend_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "back to MONITOR mode");

	priv->conflicts = 0;
	priv->state = IPV4LL_MONITOR;

	return FALSE;
}

static gboolean ipv4ll_announce_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint32_t ip;

	debug(dhcp_client, "request timeout (retries %d)", priv->retry_times);

	if (priv->retry_times != ANNOUNCE_NUM) {
		priv->retry_times++;
		send_announce_packet(dhcp_client);
		return FALSE;
	}

	ip = htonl(priv->requested_ip);
	debug(dhcp_client, "switching to monitor mode");
	priv->state = IPV4LL_MONITOR;
	priv->assigned_ip = get_ip(ip);

	g_signal_emit (dhcp_client, signals[SIG_IPV4LL_AVAILABLE], 0);
	priv->conflicts = 0;
	priv->timeout = 0;

	return FALSE;
}

static gboolean ipv4ll_first_probe_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	send_probe_packet(dhcp_client);

	return FALSE;
}

static gboolean ipv4ll_probe_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	debug(dhcp_client, "IPV4LL probe timeout (retries %d)", priv->retry_times);

	if (priv->retry_times == PROBE_NUM) {
		priv->state = IPV4LL_ANNOUNCE;
		priv->retry_times = 0;

		priv->retry_times++;
		send_announce_packet(dhcp_client);
		return FALSE;
	}
	priv->retry_times++;
	send_probe_packet(dhcp_client);

	return FALSE;
}

int gdhcp_client_start(GDHCPClient *dhcp_client, const char *last_address)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	int re;
	uint32_t addr;
	uint64_t rand;

	remove_timeouts(dhcp_client);

	if (priv->type == G_DHCP_IPV6) {
		if (g_signal_has_handler_pending (dhcp_client, signals[SIG_INFORMATION_REQ], 0, FALSE)) {
			priv->state = INFORMATION_REQ;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_information_req(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_SOLICITATION], 0, FALSE)) {
			priv->state = SOLICITATION;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_solicitation(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_REQUEST], 0, FALSE)) {
			priv->state = REQUEST;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_request(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_CONFIRM], 0, FALSE)) {
			priv->state = CONFIRM;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_confirm(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_RENEW], 0, FALSE)) {
			priv->state = RENEW;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_renew(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_REBIND], 0, FALSE)) {
			priv->state = REBIND;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_rebind(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_RELEASE], 0, FALSE)) {
			priv->state = RENEW;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_release(dhcp_client);

		} else if (g_signal_has_handler_pending (dhcp_client, signals[SIG_DECLINE], 0, FALSE)) {
			priv->state = DECLINE;
			re = switch_listening_mode(dhcp_client, L3);
			if (re != 0) {
				switch_listening_mode(dhcp_client, L_NONE);
				priv->state = 0;
				return re;
			}
			send_dhcpv6_decline(dhcp_client);
		}

		return 0;
	}
	else if (priv->type == G_DHCP_IPV4LL) {
		priv->state = INIT_SELECTING;
		ipv4ll_start(dhcp_client);
		return 0;
	}
	else {
		if (priv->retry_times == DISCOVER_RETRIES) {
			g_signal_emit (dhcp_client, signals[SIG_NO_LEASE], 0);
			priv->retry_times = 0;
			return 0;
		}

		if (priv->retry_times == 0) {
			g_free(priv->assigned_ip);
			priv->assigned_ip = NULL;

			priv->state = INIT_SELECTING;
			re = switch_listening_mode(dhcp_client, L2);
			if (re != 0)
				return re;

			dhcp_get_random(&rand);
			priv->xid = rand;
			priv->start = time(NULL);
		}

		if (!last_address) {
			addr = 0;
		} else {
			addr = ntohl(inet_addr(last_address));
			if (addr == 0xFFFFFFFF || ((addr & LINKLOCAL_ADDR) == LINKLOCAL_ADDR)) {
				addr = 0;
			} else if (priv->last_address != last_address) {
				g_free(priv->last_address);
				priv->last_address = g_strdup(last_address);
			}
		}

		if (addr != 0) {
			debug(dhcp_client, "DHCP client start with state init_reboot");
			priv->requested_ip = addr;
			priv->state = REBOOTING;
			send_request(dhcp_client);
			priv->timeout = g_timeout_add_seconds_full(
									G_PRIORITY_HIGH,
									REQUEST_TIMEOUT,
									reboot_timeout,
									dhcp_client,
									NULL);
			return 0;
		} else {
			send_discover(dhcp_client, addr);
			priv->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
									DISCOVER_TIMEOUT,
									discover_timeout,
									dhcp_client,
									NULL);
			return 0;
		}
	}
}

void gdhcp_client_stop(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	switch_listening_mode(dhcp_client, L_NONE);

	if (priv->state == BOUND ||
			priv->state == RENEWING ||
				priv->state == REBINDING) {
		send_release(dhcp_client, priv->server_ip, priv->requested_ip);
	}

	remove_timeouts(dhcp_client);

	if (priv->listener_watch > 0) {
		g_source_remove(priv->listener_watch);
		priv->listener_watch = 0;
	}

	priv->retry_times = 0;
	priv->ack_retry_times = 0;

	priv->requested_ip = 0;
	priv->state = RELEASED;
	priv->lease_seconds = 0;
	priv->request_bcast = false;
}

GList *gdhcp_client_get_option(GDHCPClient *dhcp_client, unsigned char option_code)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return g_hash_table_lookup(priv->code_value_hash, GINT_TO_POINTER((int) option_code));
}

int gdhcp_client_get_index(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return priv->ifindex;
}

char *gdhcp_client_get_server_address(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return get_ip(priv->server_ip);
}

char *gdhcp_client_get_address(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return g_strdup(priv->assigned_ip);
}

char *gdhcp_client_get_netmask(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	GList *option = NULL;

	if (priv->type == G_DHCP_IPV6)
		return NULL;

	switch (priv->state) {
		case IPV4LL_DEFEND:
		case IPV4LL_MONITOR:
			return g_strdup("255.255.0.0");
		case BOUND:
		case RENEWING:
		case REBINDING:
			option = gdhcp_client_get_option(dhcp_client, GDHCP_SUBNET);
			if (option)
				return g_strdup(option->data);
		case INIT_SELECTING:
		case REBOOTING:
		case REQUESTING:
		case RELEASED:
		case IPV4LL_PROBE:
		case IPV4LL_ANNOUNCE:
		case INFORMATION_REQ:
		case SOLICITATION:
		case REQUEST:
		case CONFIRM:
		case RENEW:
		case REBIND:
		case RELEASE:
		case DECLINE:
			break;
	}
	return NULL;
}

void gdhcp_client_set_request(GDHCPClient *dhcp_client, unsigned int option_code)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (!g_list_find(priv->request_list, GINT_TO_POINTER((int)option_code)))
		priv->request_list = g_list_prepend(priv->request_list, (GINT_TO_POINTER((int) option_code)));
}

void gdhcp_client_clear_requests(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_list_free(priv->request_list);
	priv->request_list = NULL;
}

void gdhcp_client_clear_values(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_hash_table_remove_all(priv->send_value_hash);
}

static uint8_t *alloc_dhcp_option(int code, const uint8_t *data, unsigned size)
{
	uint8_t *storage;

	storage = g_try_malloc(size + OPT_DATA);
	if (!storage)
		return NULL;

	storage[OPT_CODE] = code;
	storage[OPT_LEN] = size;
	memcpy(&storage[OPT_DATA], data, size);

	return storage;
}

static uint8_t *alloc_dhcp_data_option(int code, const uint8_t *data,
					unsigned size)
{
	return alloc_dhcp_option(code, data, MIN(size, 255));
}

static uint8_t *alloc_dhcp_string_option(int code, const char *str)
{
	return alloc_dhcp_data_option(code, (const uint8_t *)str, strlen(str));
}

void gdhcp_client_set_id(GDHCPClient *dhcp_client, GError **error)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	const unsigned maclen = 6;
	const unsigned idlen = maclen + 1;
	const uint8_t option_code = GDHCP_CLIENT_ID;
	uint8_t idbuf[idlen];
	uint8_t *data_option;

	idbuf[0] = ARPHRD_ETHER;

	memcpy(&idbuf[1], priv->mac_address, maclen);

	data_option = alloc_dhcp_data_option(option_code, idbuf, idlen);
	if (!data_option) {
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"No memory");
		return;
	}

	g_hash_table_insert(priv->send_value_hash, GINT_TO_POINTER((int) option_code), data_option);
}

/* Now only support send hostname and vendor class ID */
void gdhcp_client_set_send(GDHCPClient *dhcp_client,
		unsigned char option_code, const char *option_value, GError **error)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	uint8_t *binary_option;

	if ((option_code == GDHCP_HOST_NAME || option_code == GDHCP_VENDOR_CLASS_ID) && option_value) {
		binary_option = alloc_dhcp_string_option(option_code, option_value);
		if (!binary_option) {
			g_set_error_literal(error,
					g_quark_from_string("fixme"),
					1,
					"No memory");
			return;
		}

		g_hash_table_insert(priv->send_value_hash, GINT_TO_POINTER((int) option_code), binary_option);
	}
}

static uint8_t *alloc_dhcpv6_option(uint16_t code, uint8_t *option, uint16_t len)
{
	uint8_t *storage;

	storage = g_malloc(2 + 2 + len);
	if (!storage)
		return NULL;

	storage[0] = code >> 8;
	storage[1] = code & 0xff;
	storage[2] = len >> 8;
	storage[3] = len & 0xff;
	memcpy(storage + 2 + 2, option, len);

	return storage;
}

gboolean gdhcp_v6_client_clear_send(GDHCPClient *dhcp_client, uint16_t code)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);
	return g_hash_table_remove(priv->send_value_hash, GINT_TO_POINTER((int)code));
}

void gdhcp_v6_client_set_send(GDHCPClient *dhcp_client,
					uint16_t option_code,
					uint8_t *option_value,
					uint16_t option_len)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	if (option_value) {
		uint8_t *binary_option;

		debug(dhcp_client, "setting option %d to %p len %d",
			option_code, option_value, option_len);

		binary_option = alloc_dhcpv6_option(option_code, option_value,
						option_len);
		if (binary_option)
			g_hash_table_insert(priv->send_value_hash,
					GINT_TO_POINTER((int) option_code),
					binary_option);
	}
}

void gdhcp_v6_client_reset_request(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	priv->last_request = time(NULL);
}

uint16_t gdhcp_v6_client_get_status(GDHCPClient *dhcp_client)
{
	GDHCPClientPrivate *priv = gdhcp_client_get_instance_private(dhcp_client);

	g_assert(priv->type == G_DHCP_IPV6);

	return priv->status_code;
}

static GDHCPIAPrefix *copy_prefix(gpointer data)
{
	GDHCPIAPrefix *copy, *prefix = data;

	copy = g_try_new(GDHCPIAPrefix, 1);
	if (!copy)
		return NULL;

	memcpy(copy, prefix, sizeof(GDHCPIAPrefix));

	return copy;
}

GSList *gdhcp_v6_copy_prefixes(GSList *prefixes)
{
	GSList *copy = NULL;
	GSList *list;

	for (list = prefixes; list; list = list->next)
		copy = g_slist_prepend(copy, copy_prefix(list->data));

	return copy;
}
