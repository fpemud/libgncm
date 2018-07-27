/*
 *
 *  DHCP library with GLib integration
 *
 *  Copyright (C) 2009-2013  Intel Corporation. All rights reserved.
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

#ifndef __LIBGNCM_H__
#define __LIBGNCM_H__

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib-object.h>

#define LIBGNCM_INSIDE
# include "gdhcp-version.h"
#undef LIBGNCM_INSIDE

G_BEGIN_DECLS

#ifndef LIBGNCM_EXTERN
#define LIBGNCM_EXTERN
#endif

#define GNCM_TYPE_MANAGER  (gncm_manager_get_type())
#define GNCM_MANAGER_ERROR (gncm_manager_error_quark())

LIBGNCM_EXTERN
G_DECLARE_DERIVABLE_TYPE (GncmManager, gncm_manager, GNCM, MANAGER, GObject)

struct _GncmManagerClass
{
  GObjectClass parent_class;
};

LIBGNCM_EXTERN
int gncm_manager_add_nameserver(GncmManager *manager, const char *nameserver_address);

LIBGNCM_EXTERN
void gdhcp_client_stop(GDHCPClient *client);

LIBGNCM_EXTERN
void gdhcp_client_set_request(GDHCPClient *client, unsigned int option_code);

LIBGNCM_EXTERN
void gdhcp_client_clear_requests(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
void gdhcp_client_clear_values(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
void gdhcp_client_set_id(GDHCPClient *client, GError **error);

LIBGNCM_EXTERN
void gdhcp_client_set_send(GDHCPClient *client, unsigned char option_code, const char *option_value, GError **error);

LIBGNCM_EXTERN
char *gdhcp_client_get_server_address(GDHCPClient *client);

LIBGNCM_EXTERN
char *gdhcp_client_get_address(GDHCPClient *client);

LIBGNCM_EXTERN
char *gdhcp_client_get_netmask(GDHCPClient *client);

LIBGNCM_EXTERN
GList *gdhcp_client_get_option(GDHCPClient *client, unsigned char option_code);

LIBGNCM_EXTERN
int gdhcp_client_get_index(GDHCPClient *client);

LIBGNCM_EXTERN
int gdhcp_v6_create_duid(GDHCPDuidType duid_type, int index, int type, unsigned char **duid, int *duid_len);

LIBGNCM_EXTERN
int gdhcp_v6_client_set_duid(GDHCPClient *dhcp_client, unsigned char *duid, int duid_len);

LIBGNCM_EXTERN
int gdhcp_v6_client_set_pd(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, GSList *prefixes);

LIBGNCM_EXTERN
GSList *gdhcp_v6_copy_prefixes(GSList *prefixes);

LIBGNCM_EXTERN
gboolean gdhcp_v6_client_clear_send(GDHCPClient *dhcp_client, uint16_t code);

LIBGNCM_EXTERN
void gdhcp_v6_client_set_send(GDHCPClient *dhcp_client, uint16_t option_code, uint8_t *option_value, uint16_t option_len);

LIBGNCM_EXTERN
uint16_t gdhcp_v6_client_get_status(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
int gdhcp_v6_client_set_oro(GDHCPClient *dhcp_client, int args, ...);

LIBGNCM_EXTERN
void gdhcp_v6_client_create_iaid(GDHCPClient *dhcp_client, int index, unsigned char *iaid);

LIBGNCM_EXTERN
int gdhcp_v6_client_get_timeouts(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, time_t *started, time_t *expire);

LIBGNCM_EXTERN
uint32_t gdhcp_v6_client_get_iaid(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
void gdhcp_v6_client_set_iaid(GDHCPClient *dhcp_client, uint32_t iaid);

LIBGNCM_EXTERN
int gdhcp_v6_client_set_ia(GDHCPClient *dhcp_client, int index, int code, uint32_t *T1, uint32_t *T2, bool add_addresses, const char *address);

LIBGNCM_EXTERN
int gdhcp_v6_client_set_ias(GDHCPClient *dhcp_client, int index, int code, uint32_t *T1, uint32_t *T2, GSList *addresses);

LIBGNCM_EXTERN
void gdhcp_v6_client_reset_request(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
void gdhcp_v6_client_set_retransmit(GDHCPClient *dhcp_client);

LIBGNCM_EXTERN
void gdhcp_v6_client_clear_retransmit(GDHCPClient *dhcp_client);


