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

#include <netconfig/gncm_nameserver.h>
#include <netconfig/gncm_internal_network.h>
#include <netconfig/gncm_hotspot.h>

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
GncmManager *gncm_manager_get();

LIBGNCM_EXTERN
void gncm_manager_add_nameserver(GncmManager *manager, GncmNameserver *nameserver);

LIBGNCM_EXTERN
void gncm_manager_remove_nameserver(GncmManager *manager, GncmNameserver *nameserver);

LIBGNCM_EXTERN
void gncm_manager_add_internal_network(GncmManager *manager, GncmInternalNetwork *internal_network);

LIBGNCM_EXTERN
void gncm_manager_remove_internal_network(GncmManager *manager, GncmInternalNetwork *internal_network);

LIBGNCM_EXTERN
void gncm_manager_add_hotspot(GncmManager *manager, GncmHotspot *hotspot, const gchar *interface);

LIBGNCM_EXTERN
void gncm_manager_remove_hotspot(GncmManager *manager, GncmHotspot *hotspot);















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

