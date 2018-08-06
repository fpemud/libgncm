/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#ifndef __GNCM_NAMESERVER_H__
#define __GNCM_NAMESERVER_H__

#include "nm-setting-connection.h"

typedef enum {
	NM_DNS_IP_CONFIG_TYPE_REMOVED = -1,

	NM_DNS_IP_CONFIG_TYPE_DEFAULT = 0,
	NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE,
	NM_DNS_IP_CONFIG_TYPE_VPN,
} NMDnsIPConfigType;

enum {
	NM_DNS_PRIORITY_DEFAULT_NORMAL  = 100,
	NM_DNS_PRIORITY_DEFAULT_VPN     = 50,
};

struct _GncmNameserver;

typedef struct {
	struct _NMDnsConfigData *data;
	NMIPConfig *ip_config;
	CList data_lst;
	CList ip_config_lst;
	NMDnsIPConfigType ip_config_type;
	struct {
		const char **search;
		char **reverse;
	} domains;
} NMDnsIPConfigData;

#define GNCM_TYPE_NAMESERVER (gncm_nameserver_get_type ())
#define GNCM_NAMESERVER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), GNCM_TYPE_NAMESERVER, GncmNameserver))
#define GNCM_NAMESERVER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), GNCM_TYPE_NAMESERVER, GncmNameserverClass))
#define GNCM_IS_NAMESERVER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), GNCM_TYPE_NAMESERVER))
#define GNCM_IS_NAMESERVER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), GNCM_TYPE_NAMESERVER))
#define GNCM_NAMESERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GNCM_TYPE_NAMESERVER, GncmNameserverClass))

typedef struct _GncmNameserver GncmNameserver;
typedef struct _GncmNameserverClass GncmNameserverClass;

GType gncm_nameserver_get_type (void);

GncmNameserver *gncm_nameserver_new (const gchar *nameserver_address, int priority);

GncmNameserver *gncm_nameserver_new_with_domains (const gchar *nameserver_address, int priority, GList *domain_list);

void gncm_nameserver_add_domain (GncmNameserver *self, const gchar *domain);

void gncm_nameserver_remove_domain (GncmNameserver *self, const gchar *domain);

void gncm_nameserver_set_domain_list (GncmNameserver *self, GList *domain_list);

#endif /* __GNCM_NAMESERVER_H__ */
