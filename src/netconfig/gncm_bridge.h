/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* GNCM -- Global Network Config Management Library
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

#ifndef __GNCM_INTERNAL_NETWORK_H__
#define __GNCM_INTERNAL_NETWORK_H__

#include "nm-setting-connection.h"

typedef enum {
	GNCM_INTERNAL_NETWORK_BRIDGE,
	GNCM_INTERNAL_NETWORK_NAT,
	GNCM_INTERNAL_NETWORK_ROUTE,
	GNCM_INTERNAL_NETWORK_ISOLATE,
} GncmInternalNetworkType;

struct _GncmInternalNetwork;

#define GNCM_TYPE_INTERNAL_NETWORK (gncm_internal_network_get_type ())
#define GNCM_INTERNAL_NETWORK(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), GNCM_TYPE_INTERNAL_NETWORK, GncmInternalNetwork))
#define GNCM_INTERNAL_NETWORK_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), GNCM_TYPE_INTERNAL_NETWORK, GncmInternalNetworkClass))
#define GNCM_IS_INTERNAL_NETWORK(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), GNCM_TYPE_INTERNAL_NETWORK))
#define GNCM_IS_INTERNAL_NETWORK_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), GNCM_TYPE_INTERNAL_NETWORK))
#define GNCM_INTERNAL_NETWORK_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GNCM_TYPE_INTERNAL_NETWORK, GncmInternalNetworkClass))

typedef struct _GncmInternalNetwork GncmInternalNetwork;
typedef struct _GncmInternalNetworkClass GncmInternalNetworkClass;

GType gncm_internal_network_get_type (void);

GncmInternalNetwork *gncm_internal_network_new (GncmInternalNetworkType internal_network_type, const gchar *network_name);

void gncm_internal_network_add_interface (GncmInternalNetwork *self, const gchar *interface);

void gncm_internal_network_remove_interface (GncmInternalNetwork *self, const gchar *interface);

#endif /* __GNCM_INTERNAL_NETWORK_H__ */
