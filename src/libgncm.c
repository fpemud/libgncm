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

typedef struct {
} GncmManagerPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (GncmManager, gdhcp_client, G_TYPE_OBJECT)

BYX_DEFINE_SINGLETON_GETTER (GncmManager, gncm_manager_get, GNCM_TYPE_MANAGER);

static void gncm_manager_class_init(GncmManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    object_class->dispose = gncm_manager_dispose;
}

static void gncm_manager_init (GncmManager *dhcp_client)
{
}

static void gncm_manager_dispose(GObject *object)
{
    GncmManager *dhcp_client = (GncmManager *)object;
    GncmManagerPrivate *priv = gncm_manager_get_instance_private(dhcp_client);

    /* */

    G_OBJECT_CLASS (gncm_manager_parent_class)->dispose(object);
}
