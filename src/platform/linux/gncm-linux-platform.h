/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* gncm-linux-platform.h - Linux kernel & udev network configuration layer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __GNCM_LINUX_PLATFORM_H__
#define __GNCM_LINUX_PLATFORM_H__

#include "gncm-platform.h"

#define GNCM_TYPE_LINUX_PLATFORM            (gncm_linux_platform_get_type ())
#define GNCM_LINUX_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GNCM_TYPE_LINUX_PLATFORM, GncmLinuxPlatform))
#define GNCM_LINUX_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GNCM_TYPE_LINUX_PLATFORM, GncmLinuxPlatformClass))
#define GNCM_IS_LINUX_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GNCM_TYPE_LINUX_PLATFORM))
#define GNCM_IS_LINUX_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GNCM_TYPE_LINUX_PLATFORM))
#define GNCM_LINUX_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GNCM_TYPE_LINUX_PLATFORM, GncmLinuxPlatformClass))

typedef struct _GncmLinuxPlatform GncmLinuxPlatform;
typedef struct _GncmLinuxPlatformClass GncmLinuxPlatformClass;

GType gncm_linux_platform_get_type (void);

NMPlatform *gncm_linux_platform_new (gboolean log_with_ptr, gboolean netns_support);

void gncm_linux_platform_setup (void);

#endif /* __GNCM_LINUX_PLATFORM_H__ */
