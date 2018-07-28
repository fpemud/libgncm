/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* platform.c - Handle runtime kernel networking configuration
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
 * Copyright (C) 2009 - 2018.
 */

#ifndef __GNCM_PLATFORM_H__
#define __GNCM_PLATFORM_H__

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/ip6_tunnel.h>

#define GNCM_TYPE_PLATFORM            (gncm_platform_get_type ())
#define GNCM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GNCM_TYPE_PLATFORM, GncmPlatform))
#define GNCM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GNCM_TYPE_PLATFORM, GncmPlatformClass))
#define GNCM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GNCM_TYPE_PLATFORM))
#define GNCM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GNCM_TYPE_PLATFORM))
#define GNCM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GNCM_TYPE_PLATFORM, GncmPlatformClass))

typedef enum {
	/* compare fields which kernel considers as similar routes.
	 * It is a looser comparisong then GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_ID
	 * and means that `ip route add` would fail to add two routes
	 * that have the same GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID.
	 * On the other hand, `ip route append` would allow that, as
	 * long as GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_ID differs. */
	GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID,

	/* compare two routes as kernel would allow to add them with
	 * `ip route append`. In other words, kernel does not allow you to
	 * add two routes (at the same time) which compare equal according
	 * to GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_ID.
	 *
	 * For the ID we can only recognize route fields that we actually implement.
	 * However, kernel supports more routing options, some of them also part of
	 * the ID. NetworkManager is oblivious to these options and will wrongly think
	 * that two routes are idential, while they are not. That can lead to an
	 * inconsistent platform cache. Not much what we can do about that, except
	 * implementing all options that kernel supports *sigh*. See rh#1337860.
	 */
	GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_ID,

	/* compare all fields as they make sense for kernel. For example,
	 * a route destination 192.168.1.5/24 is not accepted by kernel and
	 * we treat it identical to 192.168.1.0/24. Semantically these
	 * routes are identical, but GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL will
	 * report them as different.
	 *
	 * The result shall be identical to call first gncm_platform_ip_route_normalize()
	 * on both routes and then doing a full comparison. */
	GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY,

	/* compare all fields. This should have the same effect as memcmp(),
	 * except allowing for undefined data in holes between field alignment.
	 */
	GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL,

} GncmPlatformIPRouteCmpType;

typedef enum { /*< skip >*/

	/* dummy value, to enforce that the enum type is signed and has a size
	 * to hold an integer. We want to encode errno from <errno.h> as negative
	 * values. */
	_GNCM_PLATFORM_ERROR_MININT = G_MININT,

	GNCM_PLATFORM_ERROR_SUCCESS = 0,

	GNCM_PLATFORM_ERROR_BUG,

	GNCM_PLATFORM_ERROR_UNSPECIFIED,

	GNCM_PLATFORM_ERROR_NOT_FOUND,
	GNCM_PLATFORM_ERROR_EXISTS,
	GNCM_PLATFORM_ERROR_WRONG_TYPE,
	GNCM_PLATFORM_ERROR_NOT_SLAVE,
	GNCM_PLATFORM_ERROR_NO_FIRMWARE,
	GNCM_PLATFORM_ERROR_OPNOTSUPP,
	GNCM_PLATFORM_ERROR_NETLINK,
	GNCM_PLATFORM_ERROR_CANT_SET_MTU,
} GncmPlatformError;

typedef enum {

	/* match-flags are strictly inclusive. That means,
	 * by default nothing is matched, but if you enable a particular
	 * flag, a candidate that matches passes the check.
	 *
	 * In other words: adding more flags can only extend the result
	 * set of matching objects.
	 *
	 * Also, the flags form partitions. Like, an address can be either of
	 * ADDRTYPE_NORMAL or ADDRTYPE_LINKLOCAL, but never both. Same for
	 * the ADDRSTATE match types.
	 */
	GNCM_PLATFORM_MATCH_WITH_NONE                                 = 0,

	GNCM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL                      = (1LL <<  0),
	GNCM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL                   = (1LL <<  1),
	GNCM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY                        =   GNCM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL
	                                                              | GNCM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL,

	GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL                     = (1LL <<  2),
	GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE                  = (1LL <<  3),
	GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED                  = (1LL <<  4),
	GNCM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY                       =   GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL
	                                                              | GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE
	                                                              | GNCM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED,
} GncmPlatformMatchFlags;

struct _GncmPlatformLink {
	__GncmPlatformObject_COMMON;
	char name[IFNAMSIZ];
	NMLinkType type;

	/* rtnl_link_get_type(), IFLA_INFO_KIND. */
	/* GncmPlatform initializes this field with a static string. */
	const char *kind;

	/* GncmPlatform initializes this field with a static string. */
	const char *driver;

	int master;

	/* rtnl_link_get_link(), IFLA_LINK.
	 * If IFLA_LINK_NETNSID indicates that the parent is in another namespace,
	 * this field be set to (negative) GNCM_PLATFORM_LINK_OTHER_NETNS. */
	int parent;

	/* IFF_* flags. Note that the flags in 'struct ifinfomsg' are declared as 'unsigned'. */
	guint n_ifi_flags;

	guint mtu;

	/* rtnl_link_get_arptype(), ifinfomsg.ifi_type. */
	guint32 arptype;

	/* rtnl_link_get_addr(), IFLA_ADDRESS */
	struct {
		guint8 data[20]; /* NM_UTILS_HWADDR_LEN_MAX */
		guint8 len;
	} addr;

	/* rtnl_link_inet6_get_token(), IFLA_INET6_TOKEN */
	NMUtilsIPv6IfaceId inet6_token;

	/* The bitwise inverse of rtnl_link_inet6_get_addr_gen_mode(). It is inverse
	 * to have a default of 0 -- meaning: unspecified. That way, a struct
	 * initialized with memset(0) has and unset value.*/
	guint8 inet6_addr_gen_mode_inv;

	/* Statistics */
	guint64 rx_packets;
	guint64 rx_bytes;
	guint64 tx_packets;
	guint64 tx_bytes;

	/* @connected is mostly identical to (@n_ifi_flags & IFF_UP). Except for bridge/bond masters,
	 * where we coerce the link as disconnect if it has no slaves. */
	bool connected:1;

	bool initialized:1;
};

typedef enum { /*< skip >*/
	GNCM_PLATFORM_SIGNAL_ID_NONE,
	GNCM_PLATFORM_SIGNAL_ID_LINK,
	GNCM_PLATFORM_SIGNAL_ID_IP4_ADDRESS,
	GNCM_PLATFORM_SIGNAL_ID_IP6_ADDRESS,
	GNCM_PLATFORM_SIGNAL_ID_IP4_ROUTE,
	GNCM_PLATFORM_SIGNAL_ID_IP6_ROUTE,
	GNCM_PLATFORM_SIGNAL_ID_QDISC,
	GNCM_PLATFORM_SIGNAL_ID_TFILTER,
	_GNCM_PLATFORM_SIGNAL_ID_LAST,
} GncmPlatformSignalIdType;

guint _gncm_platform_signal_id_get (GncmPlatformSignalIdType signal_type);

typedef enum {
	GNCM_PLATFORM_SIGNAL_NONE,
	GNCM_PLATFORM_SIGNAL_ADDED,
	GNCM_PLATFORM_SIGNAL_CHANGED,
	GNCM_PLATFORM_SIGNAL_REMOVED,
} GncmPlatformSignalChangeType;

struct _GncmPlatformObject {
	__GncmPlatformObject_COMMON;
};

#define GNCM_PLATFORM_IP_ADDRESS_CAST(address) \
	NM_CONSTCAST (GncmPlatformIPAddress, (address), GncmPlatformIPXAddress, GncmPlatformIP4Address, GncmPlatformIP6Address)

#define __GncmPlatformIPAddress_COMMON \
	__GncmPlatformObject_COMMON; \
	NMIPConfigSource addr_source; \
	\
	/* Timestamp in seconds in the reference system of byx_utils_get_monotonic_timestamp_*().
	 *
	 * The rules are:
	 * 1 @lifetime==0: @timestamp and @preferred is irrelevant (but mostly set to 0 too). Such addresses
	 *   are permanent. This rule is so that unset addresses (calloc) are permanent by default.
	 * 2 @lifetime==@preferred==GNCM_PLATFORM_LIFETIME_PERMANENT: @timestamp is irrelevant (but mostly
	 *   set to 0). Such addresses are permanent.
	 * 3 Non permanent addreses should (almost) always have @timestamp > 0. 0 is not a valid timestamp
	 *   and never returned by byx_utils_get_monotonic_timestamp_s(). In this case @valid/@preferred
	 *   is anchored at @timestamp.
	 * 4 Non permanent addresses with @timestamp == 0 are implicitely anchored at *now*, thus the time
	 *   moves as time goes by. This is usually not useful, except e.g. gncm_platform_ip[46]_address_add().
	 *
	 * Non permanent addresses from DHCP/RA might have the @timestamp set to the moment of when the
	 * lease was received. Addresses from kernel might have the @timestamp based on the last modification
	 * time of the addresses. But don't rely on this behaviour, the @timestamp is only defined for anchoring
	 * @lifetime and @preferred.
	 */ \
	guint32 timestamp; \
	guint32 lifetime;   /* seconds since timestamp */ \
	guint32 preferred;  /* seconds since timestamp */ \
	\
	/* ifa_flags in 'struct ifaddrmsg' from <linux/if_addr.h>, extended to 32 bit by
	 * IFA_FLAGS attribute. */ \
	guint32 n_ifa_flags; \
	\
	guint8 plen; \
	;

/**
 * GncmPlatformIPAddress:
 *
 * Common parts of GncmPlatformIP4Address and GncmPlatformIP6Address.
 **/
typedef struct {
	__GncmPlatformIPAddress_COMMON;
	union {
		guint8 address_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} GncmPlatformIPAddress;

/**
 * GncmPlatformIP4Address:
 * @timestamp: timestamp as returned by byx_utils_get_monotonic_timestamp_s()
 **/
struct _GncmPlatformIP4Address {
	__GncmPlatformIPAddress_COMMON;

	/* The local address IFA_LOCAL. */
	in_addr_t address;

	/* The IFA_ADDRESS PTP peer address. This field is rather important, because
	 * it constitutes the identifier for the IPv4 address (e.g. you can add two
	 * addresses that only differ by their peer's network-part.
	 *
	 * Beware that for most cases, NetworkManager doesn't want to set an explicit
	 * peer-address. Hoever, that corresponds to setting the peer address to @address
	 * itself. Leaving peer-address unset/zero, means explicitly setting the peer
	 * address to 0.0.0.0, which you probably don't want.
	 * */
	in_addr_t peer_address;  /* PTP peer address */

	char label[IFNAMSIZ];
};

/**
 * GncmPlatformIP6Address:
 * @timestamp: timestamp as returned by byx_utils_get_monotonic_timestamp_s()
 **/
struct _GncmPlatformIP6Address {
	__GncmPlatformIPAddress_COMMON;
	struct in6_addr address;
	struct in6_addr peer_address;
};

typedef union {
	GncmPlatformIPAddress  ax;
	GncmPlatformIP4Address a4;
	GncmPlatformIP6Address a6;
} GncmPlatformIPXAddress;

#undef __GncmPlatformIPAddress_COMMON

/* Default value for adding an IPv4 route. This is also what iproute2 does.
 * Note that contrary to IPv6, you can add routes with metric 0 and it is even
 * the default.
 */
#define GNCM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4 0

/* Default value for adding an IPv6 route. This is also what iproute2 does.
 * Adding an IPv6 route with metric 0, kernel translates to IP6_RT_PRIO_USER (1024). */
#define GNCM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6 1024

/* For IPv4, kernel adds a device route (subnet routes) with metric 0 when user
 * configures addresses. */
#define GNCM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE 0

#define __GncmPlatformIPRoute_COMMON \
	__GncmPlatformObject_COMMON; \
	\
	/* The NMIPConfigSource. For routes that we receive from cache this corresponds
	 * to the rtm_protocol field (and is one of the NM_IP_CONFIG_SOURCE_RTPROT_* values).
	 * When adding a route, the source will be coerced to the protocol using
	 * nmp_utils_ip_config_source_coerce_to_rtprot().
	 *
	 * rtm_protocol is part of the primary key of an IPv4 route (meaning, you can add
	 * two IPv4 routes that only differ in their rtm_protocol. For IPv6, that is not
	 * the case.
	 *
	 * When deleting an IPv4/IPv6 route, the rtm_protocol field must match (even
	 * if it is not part of the primary key for IPv6) -- unless rtm_protocol is set
	 * to zero, in which case the first matching route (with proto ignored) is deleted. */ \
	NMIPConfigSource rt_source; \
	\
	guint8 plen; \
	\
	/* RTA_METRICS:
	 *
	 * For IPv4 routes, these properties are part of their
	 * ID (meaning: you can add otherwise idential IPv4 routes that
	 * only differ by the metric property).
	 * On the other hand, for IPv6 you cannot add two IPv6 routes that only differ
	 * by an RTA_METRICS property.
	 *
	 * When deleting a route, kernel seems to ignore the RTA_METRICS propeties.
	 * That is a problem/bug for IPv4 because you cannot explicitly select which
	 * route to delete. Kernel just picks the first. See rh#1475642. */ \
	\
	/* RTA_METRICS.RTAX_LOCK (iproute2: "lock" arguments) */ \
	bool lock_window:1; \
	bool lock_cwnd:1; \
	bool lock_initcwnd:1; \
	bool lock_initrwnd:1; \
	bool lock_mtu:1; \
	\
	/* rtnh_flags
	 *
	 * Routes with rtm_flags RTM_F_CLONED are hidden by platform and
	 * do not exist from the point-of-view of platform users.
	 * Such a route is not alive, according to nmp_object_is_alive().
	 *
	 * NOTE: currently we ignore all flags except RTM_F_CLONED
	 * and RTNH_F_ONLINK for IPv4.
	 * We also may not properly consider the flags as part of the ID
	 * in route-cmp. */ \
	unsigned r_rtm_flags; \
	\
	/* RTA_METRICS.RTAX_ADVMSS (iproute2: advmss) */ \
	guint32 mss; \
	\
	/* RTA_METRICS.RTAX_WINDOW (iproute2: window) */ \
	guint32 window; \
	\
	/* RTA_METRICS.RTAX_CWND (iproute2: cwnd) */ \
	guint32 cwnd; \
	\
	/* RTA_METRICS.RTAX_INITCWND (iproute2: initcwnd) */ \
	guint32 initcwnd; \
	\
	/* RTA_METRICS.RTAX_INITRWND (iproute2: initrwnd) */ \
	guint32 initrwnd; \
	\
	/* RTA_METRICS.RTAX_MTU (iproute2: mtu) */ \
	guint32 mtu; \
	\
	\
	/* RTA_PRIORITY (iproute2: metric) */ \
	guint32 metric; \
	\
	/* rtm_table, RTA_TABLE.
	 *
	 * This is not the original table ID. Instead, 254 (RT_TABLE_MAIN) and
	 * zero (RT_TABLE_UNSPEC) are swapped, so that the default is the main
	 * table. Use gncm_platform_route_table_coerce()/gncm_platform_route_table_uncoerce(). */ \
	guint32 table_coerced; \
	\
	/*end*/

typedef struct {
	__GncmPlatformIPRoute_COMMON;
	union {
		guint8 network_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} GncmPlatformIPRoute;

#define GNCM_PLATFORM_IP_ROUTE_CAST(route) \
	NM_CONSTCAST (GncmPlatformIPRoute, (route), GncmPlatformIPXRoute, GncmPlatformIP4Route, GncmPlatformIP6Route)

#define GNCM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) \
	(GNCM_PLATFORM_IP_ROUTE_CAST (route)->plen <= 0)

struct _GncmPlatformIP4Route {
	__GncmPlatformIPRoute_COMMON;
	in_addr_t network;

	/* RTA_GATEWAY. The gateway is part of the primary key for a route */
	in_addr_t gateway;

	/* RTA_PREFSRC (called "src" by iproute2).
	 *
	 * pref_src is part of the ID of an IPv4 route. When deleting a route,
	 * pref_src must match, unless set to 0.0.0.0 to match any. */
	in_addr_t pref_src;

	/* rtm_tos (iproute2: tos)
	 *
	 * For IPv4, tos is part of the weak-id (like metric).
	 *
	 * For IPv6, tos is ignored by kernel.  */
	guint8 tos;

	/* The bitwise inverse of the route scope rtm_scope. It is inverted so that the
	 * default value (RT_SCOPE_NOWHERE) is zero. Use gncm_platform_route_scope_inv()
	 * to convert back and forth between the inverese representation and the
	 * real value.
	 *
	 * rtm_scope is part of the primary key for IPv4 routes. When deleting a route,
	 * the scope must match, unless it is left at RT_SCOPE_NOWHERE, in which case the first
	 * matching route is deleted.
	 *
	 * For IPv6 routes, the scope is ignored and kernel always assumes global scope.
	 * Hence, this field is only in GncmPlatformIP4Route. */
	guint8 scope_inv;
};

struct _GncmPlatformIP6Route {
	__GncmPlatformIPRoute_COMMON;
	struct in6_addr network;

	/* RTA_GATEWAY. The gateway is part of the primary key for a route */
	struct in6_addr gateway;

	/* RTA_PREFSRC (called "src" by iproute2).
	 *
	 * pref_src is not part of the ID for an IPv6 route. You cannot add two
	 * routes that only differ by pref_src.
	 *
	 * When deleting a route, pref_src is ignored by kernel. */
	struct in6_addr pref_src;

	/* RTA_SRC and rtm_src_len (called "from" by iproute2).
	 *
	 * Kernel clears the host part of src/src_plen.
	 *
	 * src/src_plen is part of the ID of a route just like network/plen. That is,
	 * Not only `ip route append`, but also `ip route add` allows to add routes that only
	 * differ in their src/src_plen.
	 */
	struct in6_addr src;
	guint8 src_plen;

	/* RTA_PREF router preference.
	 *
	 * The type is guint8 to keep the struct size small. But the values are compatible with
	 * the NMIcmpv6RouterPref enum. */
	guint8 rt_pref;
};

typedef union {
	GncmPlatformIPRoute  rx;
	GncmPlatformIP4Route r4;
	GncmPlatformIP6Route r6;
} GncmPlatformIPXRoute;

#undef __GncmPlatformIPRoute_COMMON

typedef struct {
	__GncmPlatformObject_COMMON;
	const char *kind;
	int addr_family;
	guint32 handle;
	guint32 parent;
	guint32 info;
} GncmPlatformQdisc;

typedef struct {
	char sdata[32];
} GncmPlatformActionSimple;

typedef struct {
	const char *kind;
	union {
		GncmPlatformActionSimple simple;
	};
} GncmPlatformAction;

#define GNCM_PLATFORM_ACTION_KIND_SIMPLE "simple"

typedef struct {
	__GncmPlatformObject_COMMON;
	const char *kind;
	int addr_family;
	guint32 handle;
	guint32 parent;
	guint32 info;
	GncmPlatformAction action;
} GncmPlatformTfilter;

#undef __GncmPlatformObject_COMMON

typedef struct {
	gboolean is_ip4;
	NMPObjectType obj_type;
	int addr_family;
	gsize sizeof_route;
	int (*route_cmp) (const GncmPlatformIPXRoute *a, const GncmPlatformIPXRoute *b, GncmPlatformIPRouteCmpType cmp_type);
	const char *(*route_to_string) (const GncmPlatformIPXRoute *route, char *buf, gsize len);
	guint32 (*metric_normalize) (guint32 metric);
} GncmPlatformVTableRoute;

extern const GncmPlatformVTableRoute gncm_platform_vtable_route_v4;
extern const GncmPlatformVTableRoute gncm_platform_vtable_route_v6;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint16 input_flags;
	guint16 output_flags;
	guint32 input_key;
	guint32 output_key;
	guint8 ttl;
	guint8 tos;
	bool path_mtu_discovery:1;
} GncmPlatformLnkGre;

typedef struct {
	int p_key;
	const char *mode;
} GncmPlatformLnkInfiniband;

typedef struct {
	struct in6_addr local;
	struct in6_addr remote;
	int parent_ifindex;
	guint8 ttl;
	guint8 tclass;
	guint8 encap_limit;
	guint8 proto;
	guint flow_label;
	guint32 flags;
} GncmPlatformLnkIp6Tnl;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint8 ttl;
	guint8 tos;
	bool path_mtu_discovery:1;
} GncmPlatformLnkIpIp;

typedef struct {
	int parent_ifindex;
	guint64 sci;                    /* host byte order */
	guint64 cipher_suite;
	guint32 window;
	guint8 icv_length;
	guint8 encoding_sa;
	guint8 validation;
	bool encrypt:1;
	bool protect:1;
	bool include_sci:1;
	bool es:1;
	bool scb:1;
	bool replay_protect:1;
} GncmPlatformLnkMacsec;

typedef struct {
	guint mode;
	bool no_promisc:1;
	bool tap:1;
} GncmPlatformLnkMacvlan;

typedef GncmPlatformLnkMacvlan GncmPlatformLnkMacvtap;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint16 flags;
	guint8 ttl;
	guint8 tos;
	guint8 proto;
	bool path_mtu_discovery:1;
} GncmPlatformLnkSit;

typedef struct {
	guint32 owner;
	guint32 group;

	guint8 type;

	bool owner_valid:1;
	bool group_valid:1;

	bool pi:1;
	bool vnet_hdr:1;
	bool multi_queue:1;
	bool persist:1;
} GncmPlatformLnkTun;

typedef struct {
	/* rtnl_link_vlan_get_id(), IFLA_VLAN_ID */
	guint16 id;
	NMVlanFlags flags;
} GncmPlatformLnkVlan;

typedef struct {
	struct in6_addr group6;
	struct in6_addr local6;
	in_addr_t group;
	in_addr_t local;
	int parent_ifindex;
	guint32 id;
	guint32 ageing;
	guint32 limit;
	guint16 dst_port;
	guint16 src_port_min;
	guint16 src_port_max;
	guint8 tos;
	guint8 ttl;
	bool learning:1;
	bool proxy:1;
	bool rsc:1;
	bool l2miss:1;
	bool l3miss:1;
} GncmPlatformLnkVxlan;

typedef enum {
	GNCM_PLATFORM_LINK_DUPLEX_UNKNOWN,
	GNCM_PLATFORM_LINK_DUPLEX_HALF,
	GNCM_PLATFORM_LINK_DUPLEX_FULL,
} GncmPlatformLinkDuplexType;

typedef enum {
	GNCM_PLATFORM_KERNEL_SUPPORT_EXTENDED_IFA_FLAGS               = (1LL <<  0),
	GNCM_PLATFORM_KERNEL_SUPPORT_USER_IPV6LL                      = (1LL <<  1),
	GNCM_PLATFORM_KERNEL_SUPPORT_RTA_PREF                         = (1LL <<  2),
} GncmPlatformKernelSupportFlags;

/*****************************************************************************/

struct _GncmPlatformPrivate;

struct _GncmPlatform {
	GObject parent;
	NMPNetns *_netns;
	struct _GncmPlatformPrivate *_priv;
};

typedef struct {
	GObjectClass parent;

	gboolean (*sysctl_set) (GncmPlatform *, const char *pathid, int dirfd, const char *path, const char *value);
	char * (*sysctl_get) (GncmPlatform *, const char *pathid, int dirfd, const char *path);

	void (*refresh_all) (GncmPlatform *self, NMPObjectType obj_type);

	gboolean (*link_add) (GncmPlatform *,
	                      const char *name,
	                      NMLinkType type,
	                      const char *veth_peer,
	                      const void *address,
	                      size_t address_len,
	                      const GncmPlatformLink **out_link);
	gboolean (*link_delete) (GncmPlatform *, int ifindex);

	gboolean (*link_refresh) (GncmPlatform *, int ifindex);

	gboolean (*link_set_netns) (GncmPlatform *, int ifindex, int netns_fd);

	void (*process_events) (GncmPlatform *self);

	gboolean (*link_set_up) (GncmPlatform *, int ifindex, gboolean *out_no_firmware);
	gboolean (*link_set_down) (GncmPlatform *, int ifindex);
	gboolean (*link_set_arp) (GncmPlatform *, int ifindex);
	gboolean (*link_set_noarp) (GncmPlatform *, int ifindex);

	const char *(*link_get_udi) (GncmPlatform *self, int ifindex);
	struct udev_device *(*link_get_udev_device) (GncmPlatform *self, int ifindex);

	GncmPlatformError (*link_set_user_ipv6ll_enabled) (GncmPlatform *, int ifindex, gboolean enabled);
	gboolean (*link_set_token) (GncmPlatform *, int ifindex, NMUtilsIPv6IfaceId iid);

	gboolean (*link_get_permanent_address) (GncmPlatform *,
	                                        int ifindex,
	                                        guint8 *buf,
	                                        size_t *length);
	GncmPlatformError (*link_set_address) (GncmPlatform *, int ifindex, gconstpointer address, size_t length);
	GncmPlatformError (*link_set_mtu) (GncmPlatform *, int ifindex, guint32 mtu);
	gboolean (*link_set_name) (GncmPlatform *, int ifindex, const char *name);
	gboolean (*link_set_sriov_num_vfs) (GncmPlatform *, int ifindex, guint num_vfs);

	char *   (*link_get_physical_port_id) (GncmPlatform *, int ifindex);
	guint    (*link_get_dev_id) (GncmPlatform *, int ifindex);
	gboolean (*link_get_wake_on_lan) (GncmPlatform *, int ifindex);
	gboolean (*link_get_driver_info) (GncmPlatform *,
	                                  int ifindex,
	                                  char **out_driver_name,
	                                  char **out_driver_version,
	                                  char **out_fw_version);

	gboolean (*link_supports_carrier_detect) (GncmPlatform *, int ifindex);
	gboolean (*link_supports_vlans) (GncmPlatform *, int ifindex);
	gboolean (*link_supports_sriov) (GncmPlatform *, int ifindex);

	gboolean (*link_enslave) (GncmPlatform *, int master, int slave);
	gboolean (*link_release) (GncmPlatform *, int master, int slave);

	gboolean (*link_can_assume) (GncmPlatform *, int ifindex);

	guint16     (*wpan_get_pan_id)       (GncmPlatform *, int ifindex);
	guint16     (*wpan_get_short_addr)   (GncmPlatform *, int ifindex);

	gboolean (*object_delete) (GncmPlatform *, const NMPObject *obj);

	gboolean (*ip4_address_delete) (GncmPlatform *, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);

	GncmPlatformError (*ip_route_add) (GncmPlatform *,
	                                 NMPNlmFlags flags,
	                                 int addr_family,
	                                 const GncmPlatformIPRoute *route);
	GncmPlatformError (*ip_route_get) (GncmPlatform *self,
	                                 int addr_family,
	                                 gconstpointer address,
	                                 int oif_ifindex,
	                                 NMPObject **out_route);

	GncmPlatformError (*qdisc_add)   (GncmPlatform *self,
	                                NMPNlmFlags flags,
	                                const GncmPlatformQdisc *qdisc);

	GncmPlatformError (*tfilter_add)   (GncmPlatform *self,
	                                  NMPNlmFlags flags,
	                                  const GncmPlatformTfilter *tfilter);

	GncmPlatformKernelSupportFlags (*check_kernel_support) (GncmPlatform * self,
	                                                      GncmPlatformKernelSupportFlags request_flags);
} GncmPlatformClass;

/* GncmPlatform signals
 *
 * Each signal handler is called with a type-specific object that provides
 * key attributes that constitute identity of the object. They may also
 * provide additional attributes for convenience.
 *
 * The object only intended to be used by the signal handler to determine
 * the current values. It is no longer valid after the signal handler exits
 * but you are free to copy the provided information and use it for later
 * reference.
 */
#define GNCM_PLATFORM_SIGNAL_LINK_CHANGED "link-changed"
#define GNCM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED "ip4-address-changed"
#define GNCM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED "ip6-address-changed"
#define GNCM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED "ip4-route-changed"
#define GNCM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED "ip6-route-changed"
#define GNCM_PLATFORM_SIGNAL_QDISC_CHANGED "qdisc-changed"
#define GNCM_PLATFORM_SIGNAL_TFILTER_CHANGED "tfilter-changed"

const char *gncm_platform_signal_change_type_to_string (GncmPlatformSignalChangeType change_type);

/*****************************************************************************/

GType gncm_platform_get_type (void);

void gncm_platform_setup (GncmPlatform *instance);
GncmPlatform *gncm_platform_get (void);

#define GNCM_PLATFORM_GET (gncm_platform_get ())

/*****************************************************************************/

/**
 * gncm_platform_route_table_coerce:
 * @table: the route table, in its original value as received
 *   from rtm_table/RTA_TABLE.
 *
 * Returns: returns the coerced table id, that can be stored in
 *   GncmPlatformIPRoute.table_coerced.
 */
static inline guint32
gncm_platform_route_table_coerce (guint32 table)
{
	/* For kernel, the default table is RT_TABLE_MAIN (254).
	 * We want that in GncmPlatformIPRoute.table_coerced a numeric
	 * zero is the default. Hence, @table_coerced swaps the
	 * value 0 and 254. Use gncm_platform_route_table_coerce()
	 * and gncm_platform_route_table_uncoerce() to convert between
	 * the two domains. */
	switch (table) {
	case 0 /* RT_TABLE_UNSPEC */:
		return 254;
	case 254 /* RT_TABLE_MAIN */:
		return 0;
	default:
		return table;
	}
}

/**
 * gncm_platform_route_table_uncoerce:
 * @table: the route table, in its coerced value
 * @normalize: whether to normalize RT_TABLE_UNSPEC to
 *   RT_TABLE_MAIN. For kernel, routes with a table id
 *   RT_TABLE_UNSPEC do not exist and are treated like
 *   RT_TABLE_MAIN.
 *
 * Returns: reverts the coerced table ID in GncmPlatformIPRoute.table_coerced
 *   to the original value as kernel understands it.
 */
static inline guint32
gncm_platform_route_table_uncoerce (guint32 table_coerced, gboolean normalize)
{
	/* this undoes gncm_platform_route_table_coerce().  */
	switch (table_coerced) {
	case 0 /* RT_TABLE_UNSPEC */:
		return 254;
	case 254 /* RT_TABLE_MAIN */:
		return normalize ? 254 : 0;
	default:
		return table_coerced;
	}
}

static inline gboolean
gncm_platform_route_table_is_main (guint32 table)
{
	/* same as
	 *   gncm_platform_route_table_uncoerce (table, TRUE) == RT_TABLE_MAIN
	 * and
	 *   gncm_platform_route_table_uncoerce (gncm_platform_route_table_coerce (table), TRUE) == RT_TABLE_MAIN
	 *
	 * That is, the function operates the same on @table and its coerced
	 * form.
	 */
	return table == 0 || table == 254;
}

/**
 * gncm_platform_route_scope_inv:
 * @scope: the route scope, either its original value, or its inverse.
 *
 * This function is useful, because the constants such as RT_SCOPE_NOWHERE
 * are 'int', so ~scope also gives an 'int'. This function gets the type
 * casts to guint8 right.
 *
 * Returns: the bitwise inverse of the route scope.
 * */
#define gncm_platform_route_scope_inv _gncm_platform_uint8_inv
static inline guint8
_gncm_platform_uint8_inv (guint8 scope)
{
	return (guint8) ~scope;
}

gboolean gncm_platform_get_use_udev (GncmPlatform *self);
gboolean gncm_platform_get_log_with_ptr (GncmPlatform *self);

NMPNetns *gncm_platform_netns_get (GncmPlatform *self);
gboolean gncm_platform_netns_push (GncmPlatform *platform, NMPNetns **netns);

const char *nm_link_type_to_string (NMLinkType link_type);

const char *gncm_platform_error_to_string (GncmPlatformError error,
                                         char *buf,
                                         gsize buf_len);
#define gncm_platform_error_to_string_a(error) \
	(gncm_platform_error_to_string ((error), g_alloca (30), 30))

#define NMP_SYSCTL_PATHID_ABSOLUTE(path) \
	((const char *) NULL), -1, (path)

#define NMP_SYSCTL_PATHID_NETDIR_unsafe(dirfd, ifname, path) \
	nm_sprintf_bufa (NM_STRLEN ("net:/sys/class/net//\0") + IFNAMSIZ + strlen (path), \
	                 "net:/sys/class/net/%s/%s", (ifname), (path)), \
	(dirfd), (path)

#define NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, path) \
	nm_sprintf_bufa (NM_STRLEN ("net:/sys/class/net//"path"/\0") + IFNAMSIZ, \
	                 "net:/sys/class/net/%s/%s", (ifname), path), \
	(dirfd), (""path"")

int gncm_platform_sysctl_open_netdir (GncmPlatform *self, int ifindex, char *out_ifname);
gboolean gncm_platform_sysctl_set (GncmPlatform *self, const char *pathid, int dirfd, const char *path, const char *value);
char *gncm_platform_sysctl_get (GncmPlatform *self, const char *pathid, int dirfd, const char *path);
gint32 gncm_platform_sysctl_get_int32 (GncmPlatform *self, const char *pathid, int dirfd, const char *path, gint32 fallback);
gint64 gncm_platform_sysctl_get_int_checked (GncmPlatform *self, const char *pathid, int dirfd, const char *path, guint base, gint64 min, gint64 max, gint64 fallback);

gboolean gncm_platform_sysctl_set_ip6_hop_limit_safe (GncmPlatform *self, const char *iface, int value);

const char *gncm_platform_if_indextoname (GncmPlatform *self, int ifindex, char *out_ifname/* of size IFNAMSIZ */);
int gncm_platform_if_nametoindex (GncmPlatform *self, const char *ifname);

void gncm_platform_refresh_all (GncmPlatform *self, NMPObjectType obj_type);

const NMPObject *gncm_platform_link_get_obj (GncmPlatform *self,
                                           int ifindex,
                                           gboolean visible_only);
const GncmPlatformLink *gncm_platform_link_get (GncmPlatform *self, int ifindex);
const GncmPlatformLink *gncm_platform_link_get_by_ifname (GncmPlatform *self, const char *ifname);
const GncmPlatformLink *gncm_platform_link_get_by_address (GncmPlatform *self, NMLinkType link_type, gconstpointer address, size_t length);

GPtrArray *gncm_platform_link_get_all (GncmPlatform *self, gboolean sort_by_name);

gboolean gncm_platform_link_delete (GncmPlatform *self, int ifindex);

gboolean gncm_platform_link_set_netns (GncmPlatform *self, int ifindex, int netns_fd);

struct _NMDedupMultiHeadEntry;
struct _NMPLookup;
const struct _NMDedupMultiHeadEntry *gncm_platform_lookup (GncmPlatform *platform,
                                                         const struct _NMPLookup *lookup);

gboolean gncm_platform_lookup_predicate_routes_main (const NMPObject *obj,
                                                   gpointer user_data);
gboolean gncm_platform_lookup_predicate_routes_main_skip_rtprot_kernel (const NMPObject *obj,
                                                                      gpointer user_data);

GPtrArray *gncm_platform_lookup_clone (GncmPlatform *platform,
                                     const struct _NMPLookup *lookup,
                                     NMPObjectPredicateFunc predicate,
                                     gpointer user_data);

/* convienience methods to lookup the link and access fields of GncmPlatformLink. */
int gncm_platform_link_get_ifindex (GncmPlatform *self, const char *name);
const char *gncm_platform_link_get_name (GncmPlatform *self, int ifindex);
NMLinkType gncm_platform_link_get_type (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_is_software (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_is_up (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_is_connected (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_uses_arp (GncmPlatform *self, int ifindex);
guint32 gncm_platform_link_get_mtu (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_get_user_ipv6ll_enabled (GncmPlatform *self, int ifindex);

gconstpointer gncm_platform_link_get_address (GncmPlatform *self, int ifindex, size_t *length);

static inline GBytes *
gncm_platform_link_get_address_as_bytes (GncmPlatform *self, int ifindex)
{
	gconstpointer p;
	gsize l;

	p = gncm_platform_link_get_address (self, ifindex, &l);
	return p
	       ? g_bytes_new (p, l)
	       : NULL;
}

int gncm_platform_link_get_master (GncmPlatform *self, int slave);

gboolean gncm_platform_link_can_assume (GncmPlatform *self, int ifindex);

gboolean gncm_platform_link_get_unmanaged (GncmPlatform *self, int ifindex, gboolean *unmanaged);
gboolean gncm_platform_link_supports_slaves (GncmPlatform *self, int ifindex);
const char *gncm_platform_link_get_type_name (GncmPlatform *self, int ifindex);

gboolean gncm_platform_link_refresh (GncmPlatform *self, int ifindex);
void gncm_platform_process_events (GncmPlatform *self);

const GncmPlatformLink *gncm_platform_process_events_ensure_link (GncmPlatform *self,
                                                              int ifindex,
                                                              const char *ifname);

gboolean gncm_platform_link_set_up (GncmPlatform *self, int ifindex, gboolean *out_no_firmware);
gboolean gncm_platform_link_set_down (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_set_arp (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_set_noarp (GncmPlatform *self, int ifindex);

const char *gncm_platform_link_get_udi (GncmPlatform *self, int ifindex);

struct udev_device *gncm_platform_link_get_udev_device (GncmPlatform *self, int ifindex);

GncmPlatformError gncm_platform_link_set_user_ipv6ll_enabled (GncmPlatform *self, int ifindex, gboolean enabled);
gboolean gncm_platform_link_set_ipv6_token (GncmPlatform *self, int ifindex, NMUtilsIPv6IfaceId iid);

gboolean gncm_platform_link_get_permanent_address (GncmPlatform *self, int ifindex, guint8 *buf, size_t *length);
GncmPlatformError gncm_platform_link_set_address (GncmPlatform *self, int ifindex, const void *address, size_t length);
GncmPlatformError gncm_platform_link_set_mtu (GncmPlatform *self, int ifindex, guint32 mtu);
gboolean gncm_platform_link_set_name (GncmPlatform *self, int ifindex, const char *name);
gboolean gncm_platform_link_set_sriov_num_vfs (GncmPlatform *self, int ifindex, guint num_vfs);

char    *gncm_platform_link_get_physical_port_id (GncmPlatform *self, int ifindex);
guint    gncm_platform_link_get_dev_id (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_get_wake_on_lan (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_get_driver_info (GncmPlatform *self,
                                           int ifindex,
                                           char **out_driver_name,
                                           char **out_driver_version,
                                           char **out_fw_version);

gboolean gncm_platform_link_supports_carrier_detect (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_supports_vlans (GncmPlatform *self, int ifindex);
gboolean gncm_platform_link_supports_sriov (GncmPlatform *self, int ifindex);

gboolean gncm_platform_link_enslave (GncmPlatform *self, int master, int slave);
gboolean gncm_platform_link_release (GncmPlatform *self, int master, int slave);

gboolean gncm_platform_sysctl_master_set_option (GncmPlatform *self, int ifindex, const char *option, const char *value);
char *gncm_platform_sysctl_master_get_option (GncmPlatform *self, int ifindex, const char *option);
gboolean gncm_platform_sysctl_slave_set_option (GncmPlatform *self, int ifindex, const char *option, const char *value);
char *gncm_platform_sysctl_slave_get_option (GncmPlatform *self, int ifindex, const char *option);

const NMPObject *gncm_platform_link_get_lnk (GncmPlatform *self, int ifindex, NMLinkType link_type, const GncmPlatformLink **out_link);
const GncmPlatformLnkGre *gncm_platform_link_get_lnk_gre (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkIp6Tnl *gncm_platform_link_get_lnk_ip6tnl (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkIpIp *gncm_platform_link_get_lnk_ipip (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkInfiniband *gncm_platform_link_get_lnk_infiniband (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkIpIp *gncm_platform_link_get_lnk_ipip (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkMacsec *gncm_platform_link_get_lnk_macsec (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkMacvlan *gncm_platform_link_get_lnk_macvlan (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkMacvtap *gncm_platform_link_get_lnk_macvtap (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkSit *gncm_platform_link_get_lnk_sit (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkTun *gncm_platform_link_get_lnk_tun (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkVlan *gncm_platform_link_get_lnk_vlan (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);
const GncmPlatformLnkVxlan *gncm_platform_link_get_lnk_vxlan (GncmPlatform *self, int ifindex, const GncmPlatformLink **out_link);


guint16     gncm_platform_wpan_get_pan_id       (GncmPlatform *platform, int ifindex);
guint16     gncm_platform_wpan_get_short_addr   (GncmPlatform *platform, int ifindex);

void                   gncm_platform_ip4_address_set_addr (GncmPlatformIP4Address *addr, in_addr_t address, guint8 plen);
const struct in6_addr *gncm_platform_ip6_address_get_peer (const GncmPlatformIP6Address *addr);

const GncmPlatformIP4Address *gncm_platform_ip4_address_get (GncmPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);

const GncmPlatformIP6Address *gncm_platform_ip6_address_get (GncmPlatform *self, int ifindex, struct in6_addr address);

gboolean gncm_platform_object_delete (GncmPlatform *self, const NMPObject *route);
gboolean gncm_platform_ip4_address_delete (GncmPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);

void gncm_platform_ip_route_normalize (int addr_family,
                                     GncmPlatformIPRoute *route);

GncmPlatformError gncm_platform_ip_route_add (GncmPlatform *self,
                                          NMPNlmFlags flags,
                                          const NMPObject *route);
GncmPlatformError gncm_platform_ip4_route_add (GncmPlatform *self, NMPNlmFlags flags, const GncmPlatformIP4Route *route);
GncmPlatformError gncm_platform_ip6_route_add (GncmPlatform *self, NMPNlmFlags flags, const GncmPlatformIP6Route *route);

GPtrArray *gncm_platform_ip_route_get_prune_list (GncmPlatform *self,
                                                int addr_family,
                                                int ifindex,
                                                NMIPRouteTableSyncMode route_table_sync);

gboolean gncm_platform_ip_route_sync (GncmPlatform *self,
                                    int addr_family,
                                    int ifindex,
                                    GPtrArray *routes,
                                    GPtrArray *routes_prune,
                                    GPtrArray **out_temporary_not_available);

gboolean gncm_platform_ip_route_flush (GncmPlatform *self,
                                     int addr_family,
                                     int ifindex);

GncmPlatformError gncm_platform_ip_route_get (GncmPlatform *self,
                                          int addr_family,
                                          gconstpointer address,
                                          int oif_ifindex,
                                          NMPObject **out_route);

GncmPlatformError gncm_platform_qdisc_add   (GncmPlatform *self,
                                         NMPNlmFlags flags,
                                         const GncmPlatformQdisc *qdisc);
gboolean gncm_platform_qdisc_sync         (GncmPlatform *self,
                                         int ifindex,
                                         GPtrArray *known_qdiscs);

GncmPlatformError gncm_platform_tfilter_add   (GncmPlatform *self,
                                           NMPNlmFlags flags,
                                           const GncmPlatformTfilter *tfilter);
gboolean gncm_platform_tfilter_sync         (GncmPlatform *self,
                                           int ifindex,
                                           GPtrArray *known_tfilters);

const char *gncm_platform_link_to_string (const GncmPlatformLink *link, char *buf, gsize len);
const char *gncm_platform_lnk_gre_to_string (const GncmPlatformLnkGre *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_infiniband_to_string (const GncmPlatformLnkInfiniband *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_ip6tnl_to_string (const GncmPlatformLnkIp6Tnl *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_ipip_to_string (const GncmPlatformLnkIpIp *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_macsec_to_string (const GncmPlatformLnkMacsec *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_macvlan_to_string (const GncmPlatformLnkMacvlan *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_sit_to_string (const GncmPlatformLnkSit *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_tun_to_string (const GncmPlatformLnkTun *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_vlan_to_string (const GncmPlatformLnkVlan *lnk, char *buf, gsize len);
const char *gncm_platform_lnk_vxlan_to_string (const GncmPlatformLnkVxlan *lnk, char *buf, gsize len);
const char *gncm_platform_ip4_address_to_string (const GncmPlatformIP4Address *address, char *buf, gsize len);
const char *gncm_platform_ip6_address_to_string (const GncmPlatformIP6Address *address, char *buf, gsize len);
const char *gncm_platform_ip4_route_to_string (const GncmPlatformIP4Route *route, char *buf, gsize len);
const char *gncm_platform_ip6_route_to_string (const GncmPlatformIP6Route *route, char *buf, gsize len);
const char *gncm_platform_qdisc_to_string (const GncmPlatformQdisc *qdisc, char *buf, gsize len);
const char *gncm_platform_tfilter_to_string (const GncmPlatformTfilter *tfilter, char *buf, gsize len);

const char *gncm_platform_vlan_qos_mapping_to_string (const char *name,
                                                    const NMVlanQosMapping *map,
                                                    gsize n_map,
                                                    char *buf,
                                                    gsize len);

int gncm_platform_link_cmp (const GncmPlatformLink *a, const GncmPlatformLink *b);
int gncm_platform_lnk_gre_cmp (const GncmPlatformLnkGre *a, const GncmPlatformLnkGre *b);
int gncm_platform_lnk_infiniband_cmp (const GncmPlatformLnkInfiniband *a, const GncmPlatformLnkInfiniband *b);
int gncm_platform_lnk_ip6tnl_cmp (const GncmPlatformLnkIp6Tnl *a, const GncmPlatformLnkIp6Tnl *b);
int gncm_platform_lnk_ipip_cmp (const GncmPlatformLnkIpIp *a, const GncmPlatformLnkIpIp *b);
int gncm_platform_lnk_macsec_cmp (const GncmPlatformLnkMacsec *a, const GncmPlatformLnkMacsec *b);
int gncm_platform_lnk_macvlan_cmp (const GncmPlatformLnkMacvlan *a, const GncmPlatformLnkMacvlan *b);
int gncm_platform_lnk_sit_cmp (const GncmPlatformLnkSit *a, const GncmPlatformLnkSit *b);
int gncm_platform_lnk_tun_cmp (const GncmPlatformLnkTun *a, const GncmPlatformLnkTun *b);
int gncm_platform_lnk_vlan_cmp (const GncmPlatformLnkVlan *a, const GncmPlatformLnkVlan *b);
int gncm_platform_lnk_vxlan_cmp (const GncmPlatformLnkVxlan *a, const GncmPlatformLnkVxlan *b);
int gncm_platform_ip4_address_cmp (const GncmPlatformIP4Address *a, const GncmPlatformIP4Address *b);
int gncm_platform_ip6_address_cmp (const GncmPlatformIP6Address *a, const GncmPlatformIP6Address *b);

int gncm_platform_ip4_route_cmp (const GncmPlatformIP4Route *a, const GncmPlatformIP4Route *b, GncmPlatformIPRouteCmpType cmp_type);
int gncm_platform_ip6_route_cmp (const GncmPlatformIP6Route *a, const GncmPlatformIP6Route *b, GncmPlatformIPRouteCmpType cmp_type);

static inline int
gncm_platform_ip4_route_cmp_full (const GncmPlatformIP4Route *a, const GncmPlatformIP4Route *b)
{
	return gncm_platform_ip4_route_cmp (a, b, GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

static inline int
gncm_platform_ip6_route_cmp_full (const GncmPlatformIP6Route *a, const GncmPlatformIP6Route *b)
{
	return gncm_platform_ip6_route_cmp (a, b, GNCM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

int gncm_platform_qdisc_cmp (const GncmPlatformQdisc *a, const GncmPlatformQdisc *b);
int gncm_platform_tfilter_cmp (const GncmPlatformTfilter *a, const GncmPlatformTfilter *b);

void gncm_platform_link_hash_update (const GncmPlatformLink *obj, NMHashState *h);
void gncm_platform_ip4_address_hash_update (const GncmPlatformIP4Address *obj, NMHashState *h);
void gncm_platform_ip6_address_hash_update (const GncmPlatformIP6Address *obj, NMHashState *h);
void gncm_platform_ip4_route_hash_update (const GncmPlatformIP4Route *obj, GncmPlatformIPRouteCmpType cmp_type, NMHashState *h);
void gncm_platform_ip6_route_hash_update (const GncmPlatformIP6Route *obj, GncmPlatformIPRouteCmpType cmp_type, NMHashState *h);
void gncm_platform_lnk_gre_hash_update (const GncmPlatformLnkGre *obj, NMHashState *h);
void gncm_platform_lnk_infiniband_hash_update (const GncmPlatformLnkInfiniband *obj, NMHashState *h);
void gncm_platform_lnk_ip6tnl_hash_update (const GncmPlatformLnkIp6Tnl *obj, NMHashState *h);
void gncm_platform_lnk_ipip_hash_update (const GncmPlatformLnkIpIp *obj, NMHashState *h);
void gncm_platform_lnk_macsec_hash_update (const GncmPlatformLnkMacsec *obj, NMHashState *h);
void gncm_platform_lnk_macvlan_hash_update (const GncmPlatformLnkMacvlan *obj, NMHashState *h);
void gncm_platform_lnk_sit_hash_update (const GncmPlatformLnkSit *obj, NMHashState *h);
void gncm_platform_lnk_tun_hash_update (const GncmPlatformLnkTun *obj, NMHashState *h);
void gncm_platform_lnk_vlan_hash_update (const GncmPlatformLnkVlan *obj, NMHashState *h);
void gncm_platform_lnk_vxlan_hash_update (const GncmPlatformLnkVxlan *obj, NMHashState *h);

void gncm_platform_qdisc_hash_update (const GncmPlatformQdisc *obj, NMHashState *h);
void gncm_platform_tfilter_hash_update (const GncmPlatformTfilter *obj, NMHashState *h);

GncmPlatformKernelSupportFlags gncm_platform_check_kernel_support (GncmPlatform *self,
                                                               GncmPlatformKernelSupportFlags request_flags);

const char *gncm_platform_link_flags2str (unsigned flags, char *buf, gsize len);
const char *gncm_platform_link_inet6_addrgenmode2str (guint8 mode, char *buf, gsize len);
const char *gncm_platform_addr_flags2str (unsigned flags, char *buf, gsize len);
const char *gncm_platform_route_scope2str (int scope, char *buf, gsize len);

int gncm_platform_ip_address_cmp_expiry (const GncmPlatformIPAddress *a, const GncmPlatformIPAddress *b);

gboolean gncm_platform_ethtool_set_wake_on_lan (GncmPlatform *self, int ifindex, NMSettingWiredWakeOnLan wol, const char *wol_password);
gboolean gncm_platform_ethtool_set_link_settings (GncmPlatform *self, int ifindex, gboolean autoneg, guint32 speed, GncmPlatformLinkDuplexType duplex);
gboolean gncm_platform_ethtool_get_link_settings (GncmPlatform *self, int ifindex, gboolean *out_autoneg, guint32 *out_speed, GncmPlatformLinkDuplexType *out_duplex);
const char * gncm_platform_link_duplex_type_to_string (GncmPlatformLinkDuplexType duplex);

void gncm_platform_ip4_dev_route_blacklist_set (GncmPlatform *self,
                                              int ifindex,
                                              GPtrArray *ip4_dev_route_blacklist);

struct _NMDedupMultiIndex *gncm_platform_get_multi_idx (GncmPlatform *self);

#endif /* __GNCM_PLATFORM_H__ */
