// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

// rtnetlink numbers and fixed headers for links, addresses and routes
// (<linux/rtnetlink.h>, <linux/if_link.h>, <linux/if_addr.h>, <linux/if.h>).
// Only what noirvpn uses is here. The struct fields are in host byte order.

// Address families as the kernel puts them in the one-byte family fields.
AF_UNSPEC :: 0
AF_INET   :: 2
AF_INET6  :: 10
AF_PACKET :: 17

// Message types.
RTM_NEWLINK  :: 16
RTM_DELLINK  :: 17
RTM_GETLINK  :: 18
RTM_SETLINK  :: 19
RTM_NEWADDR  :: 20
RTM_DELADDR  :: 21
RTM_GETADDR  :: 22
RTM_NEWROUTE :: 24
RTM_DELROUTE :: 25
RTM_GETROUTE :: 26

// ---- links ----

// Header of link messages (RTM_*LINK).
Ifinfomsg :: struct {
	family: u8,
	_pad:   u8,
	type:   u16, // ARPHRD_*
	index:  i32,
	flags:  u32, // IFF_*
	change: u32, // which flag bits to touch
}
#assert(size_of(Ifinfomsg) == 16)

IFLA_ADDRESS     :: 1
IFLA_BROADCAST   :: 2
IFLA_IFNAME      :: 3
IFLA_MTU         :: 4
IFLA_LINK        :: 5
IFLA_QDISC       :: 6
IFLA_STATS       :: 7
IFLA_MASTER      :: 10
IFLA_TXQLEN      :: 13
IFLA_OPERSTATE   :: 16
IFLA_LINKMODE    :: 17
IFLA_LINKINFO    :: 18
IFLA_NET_NS_PID  :: 19
IFLA_IFALIAS     :: 20
IFLA_GROUP       :: 27
IFLA_NET_NS_FD   :: 28
IFLA_EXT_MASK    :: 29
IFLA_CARRIER     :: 33
IFLA_MIN_MTU     :: 50
IFLA_MAX_MTU     :: 51

// Nested in IFLA_LINKINFO.
IFLA_INFO_KIND :: 1
IFLA_INFO_DATA :: 2

// Nested in IFLA_INFO_DATA of the `ovpn` kind (<linux/if_link.h>): the mode, a u8.
IFLA_OVPN_MODE :: 1
OVPN_MODE_P2P :: 0
OVPN_MODE_MP :: 1

// Link flags (ifi_flags).
IFF_UP          :: 0x1
IFF_BROADCAST   :: 0x2
IFF_LOOPBACK    :: 0x8
IFF_POINTOPOINT :: 0x10
IFF_RUNNING     :: 0x40
IFF_NOARP       :: 0x80
IFF_MULTICAST   :: 0x1000
IFF_LOWER_UP    :: 0x10000

// ---- addresses ----

// Header of address messages (RTM_*ADDR).
Ifaddrmsg :: struct {
	family:    u8,
	prefixlen: u8,
	flags:     u8, // IFA_F_* (the low 8 bits)
	scope:     u8, // RT_SCOPE_*
	index:     u32,
}
#assert(size_of(Ifaddrmsg) == 8)

IFA_ADDRESS   :: 1 // the peer address on a point-to-point link, else the address
IFA_LOCAL     :: 2 // the local address
IFA_LABEL     :: 3
IFA_BROADCAST :: 4
IFA_CACHEINFO :: 6
IFA_FLAGS     :: 8

IFA_F_SECONDARY      :: 0x01
IFA_F_NODAD          :: 0x02
IFA_F_OPTIMISTIC     :: 0x04
IFA_F_DADFAILED      :: 0x08
IFA_F_HOMEADDRESS    :: 0x10
IFA_F_DEPRECATED     :: 0x20
IFA_F_TENTATIVE      :: 0x40
IFA_F_PERMANENT      :: 0x80
IFA_F_NOPREFIXROUTE  :: 0x200

// ---- routes ----

// Header of route messages (RTM_*ROUTE).
Rtmsg :: struct {
	family:   u8,
	dst_len:  u8, // prefix length of the destination
	src_len:  u8,
	tos:      u8,
	table:    u8, // RT_TABLE_*; a table above 255 goes in RTA_TABLE
	protocol: u8, // RTPROT_*
	scope:    u8, // RT_SCOPE_*
	type:     u8, // RTN_*
	flags:    u32, // RTM_F_* and RTNH_F_*
}
#assert(size_of(Rtmsg) == 12)

RTA_DST       :: 1
RTA_SRC       :: 2
RTA_IIF       :: 3
RTA_OIF       :: 4
RTA_GATEWAY   :: 5
RTA_PRIORITY  :: 6 // the metric
RTA_PREFSRC   :: 7
RTA_METRICS   :: 8
RTA_MULTIPATH :: 9
RTA_TABLE     :: 15
RTA_MARK      :: 16

RT_TABLE_UNSPEC  :: 0
RT_TABLE_COMPAT  :: 252
RT_TABLE_DEFAULT :: 253
RT_TABLE_MAIN    :: 254
RT_TABLE_LOCAL   :: 255

RTPROT_UNSPEC   :: 0
RTPROT_REDIRECT :: 1
RTPROT_KERNEL   :: 2
RTPROT_BOOT     :: 3
RTPROT_STATIC   :: 4

RT_SCOPE_UNIVERSE :: 0
RT_SCOPE_SITE     :: 200
RT_SCOPE_LINK     :: 253
RT_SCOPE_HOST     :: 254
RT_SCOPE_NOWHERE  :: 255

RTN_UNSPEC      :: 0
RTN_UNICAST     :: 1
RTN_LOCAL       :: 2
RTN_BROADCAST   :: 3
RTN_ANYCAST     :: 4
RTN_MULTICAST   :: 5
RTN_BLACKHOLE   :: 6
RTN_UNREACHABLE :: 7
RTN_PROHIBIT    :: 8
RTN_THROW       :: 9

RTM_F_NOTIFY    :: 0x100
RTM_F_CLONED    :: 0x200
RTM_F_FIB_MATCH :: 0x2000

RTNH_F_DEAD    :: 0x1
RTNH_F_ONLINK  :: 0x4
