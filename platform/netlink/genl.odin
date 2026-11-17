// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

// Generic netlink (<linux/genetlink.h>). Each family has a dynamic message
// type number. `genl_resolve` asks the controller for it (the Linux DCO
// backend resolves the `ovpn` family this way).

GENL_ID_CTRL :: 0x10

// The header that follows the netlink header in every generic message.
Genlmsghdr :: struct {
	cmd:      u8,
	version:  u8,
	reserved: u16,
}
#assert(size_of(Genlmsghdr) == 4)

CTRL_CMD_GETFAMILY :: 3

CTRL_ATTR_FAMILY_ID     :: 1
CTRL_ATTR_FAMILY_NAME   :: 2
CTRL_ATTR_VERSION       :: 3
CTRL_ATTR_HDRSIZE       :: 4
CTRL_ATTR_MAXATTR       :: 5
CTRL_ATTR_OPS           :: 6
CTRL_ATTR_MCAST_GROUPS  :: 7

CTRL_ATTR_MCAST_GRP_NAME :: 1
CTRL_ATTR_MCAST_GRP_ID   :: 2

GENL_NAMSIZ :: 16
MAX_MCAST_GROUPS :: 8

Mcast_Group :: struct {
	name:     [GENL_NAMSIZ]u8, // NUL padded
	name_len: u8,
	id:       u32, // group number for NETLINK_ADD_MEMBERSHIP
}

Family_Info :: struct {
	id:       u16, // the message type to use in requests
	version:  u32,
	hdr_size: u32, // size of the family's own header after genlmsghdr
	max_attr: u32,
	groups:   [MAX_MCAST_GROUPS]Mcast_Group,
	n_groups: int,
}

// Start a generic message: netlink header, then the generic header.
put_genl_header :: proc(b: ^Builder, family: u16, flags: u16, seq: u32, cmd: u8, version: u8) {
	msg_begin(b, family, flags, seq)
	put_struct(b, Genlmsghdr{cmd = cmd, version = version})
}

// Reads the reply to CTRL_CMD_GETFAMILY. `payload` is the message payload
// (generic header included).
parse_family_info :: proc "contextless" (payload: []u8) -> (info: Family_Info, ok: bool) {
	_, attrs := read_struct(payload, Genlmsghdr) or_return
	it := attr_iter(attrs)
	for a in attr_next(&it) {
		switch a.type {
		case CTRL_ATTR_FAMILY_ID:
			info.id, _ = attr_u16(a)
		case CTRL_ATTR_VERSION:
			info.version, _ = attr_u32(a)
		case CTRL_ATTR_HDRSIZE:
			info.hdr_size, _ = attr_u32(a)
		case CTRL_ATTR_MAXATTR:
			info.max_attr, _ = attr_u32(a)
		case CTRL_ATTR_MCAST_GROUPS:
			groups := attr_iter(a.data)
			for g in attr_next(&groups) {
				if info.n_groups >= MAX_MCAST_GROUPS {
					break
				}
				slot := &info.groups[info.n_groups]
				fields := attr_iter(g.data)
				for f in attr_next(&fields) {
					switch f.type {
					case CTRL_ATTR_MCAST_GRP_NAME:
						name := attr_str(f)
						n := min(len(name), GENL_NAMSIZ)
						copy(slot.name[:], name[:n])
						slot.name_len = u8(n)
					case CTRL_ATTR_MCAST_GRP_ID:
						slot.id, _ = attr_u32(f)
					}
				}
				info.n_groups += 1
			}
		}
	}
	return info, info.id != 0
}

// The name of group `i` as a string (points into `info`).
group_name :: proc "contextless" (info: ^Family_Info, i: int) -> string {
	return string(info.groups[i].name[:info.groups[i].name_len])
}

// The number of the multicast group `name` of a family, for `subscribe`.
group_id :: proc "contextless" (info: ^Family_Info, name: string) -> (id: u32, ok: bool) {
	for i in 0 ..< info.n_groups {
		if group_name(info, i) == name {
			return info.groups[i].id, true
		}
	}
	return 0, false
}
