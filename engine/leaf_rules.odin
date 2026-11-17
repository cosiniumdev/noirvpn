// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:strings"
import "noir:proto/config"
import "noir:proto/ossl"

// Peer certificate rules in the control channel TLS: `remote-cert-tls`,
// `remote-cert-ku`, `remote-cert-eku`, `verify-x509-name`, and the limits
// `tls-version-min` and `tls-version-max`. A client checks the server cert, a
// server checks client certs. The TLS library applies them in its verify path
// (ossl/leaf.odin). The outer TLS of the `tls` transport has no certificate
// check, so none of this applies there.

// What the TLS library checks on the peer's own certificate. The strings are
// copies: free them with `leaf_rules_free`.
leaf_rules_of :: proc(t: ^config.Tls_Config) -> (r: ossl.Leaf_Rules) {
	r.ku_required = t.remote_cert_ku_set || t.remote_cert_tls != .None
	for v in t.remote_cert_ku {
		if r.ku_count < ossl.KU_LIST_MAX && v > 0 && v <= 0xff {
			r.ku_list[r.ku_count] = u8(v)
			r.ku_count += 1
		}
	}
	if t.remote_cert_eku != "" {
		r.eku = strings.clone(t.remote_cert_eku)
	}
	if x, ok := t.verify_x509_name.?; ok {
		switch x.kind {
		case .Subject:
			r.name_kind = .Subject
		case .Name:
			r.name_kind = .Name
		case .Name_Prefix:
			r.name_kind = .Name_Prefix
		}
		r.name = strings.clone(x.name)
	}
	return
}

leaf_rules_free :: proc(r: ^ossl.Leaf_Rules) {
	delete(r.eku)
	delete(r.name)
	r^ = {}
}

// The TLS version range of the config (`.Any`: the library floor of 1.2, and no cap).
tls_range_of :: proc(t: ^config.Tls_Config) -> (min, max: ossl.Tls_Version) {
	version :: proc(v: config.Tls_Version) -> ossl.Tls_Version {
		switch v {
		case .Default:
			return .Any
		case .V1_2:
			return .TLS_1_2
		case .V1_3:
			return .TLS_1_3
		}
		return .Any
	}
	return version(t.version_min), version(t.version_max)
}

// What the daemon cannot run in these options: an extended key usage the library
// does not know, a name that is too long, a name type that needs
// `x509-username-field`. Appends one text per problem to `errors`.
leaf_rules_problems :: proc(t: ^config.Tls_Config, dirs: []config.Directive, errors: ^[dynamic]string) {
	if t.remote_cert_eku != "" && !ossl.leaf_eku_valid(t.remote_cert_eku) {
		append(errors, fmt.aprintf("remote-cert-eku: '%s' is not an OID in dotted form or a name that the TLS library knows", t.remote_cert_eku))
	}
	x, named := t.verify_x509_name.?
	if !named {
		return
	}
	if len(x.name) > ossl.LEAF_NAME_MAX {
		append(errors, fmt.aprintf("verify-x509-name: the name is too long (the limit is %d bytes)", ossl.LEAF_NAME_MAX))
	}
	if x.kind != .Subject && has_directive(dirs, "x509-username-field") {
		append(errors, strings.clone("verify-x509-name with the type name or name-prefix cannot be used with x509-username-field: noirvpn compares the common name, and not the field of that option"))
	}
}
