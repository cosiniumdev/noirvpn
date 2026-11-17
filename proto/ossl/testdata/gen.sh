#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Regenerates every file in this directory. Needs the openssl CLI >= 3.5.
# These are TEST keys. Never use them for anything real.
set -eu
cd "$(dirname "$0")"

DAYS=36500

# Argument (the keys of the other files stay as they are):
#   ./gen.sh crl       only the CRL files below
#   ./gen.sh leaf      only the leaf rule files
#   ./gen.sh keypass   only the encrypted keys
#   ./gen.sh plain     only the traditional PEM forms
# With no argument everything is made.
ONLY=${1:-all}

# Self-signed pair for key-pinning tests: <name>_server and <name>_client.
# $1 = name, $2.. = extra `-newkey` style arguments for `openssl req`.
selfsigned() {
	name=$1
	shift
	for role in server client; do
		openssl req -x509 -noenc -days "$DAYS" -subj "/CN=noir-test-$name-$role" \
			-keyout "${name}_$role.key.pem" -out "${name}_$role.crt.pem" "$@"
		# Whole certificate as DER (for the peer-fingerprint check).
		openssl x509 -in "${name}_$role.crt.pem" -outform DER -out "${name}_$role.crt.der"
		# SubjectPublicKeyInfo as DER (what the key pin is a hash of).
		openssl x509 -in "${name}_$role.crt.pem" -pubkey -noout |
			openssl pkey -pubin -outform DER -out "${name}_$role.spki.der"
	done
}

base_files() {
	selfsigned ed25519 -newkey ed25519
	selfsigned p256 -newkey ec -pkeyopt ec_paramgen_curve:P-256
	selfsigned mldsa65 -newkey ML-DSA-65
	selfsigned rsa -newkey rsa:2048

	# A small CA, and server/client certificates it signs (for the chain mode).
	# The CA key is thrown away after signing; the tests never need it.
	openssl req -x509 -noenc -days "$DAYS" -subj "/CN=noir-test-ca" -newkey ed25519 \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout ca.key.tmp -out ca.crt.pem
	for role in server client; do
		openssl req -new -noenc -subj "/CN=noir-test-chain-$role" -newkey ed25519 \
			-keyout "chain_$role.key.pem" -out "chain_$role.csr.tmp"
		printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' >ext.tmp
		openssl x509 -req -in "chain_$role.csr.tmp" -CA ca.crt.pem -CAkey ca.key.tmp \
			-CAcreateserial -days "$DAYS" -extfile ext.tmp -out "chain_$role.crt.pem"
	done
	rm -f ca.key.tmp ./*.csr.tmp ext.tmp ca.crt.srl

	# A second, unrelated CA: the chain must NOT verify against it.
	openssl req -x509 -noenc -days "$DAYS" -subj "/CN=noir-test-other-ca" -newkey ed25519 \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout other_ca.key.tmp -out other_ca.crt.pem
	rm -f other_ca.key.tmp

	# Client certificates with an odd subject, for the common-name accessor: no CN
	# at all, and two CNs.
	openssl req -x509 -noenc -days "$DAYS" -subj "/O=noir-test-no-common-name" -newkey ed25519 \
		-keyout nocn_client.key.pem -out nocn_client.crt.pem
	openssl req -x509 -noenc -days "$DAYS" -subj "/CN=first-name/CN=second-name" -newkey ed25519 \
		-keyout twocn_client.key.pem -out twocn_client.crt.pem
}

# The PKI of the revocation tests (crl-verify): a root, an intermediate CA that
# it signs, and leaf certificates that the intermediate signs. Serial numbers
# are fixed so the tests can name them: intermediate 2001, good leaf 3001, bad
# leaf 3002. The "long" leaf has a 20 byte serial.
#
#   crl_root.crt.pem            the trust anchor
#   crl_sub.crt.pem             the intermediate CA (serial 2001)
#   crl_good.*, crl_bad.*       leaf certificates and keys (serials 3001, 3002)
#   crl_long.crt.pem            a leaf with the serial 0x0102030405060708090a0b0c0d0e0f1011121314
#   crl_sub_bad.crl.pem         CRL of the intermediate: revokes crl_bad
#   crl_sub_empty.crl.pem       CRL of the intermediate: revokes nothing
#   crl_sub_expired.crl.pem     CRL of the intermediate that is out of date (revokes crl_bad)
#   crl_root_sub.crl.pem        CRL of the root: revokes the intermediate
#   crl_root_empty.crl.pem      CRL of the root: revokes nothing
crl_files() {
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	cfg_for() { # $1 = dir of the CA database
		cat >"$1/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $1
database = $1/index.txt
new_certs_dir = $1
serial = $1/serial
crlnumber = $1/crlnumber
default_md = default
policy = policy_any
unique_subject = no
copy_extensions = none
[policy_any]
commonName = supplied
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
EOF
		: >"$1/index.txt"
		echo 01 >"$1/crlnumber"
	}
	mkdir "$work/root" "$work/sub"
	cfg_for "$work/root"
	cfg_for "$work/sub"

	openssl req -x509 -noenc -days "$DAYS" -subj "/CN=noir-test-crl-root" -newkey ed25519 \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$work/root.key" -out crl_root.crt.pem

	# issue <ca dir> <ca cert> <ca key> <ext section> <serial hex> <subject> <key out> <cert out>
	issue() {
		printf '%s\n' "$5" >"$1/serial"
		openssl req -new -noenc -subj "$6" -newkey ed25519 -keyout "$7" -out "$work/req.csr"
		openssl ca -batch -config "$1/ca.cnf" -cert "$2" -keyfile "$3" -extensions "$4" \
			-days "$DAYS" -notext -in "$work/req.csr" -out "$8"
	}
	issue "$work/root" crl_root.crt.pem "$work/root.key" v3_ca 07D1 /CN=noir-test-crl-sub "$work/sub.key" crl_sub.crt.pem
	issue "$work/sub" crl_sub.crt.pem "$work/sub.key" v3_leaf 0BB9 /CN=noir-test-crl-good crl_good.key.pem crl_good.crt.pem
	issue "$work/sub" crl_sub.crt.pem "$work/sub.key" v3_leaf 0BBA /CN=noir-test-crl-bad crl_bad.key.pem crl_bad.crt.pem
	issue "$work/sub" crl_sub.crt.pem "$work/sub.key" v3_leaf 0102030405060708090a0b0c0d0e0f1011121314 /CN=noir-test-crl-long "$work/long.key" crl_long.crt.pem

	gencrl() { # <ca dir> <ca cert> <ca key> <out> [extra args]
		d=$1 c=$2 k=$3 o=$4
		shift 4
		openssl ca -config "$d/ca.cnf" -cert "$c" -keyfile "$k" -gencrl -crldays 36500 -crl_lastupdate 20200101000000Z "$@" -out "$o"
	}
	gencrl "$work/root" crl_root.crt.pem "$work/root.key" crl_root_empty.crl.pem
	gencrl "$work/sub" crl_sub.crt.pem "$work/sub.key" crl_sub_empty.crl.pem

	openssl ca -batch -config "$work/root/ca.cnf" -cert crl_root.crt.pem -keyfile "$work/root.key" -revoke crl_sub.crt.pem
	gencrl "$work/root" crl_root.crt.pem "$work/root.key" crl_root_sub.crl.pem

	openssl ca -batch -config "$work/sub/ca.cnf" -cert crl_sub.crt.pem -keyfile "$work/sub.key" -revoke crl_bad.crt.pem
	gencrl "$work/sub" crl_sub.crt.pem "$work/sub.key" crl_sub_bad.crl.pem
	gencrl "$work/sub" crl_sub.crt.pem "$work/sub.key" crl_sub_expired.crl.pem \
		-crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z
}

# The PKI of the leaf rule tests (remote-cert-tls, remote-cert-ku,
# remote-cert-eku, verify-x509-name): one CA and leaf certificates with
# different key usage, extended key usage and names. The CA key is thrown away.
#
#   leaf_ca.crt.pem       the trust anchor
#   leaf_server.*         KU digitalSignature+keyEncipherment (0xa0), EKU serverAuth,
#                         subject C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1
#   leaf_client.*         KU digitalSignature (0x80), EKU clientAuth, CN=Client-1
#   leaf_both.*           KU 0x80, EKU serverAuth and clientAuth, CN=Both-1
#   leaf_noeku.*          KU 0x80, no EKU, CN=Server-2
#   leaf_noku.*           no KU, EKU serverAuth, CN=Server-3
#   leaf_plain.*          no KU, no EKU, CN=Plain-1
#   leaf_dec.*            KU digitalSignature+keyAgreement+decipherOnly (0x88 and bit 9), EKU serverAuth, CN=Dec-1
#   leaf_eku3.*           KU 0x80, EKU serverAuth, codeSigning and 1.3.6.1.4.1.99999.1.2, CN=Eku-3
#   leaf_odd.*            KU 0x80, EKU serverAuth, a subject with characters that need escapes
#   leaf_longcn.*         KU 0x80, EKU serverAuth, a CN of 80 bytes in UTF-8 (40 characters)
#   leaf_ctl.*, leaf_nul.* CN=Ctl-AAAA and CN=Nul-AAAA: a test patches the four A bytes
#                         to control bytes and to a NUL byte (the signature then fails; only the
#                         parsing is used)
leaf_files() {
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	openssl req -x509 -noenc -days "$DAYS" -subj "/CN=noir-test-leaf-ca" -newkey ed25519 \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$work/ca.key" -out leaf_ca.crt.pem
	# leaf <name> <subject> <extensions>
	leaf() {
		openssl req -new -noenc -utf8 -subj "$2" -newkey ed25519 -keyout "leaf_$1.key.pem" -out "$work/req.csr"
		printf 'basicConstraints=CA:FALSE\n%s\n' "$3" >"$work/ext"
		openssl x509 -req -in "$work/req.csr" -CA leaf_ca.crt.pem -CAkey "$work/ca.key" \
			-CAcreateserial -CAserial "$work/serial" -days "$DAYS" -extfile "$work/ext" -out "leaf_$1.crt.pem"
	}
	leaf server "/C=KG/ST=NA/L=Bishkek/O=Noir Test/CN=Server-1" 'keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth'
	leaf client "/C=KG/O=Noir Test/CN=Client-1" 'keyUsage=digitalSignature
extendedKeyUsage=clientAuth'
	leaf both "/CN=Both-1" 'keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth'
	leaf noeku "/CN=Server-2" 'keyUsage=digitalSignature'
	leaf noku "/CN=Server-3" 'extendedKeyUsage=serverAuth'
	leaf plain "/CN=Plain-1" 'subjectKeyIdentifier=hash'
	leaf dec "/CN=Dec-1" 'keyUsage=digitalSignature,keyAgreement,decipherOnly
extendedKeyUsage=serverAuth'
	leaf eku3 "/CN=Eku-3" 'keyUsage=digitalSignature
extendedKeyUsage=serverAuth,codeSigning,1.3.6.1.4.1.99999.1.2'
	e_acute=$(printf '\303\251')
	leaf odd "/C=KG/O=Acme, Inc./OU=Caf$e_acute/CN=Odd \\+ Name" 'keyUsage=digitalSignature
extendedKeyUsage=serverAuth'
	# 40 characters of 2 bytes each: within the 64 character limit of the
	# `req` command, and 80 bytes in UTF-8.
	long_cn=
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
		long_cn=$long_cn$e_acute
	done
	leaf longcn "/CN=$long_cn" 'keyUsage=digitalSignature
extendedKeyUsage=serverAuth'
	leaf ctl "/CN=Ctl-AAAA" 'keyUsage=digitalSignature'
	leaf nul "/CN=Nul-AAAA" 'keyUsage=digitalSignature'
}

# Encrypted copies of the server keys of the self-signed pairs, for the
# passphrase tests (`askpass`). The passphrase is "noir-test-pass".
#
#   keypass_pkcs8_<name>.key.pem    PKCS#8, PBES2 with PBKDF2 and AES-256-CBC
#   keypass_legacy_<name>.key.pem   the legacy PEM form (Proc-Type, DEK-Info), AES-256-CBC
#   keypass_des3_rsa.key.pem        the legacy PEM form with DES-EDE3-CBC (`openssl genrsa -des3`)
keypass_files() {
	pass=pass:noir-test-pass
	for name in ed25519 p256 rsa; do
		openssl pkey -in "${name}_server.key.pem" -aes-256-cbc -passout "$pass" -out "keypass_pkcs8_$name.key.pem"
	done
	openssl rsa -in rsa_server.key.pem -traditional -aes256 -passout "$pass" -out keypass_legacy_rsa.key.pem
	openssl ec -in p256_server.key.pem -aes256 -passout "$pass" -out keypass_legacy_p256.key.pem
	openssl rsa -in rsa_server.key.pem -traditional -des3 -passout "$pass" -out keypass_des3_rsa.key.pem
}

# Unencrypted copies of client keys in the traditional PEM forms, for the key
# argument of cert.read and identity.set (csr_test.odin, engine tests).
#
#   plain_sec1_p256_client.key.pem    "EC PRIVATE KEY" (SEC1) of p256_client.key.pem
#   plain_rsa_client.key.pem          "RSA PRIVATE KEY" (PKCS#1) of rsa_client.key.pem
plain_files() {
	openssl ec -in p256_client.key.pem -out plain_sec1_p256_client.key.pem
	openssl rsa -in rsa_client.key.pem -traditional -out plain_rsa_client.key.pem
}

case "$ONLY" in
all)
	base_files
	crl_files
	leaf_files
	keypass_files
	plain_files
	;;
plain) plain_files ;;
crl) crl_files ;;
leaf) leaf_files ;;
keypass) keypass_files ;;
*)
	echo "usage: gen.sh [crl|leaf|keypass]" >&2
	exit 2
	;;
esac
