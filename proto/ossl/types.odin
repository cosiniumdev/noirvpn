// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+private
package ossl

import "core:c"

// C type aliases. They live here (not in the backend files) so that the
// backend files need no imports of their own.
cint :: c.int
cuint :: c.uint
clong :: c.long
culong :: c.ulong
csize :: c.size_t

// Opaque handles of the C library. Same names in OpenSSL and AWS-LC.
SSL_CTX :: distinct rawptr
SSL :: distinct rawptr
SSL_METHOD :: distinct rawptr
SSL_CIPHER :: distinct rawptr
BIO :: distinct rawptr
BIO_METHOD :: distinct rawptr
X509 :: distinct rawptr
X509_STORE :: distinct rawptr
X509_STORE_CTX :: distinct rawptr
X509_CRL :: distinct rawptr
STACK :: distinct rawptr // a STACK_OF(...), only read through `chain_len` and `chain_get`
X509_NAME :: distinct rawptr
X509_NAME_ENTRY :: distinct rawptr
ASN1_STRING :: distinct rawptr // an ASN1_BIT_STRING is the same type
ASN1_OBJECT :: distinct rawptr
EVP_PKEY :: distinct rawptr
EVP_PKEY_CTX :: distinct rawptr
X509_EXTENSION :: distinct rawptr
X509_REQ :: distinct rawptr
X509_PUBKEY :: distinct rawptr
EVP_MD :: distinct rawptr
EVP_CIPHER :: distinct rawptr
EVP_CIPHER_CTX :: distinct rawptr
