// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "noir:proto/ossl"

// Starts the AEAD override of proto/ossl, when the build has one. The client
// and the server call it once at start, before the privilege drop and before
// any thread generates a data channel key.
aead_start :: proc() {
	r := ossl.aead_override_start()
	switch {
	case r.table.name != "":
		logf(.Info, "AES-GCM: %s", r.table.name)
	case r.failed:
		logf(.Warn, "AES-GCM: %s, so the crypto library handles it", r.note)
	case r.note != "":
		logf(.Debug, "AES-GCM: crypto library (%s)", r.note)
	}
}
