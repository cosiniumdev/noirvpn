// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:mem"
import "noir:proto/ossl"

// Terminal question for the passphrase of encrypted private keys (`askpass` with
// no file). The keys and the file are in keys_unlock.odin.
//
//   run / run_server, after sig_open
//     -> keys_unlock_prompt: tty_prompt -> key_unlock -> wipe

// Asks at the terminal for the passphrase of the encrypted keys of `slots` and
// decrypts them. `abort_fd` (the signal descriptor) cancels the question. Three
// tries. False after a message.
keys_unlock_prompt :: proc(slots: []Key_Slot, abort_fd: i32) -> bool {
	pass: [ossl.KEY_PASS_MAX + 2]u8
	defer mem.zero_explicit(&pass, size_of(pass))
	for _ in 1 ..= 3 {
		n, ok := tty_prompt("Enter the passphrase for the private key: ", false, pass[:], abort_fd)
		if !ok {
			eprint("noirvpn: askpass: could not read the passphrase from the terminal")
			return false
		}
		msg := ""
		switch {
		case n == 0:
			msg = "askpass: the passphrase is empty"
		case n > ossl.KEY_PASS_MAX:
			msg = fmt.tprintf("askpass: the passphrase is longer than %d bytes", ossl.KEY_PASS_MAX)
		case:
			for sl in slots {
				if msg = key_unlock(sl, pass[:n], context.temp_allocator); msg != "" {
					break
				}
			}
		}
		mem.zero_explicit(&pass, size_of(pass))
		if msg == "" {
			return true
		}
		eprint("noirvpn: %s", msg)
	}
	return false
}
