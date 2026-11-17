// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:mem"
import "core:os"
import "noir:proto/ossl"

// Passphrase of encrypted private keys (`askpass`).
//
//	settings_load / server_settings_load       (before the privilege drop)
//	  -> keys_unlock
//	       askpass FILE: askpass_read -> key_unlock for each encrypted key -> wipe
//	       askpass:      the keys wait (`key_wait`) or an error when nobody can type;
//	                     a profile of the client service waits for `auth.supply`
//	run / run_server, after sig_open
//	  -> keys_unlock_prompt: tty_prompt -> key_unlock -> wipe
//
// Each key is decrypted once. The daemon holds the decrypted key in the settings
// (like a key without passphrase) and wipes it at exit; the passphrase is wiped
// right after decryption.

// Who can type the passphrase of `askpass` with no file.
Key_Ask :: enum u8 {
	// Nobody: stdin is not a terminal, or the daemon runs as a service.
	Never,
	// Client service profile (from the GUI or noirvpnctl): with `askpass` the keys
	// wait and the passphrase comes with `auth.supply` (`key_pass`). The desktop
	// app reads `askpass FILE` itself.
	Profile,
	// A guest (the library): the keys wait, and the passphrase comes over the
	// request API (`auth.supply`, `profile.check`).
	Guest,
	// `--check-config`: nobody is asked now.
	Check,
	// The terminal, after the start checks (`keys_unlock_prompt`).
	Later,
}

// A private key of the settings and the option it comes from.
Key_Slot :: struct {
	pem:  ^[]u8,
	what: string,
}

@(private = "file")
REMOVE_PASS :: "remove the passphrase from the key (openssl pkey -in KEY -out NEW-KEY)"

// Decrypts the encrypted keys of `slots` with the `askpass` passphrase. Problems
// go to `errors` and `warnings`. True: the keys wait for the terminal passphrase
// (only with `ask` .Later).
keys_unlock :: proc(askpass: Maybe(string), ask: Key_Ask, slots: []Key_Slot, errors, warnings: ^[dynamic]string) -> (wait: bool) {
	locked := 0
	for sl in slots {
		if len(sl.pem^) > 0 && ossl.key_pem_encrypted(sl.pem^) {
			locked += 1
		}
	}
	file, set := askpass.?
	if !set && ask == .Guest {
		return locked > 0
	}
	if !set {
		for sl in slots {
			if len(sl.pem^) == 0 || !ossl.key_pem_encrypted(sl.pem^) {
				continue
			}
			if ask == .Profile {
				append(errors, fmt.aprintf("%s: the key is encrypted, and the service cannot ask for its passphrase without askpass; add askpass (to be asked when connecting) or askpass FILE (the desktop app reads FILE), or %s", sl.what, REMOVE_PASS))
			} else {
				append(errors, fmt.aprintf("%s: the key is encrypted, so give its passphrase with askpass FILE (the first line of FILE), or use askpass alone to type it at start", sl.what))
			}
		}
		return false
	}
	if file == "" {
		if locked == 0 {
			append(warnings, fmt.aprintf("askpass: no key is encrypted, so askpass will have no effect"))
			return false
		}
		switch ask {
		case .Later:
			return true
		case .Check:
			append(warnings, fmt.aprintf("askpass: the passphrase will be typed at the terminal at start, so the encrypted key cannot be checked now"))
		case .Profile, .Guest:
			// The passphrase comes over the bus (`auth.supply` with `key_pass`).
			// A guest profile has no askpass line; a service profile has one.
			return true
		case .Never:
			append(errors, fmt.aprintf("askpass: the key is encrypted, and there is no terminal to type its passphrase (stdin is not a terminal, or noirvpn runs as a service); give the passphrase in a file with askpass FILE"))
		}
		return false
	}

	pass: [ossl.KEY_PASS_MAX + 2]u8
	defer mem.zero_explicit(&pass, size_of(pass))
	n, msg, open_to_others := askpass_read(file, pass[:])
	if msg != "" {
		append(errors, fmt.aprintf("askpass: %s", msg))
		return false
	}
	if open_to_others {
		append(warnings, fmt.aprintf("askpass: other users can read %s, so allow only its owner to read it (chmod 600)", file))
	}
	if locked == 0 {
		append(warnings, fmt.aprintf("askpass: no key is encrypted, so askpass will have no effect"))
		return false
	}
	for sl in slots {
		if m := key_unlock(sl, pass[:n]); m != "" {
			append(errors, m)
		}
	}
	return false
}

// Decrypts the key of `sl` in place when it is encrypted. "" when done, else
// the message (allocated with `allocator`).
key_unlock :: proc(sl: Key_Slot, pass: []u8, allocator := context.allocator) -> string {
	key := sl.pem^
	if len(key) == 0 || !ossl.key_pem_encrypted(key) {
		return ""
	}
	plain, err := ossl.key_pem_decrypt(key, pass)
	#partial switch err {
	case .None:
		mem.zero_explicit(raw_data(key), len(key))
		delete(key)
		sl.pem^ = plain
		return ""
	case .Bad_Passphrase:
		return fmt.aprintf("%s: the passphrase does not open the key (a wrong passphrase, or a damaged key file)", sl.what, allocator = allocator)
	case .Bad_Key:
		return fmt.aprintf("%s: cannot read the encrypted key because the crypto library does not support its encryption, or the file is damaged", sl.what, allocator = allocator)
	}
	return fmt.aprintf("%s: cannot decrypt the key (%v)", sl.what, err, allocator = allocator)
}

// Reads the `askpass FILE` passphrase: first line, no trailing CR or LF. Returns
// its length in `buf`, or a message. `open_to_others`: group or others can read
// the file (POSIX only). The caller wipes `buf`.
askpass_read :: proc(path: string, buf: []u8) -> (n: int, msg: string, open_to_others: bool) {
	f, err := os.open(path)
	if err != nil {
		return 0, fmt.tprintf("cannot read %s", path), false
	}
	defer os.close(f)
	when ODIN_OS != .Windows {
		if fi, serr := os.fstat(f, context.temp_allocator); serr == nil {
			open_to_others = .Read_Group in fi.mode || .Read_Other in fi.mode
		}
	}
	got := 0
	for got < len(buf) {
		r, rerr := os.read(f, buf[got:])
		if r > 0 {
			got += r
		}
		if rerr != nil || r <= 0 {
			if rerr != nil && rerr != .EOF {
				return 0, fmt.tprintf("cannot read %s", path), open_to_others
			}
			break
		}
	}
	line := got
	full := true
	for i in 0 ..< got {
		if buf[i] == '\n' {
			line = i
			full = false
			break
		}
	}
	if line > 0 && buf[line - 1] == '\r' {
		line -= 1
	}
	switch {
	case line > ossl.KEY_PASS_MAX, full && got == len(buf):
		return 0, fmt.tprintf("the first line of %s is longer than %d bytes", path, ossl.KEY_PASS_MAX), open_to_others
	case line == 0:
		return 0, fmt.tprintf("the first line of %s is empty", path), open_to_others
	}
	return line, "", open_to_others
}
