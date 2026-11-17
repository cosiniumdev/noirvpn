// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build freestanding
package config

// A freestanding build has no files. Pass a `Loader` in `Parse_Options` to
// allow `config` includes.
default_loader: Loader
