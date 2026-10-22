# Standard license texts

`third-party-notices.py` uses these texts for a crate whose package carries
no license file, such as the arti and tor-* crates, boringtun and void. The
crate's entry in THIRD-PARTY-NOTICES.txt then gives the standard text of each
license its license expression names (both texts for `MIT OR Apache-2.0`),
after a copyright line from the crate's authors field or, for boringtun,
from the header of its source files. The script also takes the standard
library's MIT text from here when the Rust toolchain has no `LICENSE-MIT`
in its `share/doc/rust` (a toolchain that follows REUSE has only
`licenses/MIT.txt`, the SPDX template with the placeholder line
`Copyright (c) <year> <copyright holders>`), and its Apache-2.0 text when
the toolchain has none.

Each file is named after an SPDX license identifier and was copied byte for
byte from a license file in the crates.io package of a crate that
`aether/Cargo.lock` pins, so nothing was retyped. A text that every copy
opens with a copyright line of its own (BSD-3-Clause) is the part after
that line; the notice puts the crate's own copyright line before it.

| File | Copied from | SHA-256 of the file |
| --- | --- | --- |
| `MIT.txt` | adler2 2.0.1, `LICENSE-MIT`, the whole file. anyhow 1.0.104, itoa 1.0.18 and other crates ship the same bytes. | `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3` |
| `Apache-2.0.txt` | cmov 0.5.4, `LICENSE-APACHE`, the whole file. ctutils 0.4.2, clang-sys 1.9.1 (`LICENSE.txt`), zeroize 1.9.0 and other crates ship the same bytes. | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `BSD-3-Clause.txt` | zstd 0.14.0, `LICENSE` (SHA-256 `ce4868c8e4ebe47a7d4b3c93dbf6b802033e5ae2fa7638098173f80836daac60`), from byte 58 (`Redistribution and use`) to the end. Bytes 0 to 57 are the title `BSD 3-Clause License` and the line `Copyright (c) 2026, Alexandre Bury`. | `7a77915f34caf18d47bc31750dae47dbd7f7895e95bbb8370f477c25009388f6` |
| `Zlib.txt` | zlib-rs 0.6.7, `LICENSE` (SHA-256 `e72111c52b7d96ebe25348dee19f0744f444d3c95ae6b1ecb6ccaecc5bce05ba`), from byte 36 (`This software is provided`) to the end. Bytes 0 to 35 are the line `(C) 2024 Trifecta Tech Foundation ` and an empty line. The macOS crates of objc2 (`Zlib OR Apache-2.0 OR MIT`) need it. | `0820e22fd911b85d99f4c2815d6307e10cf94339ecce46df88ee524bc84d0166` |

`.gitattributes` here turns off line-ending conversion, so every checkout
has these exact bytes.

When the script stops because this folder has no text for a license
identifier, add one the same way: find a crate in the local cargo registry
(`~/.cargo/registry/src`) whose license file holds the standard text with no
copyright holder of its own, or whose only own part is its opening title and
copyright lines, copy that file (or the part after those lines) byte for
byte to `<identifier>.txt`, and add its row here.
