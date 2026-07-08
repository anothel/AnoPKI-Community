# Project Identity And License

## Public project name

The public project name is **AnoPKI**.

Use this form in user-facing documentation, release notes, announcements, and support material.

## Technical identifiers

Use the following forms for technical identifiers:

| Context | Identifier |
| --- | --- |
| Repository slug | `anopki` |
| C++ namespace | `anopki` |
| CMake project | `anopki` |
| Core library target | `anopki_core` |
| Core CLI binary | `anopki-core` |
| Go service command | `anopki-service` |
| Environment variable prefix | `ANOPKI_` |
| Webhook headers | `X-AnoPKI-*` |
| Go module path | `github.com/anothel/anopki/service` |

If the GitHub repository slug has not yet been renamed, treat `github.com/anothel/anopki` as the intended post-rename module path and update it consistently during the repository rename.

## Previous name

The previous development name was `modern-pki`. Keep the previous name only in migration notes, compatibility notes, historical changelog entries, and ADRs that explain the rename.

## License

AnoPKI is licensed under the **Mozilla Public License Version 2.0** (`MPL-2.0`).

The repository root `LICENSE` file is the authoritative license text. First-party source files should use the SPDX header documented in [Source File Header Policy](source-file-header-policy.md).
