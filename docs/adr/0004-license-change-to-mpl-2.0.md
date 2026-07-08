# ADR 0004: Change Project License To MPL-2.0

## Status

Accepted

## Context

AnoPKI is an open-source PKI lifecycle service and core CLI. The project needs a license policy that allows broad use while keeping modifications to project files available under the same license terms.

## Decision

AnoPKI is licensed under the Mozilla Public License Version 2.0 (`MPL-2.0`). The repository root `LICENSE` file contains the authoritative license text.

First-party source files should use `SPDX-License-Identifier: MPL-2.0` where practical.

## Consequences

- Public documentation, validation scripts, release runbooks, and package metadata must refer to `MPL-2.0`.
- Release artifacts must include or point to the root `LICENSE` file.
- Third-party dependency licenses remain governed by their own upstream licenses and must be reviewed separately.
- Historical references to prior license text should be kept only where they explain migration history.
