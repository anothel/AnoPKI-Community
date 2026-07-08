# Source File Header Policy

AnoPKI uses the Mozilla Public License Version 2.0 (`MPL-2.0`).

## Required SPDX line

New first-party source files should include this SPDX identifier near the top of the file:

```text
SPDX-License-Identifier: MPL-2.0
```

Use the native comment syntax for each file type.

Examples:

```cpp
// SPDX-License-Identifier: MPL-2.0
```

```go
// SPDX-License-Identifier: MPL-2.0
```

```python
# SPDX-License-Identifier: MPL-2.0
```

For scripts with a shebang, keep the shebang as the first line and place the SPDX line immediately after it.

## Scope

This policy applies to first-party source files, scripts, tests, and build files. Generated files and third-party vendored files should not receive first-party headers unless their origin and license are verified.

## Review rule

Do not add or change license headers in third-party code without confirming the upstream license and attribution requirements.
