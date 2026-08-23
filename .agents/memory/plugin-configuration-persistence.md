---
name: Plugin configuration persistence
description: Durable rule for changing plugin enablement through the CLI.
---

Plugin enable/disable persistence must start from the effective merged configuration, then write the smallest user or explicitly selected configuration override.

**Why:** A new user configuration file containing only the changed plugin can replace the project enabled list and unintentionally disable every built-in plugin not repeated there.

**How to apply:** When persisting plugin state, merge the current effective enabled/disabled sets with the destination file's values, change only the requested plugin, and preserve configuration precedence.