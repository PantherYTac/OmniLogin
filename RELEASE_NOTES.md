# OmniLogin alpha 0.0.1

Initial alpha release of OmniLogin, a modular authentication plugin for Paper, Spigot, and Purpur (1.20 - 1.21+).

## Key Features

- Player Limbo and Zero-Trust Isolation: Immediate pre-authentication isolation, event cancellation, entity concealment via Player#hidePlayer, and a 30-second countdown kick.
- Modular Password Security: Length constraints, username exclusion, embedded common-password blacklist, and configurable complexity rules.
- Hybrid Mojang Authentication: Asynchronous Mojang Session API verification with local caching, auto-login for verified premium accounts, and spoof protection against offline launchers.
- Virtual PIN-Pad GUI: Chest-based 3x3 numeric keypad with item dragging and modification prevention.
- Enterprise Storage: Asynchronous HikariCP storage engine supporting SQLite (WAL mode), MySQL, and flat-file YAML.
- Zero Plaintext Storage: Password hashing with RFC 9106 Argon2id and OpenBSD BCrypt.
- Administrative Audit: In-game /omnicord inspect command for real-time authentication auditing.

## Distribution Artifacts

- OmniLogin-0.0.1-alpha.jar: Relocated, shaded distribution JAR for Paper, Spigot, and Purpur (1.20 - 1.21+).
