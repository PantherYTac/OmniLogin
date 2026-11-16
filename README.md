# OmniLogin

Production-grade, modular authentication plugin engineered for modern Minecraft servers running Paper, Spigot, or Purpur (1.20 through 1.21+).

Built from the ground up for high-concurrency environments using Java 21, Kyori Adventure MiniMessage, asynchronous database engines with HikariCP, Netty handshake interception, RFC 9106 Argon2id hashing, and a chest-based virtual PIN-pad interface.

---

## Architectural Highlights

### 1. Player Limbo and Zero-Trust Isolation
- **Immediate State Enforcement**: Unauthenticated players enter an in-memory limbo state upon join before any world or player interaction occurs.
- **Event Cancellation**: Strictly intercepts and blocks movement (`PlayerMoveEvent`), chat messages, entity damage, hunger depletion, inventory interactions, item drops, and non-authentication commands.
- **Entity Concealment**: Conceals unauthenticated players from authenticated users using `Player#hidePlayer` to eliminate visual clutter and spoofing vectors.
- **Session Countdown**: Features an asynchronous countdown timer (default: 30 seconds) that automatically disconnects unauthenticated sessions upon expiration.
- **Visual Feedback**: Applies temporary blindness and slowness effects while rendering configurable BossBars, action bars, and screen titles.

### 2. Modular Password Security and Validation
- **Configurable Length Constraints**: Enforces minimum (default: 6) and maximum (default: 32) password boundaries.
- **Username Matching Rejection**: Rejects passwords containing the player's username (case-insensitive) to prevent trivial credential reuse.
- **Embedded Blacklist**: Validates against a built-in dictionary of over 10,000 common and compromised passwords.
- **Complexity Requirements**: Independently toggleable requirements for numeric digits, uppercase letters, lowercase letters, and special symbols.
- **Pattern Detection**: Disallows repetitive single-character sequences (e.g., `aaaaaa`) and trivial numeric sequences (e.g., `123456`).
- **MiniMessage Feedback**: Delivers clear, formatted error messages explaining the exact requirement failure.

### 3. Hybrid Mojang and Offline Authentication
- **Netty Pre-Login Handshake**: Hooks directly into `AsyncPlayerPreLoginEvent` and network channels with an asynchronous Mojang Session API client and local cache.
- **Premium Auto-Login**: Validates official Mojang ownership over encrypted channels; verified premium players bypass registration and login prompts completely.
- **Cracked Spoof Protection**: Prevents offline launchers from impersonating registered premium accounts with a customizable kick message.
- **Graceful Routing**: Routes non-premium accounts through standard in-game registration and login flows without administrative intervention.

### 4. Chest-Based Virtual PIN-Pad GUI
- **Virtual Keypad**: 3x3 numeric keypad (digits 0 through 9) rendered in a virtual chest inventory using stained glass panes or custom textures.
- **Action Controls**: Dedicated Backspace/Clear and Submit buttons for streamlined navigation.
- **Inventory Safety**: Completely prevents item dragging, shift-clicking, hotbar swapping, and inventory modification while inside the interface.
- **Chat Fallback**: Seamlessly falls back to chat-based `/login` and `/register` commands when GUI mode is disabled or unsupported.

### 5. Enterprise Storage and Hashing
- **Zero Plaintext Storage**: All credentials are salt-hashed prior to storage using RFC 9106 Argon2id or OpenBSD BCrypt.
- **Storage Engines**:
  - **SQLite**: Local single-file storage with WAL (Write-Ahead Logging) and HikariCP connection pooling for fast concurrent reads and writes.
  - **MySQL**: Remote relational database backend for multi-server networks.
  - **YAML**: Lightweight flat-file storage for small servers or testing instances.
- **Asynchronous Execution**: All disk and network I/O operations execute off the primary server thread.

### 6. Administrative Inspection and Auditing
- **Inspection Command**: `/omnicord inspect <player>` (permission: `omnicord.admin.inspect`).
- **Audit Details**: Displays player UUID, registration timestamp, last login IP address, premium verification status, and active session timeout status.

---

## Commands and Permissions

| Command | Aliases | Description | Default Permission |
| :--- | :--- | :--- | :--- |
| `/login <password>` | `/l` | Authenticate an existing account | `omnilogin.command.login` (Everyone) |
| `/register <password> <confirm>` | `/reg` | Register a new account | `omnilogin.command.register` (Everyone) |
| `/changepassword <old> <new> [confirm]` | `/changepass`, `/cp`, `/passwd` | Update current account password | `omnilogin.command.changepassword` (Everyone) |
| `/omnicord inspect <player>` | `/omnilogin inspect` | View detailed player authentication metadata | `omnicord.admin.inspect` (OP) |
| `/omnicord reload` | `/omnilogin reload` | Reload configuration files from disk | `omnicord.admin.reload` (OP) |
| `/omnicord forcelogin <player>` | `/omnilogin forcelogin` | Manually authenticate a player session | `omnicord.admin.forcelogin` (OP) |
| `/omnicord unregister <player>` | `/omnilogin unregister` | Remove a player's credentials from database | `omnicord.admin.unregister` (OP) |

---

## Configuration

Default configuration files are automatically generated in `plugins/OmniLogin/`:

- `config.yml`: Core settings, storage provider selection, password security rules, limbo parameters, and Mojang auto-login toggles.
- `messages.yml`: Fully customizable MiniMessage strings for prompts, errors, titles, action bars, and admin notices.
- `guis.yml`: Visual configuration for the virtual PIN-pad interface, button slots, items, and titles.

---

## Building from Source

### Prerequisites
- JDK 21 or higher
- Gradle 8.5 or higher (or use system Gradle)

### Build Commands
```bash
# Clone the repository
git clone https://github.com/PantherYTac/OmniLogin.git
cd OmniLogin

# Compile and package the shaded distribution JAR
gradle clean build shadowJar
```

The compiled, relocated distribution JAR will be located at:
```
build/libs/OmniLogin-0.0.1-alpha.jar
```

---

## Software Specifications
- **Language**: Java 21
- **Target Platform**: Paper, Spigot, Purpur (1.20 - 1.21+)
- **Build System**: Gradle (Kotlin DSL)
- **Primary Package**: `com.omnilogin.auth`
- **License**: MIT License
