package com.omnilogin.auth.commands;

import com.omnilogin.auth.OmniLogin;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.limbo.LimboManager;
import com.omnilogin.auth.limbo.LimboSession;
import com.omnilogin.auth.storage.AccountRecord;
import com.omnilogin.auth.storage.StorageProvider;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;

/**
 * Administrative command suite under {@code /omnicord} supporting account inspection
 * ({@code omnicord.admin.inspect}), config reloads, force-login, and credential deletion.
 */
public final class OmniCordCommand implements TabExecutor {

    private static final DateTimeFormatter DISPLAY_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    private static final List<String> SUBCOMMANDS = List.of("inspect", "reload", "forcelogin", "unregister");

    private final OmniLogin plugin;
    private final StorageProvider storageProvider;
    private final LimboManager limboManager;
    private final MessageService messageService;

    public OmniCordCommand(
            OmniLogin plugin,
            StorageProvider storageProvider,
            LimboManager limboManager,
            MessageService messageService
    ) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.storageProvider = Objects.requireNonNull(storageProvider, "storageProvider");
        this.limboManager = Objects.requireNonNull(limboManager, "limboManager");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            messageService.send(sender, "admin.help");
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        switch (sub) {
            case "inspect" -> handleInspect(sender, args);
            case "reload" -> handleReload(sender);
            case "forcelogin" -> handleForceLogin(sender, args);
            case "unregister" -> handleUnregister(sender, args);
            default -> messageService.send(sender, "admin.help");
        }
        return true;
    }

    private void handleInspect(CommandSender sender, String[] args) {
        if (!sender.hasPermission("omnicord.admin.inspect")) {
            messageService.send(sender, "general.no-permission");
            return;
        }
        if (args.length < 2) {
            messageService.send(sender, "admin.help");
            return;
        }

        String targetArg = args[1];
        Player onlineTarget = Bukkit.getPlayerExact(targetArg);

        lookupAccount(onlineTarget, targetArg).whenComplete((recordOpt, ex) -> {
            if (!plugin.isEnabled()) {
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (ex != null) {
                    plugin.getLogger().log(Level.SEVERE, "Failed inspecting player " + targetArg, ex);
                    messageService.send(sender, "general.internal-error");
                    return;
                }

                if (recordOpt.isEmpty() && onlineTarget == null) {
                    messageService.send(sender, "admin.player-not-found", Placeholder.unparsed("target", targetArg));
                    return;
                }

                UUID uuid = recordOpt.map(AccountRecord::uuid)
                        .orElseGet(() -> onlineTarget.getUniqueId());
                String username = recordOpt.map(AccountRecord::username)
                        .orElseGet(() -> onlineTarget.getName());
                boolean isPremium = recordOpt.map(AccountRecord::premium).orElse(false);

                String registeredAt = recordOpt
                        .map(r -> DISPLAY_TIMESTAMP.format(r.registeredAt()) + " (" + r.registeredAt() + ")")
                        .orElse("Unregistered");
                String lastLoginAt = recordOpt
                        .map(AccountRecord::lastLoginAt)
                        .map(t -> DISPLAY_TIMESTAMP.format(t) + " (" + t + ")")
                        .orElse("Never");
                String lastIp = recordOpt
                        .map(AccountRecord::lastIp)
                        .orElseGet(() -> onlineTarget != null ? LimboManager.extractIp(onlineTarget) : "unknown");

                String authState = resolveAuthStateDisplay(uuid, onlineTarget != null && onlineTarget.isOnline());
                String premiumStatus = isPremium
                        ? "<aqua>Premium (Mojang Verified)</aqua>"
                        : "<gray>Offline / Cracked</gray>";
                String sessionTimeout = resolveSessionTimeoutDisplay(uuid);

                messageService.send(
                        sender,
                        "admin.inspect-card",
                        Placeholder.unparsed("username", username),
                        Placeholder.unparsed("uuid", uuid.toString()),
                        Placeholder.parsed("auth_state", authState),
                        Placeholder.parsed("premium_status", premiumStatus),
                        Placeholder.unparsed("registered_at", registeredAt),
                        Placeholder.unparsed("last_login_at", lastLoginAt),
                        Placeholder.unparsed("last_ip", lastIp),
                        Placeholder.unparsed("session_timeout", sessionTimeout)
                );
            });
        });
    }

    private void handleReload(CommandSender sender) {
        if (!sender.hasPermission("omnicord.admin.reload")) {
            messageService.send(sender, "general.no-permission");
            return;
        }
        plugin.reloadPlugin();
        messageService.send(sender, "general.reload-success");
    }

    private void handleForceLogin(CommandSender sender, String[] args) {
        if (!sender.hasPermission("omnicord.admin.forcelogin")) {
            messageService.send(sender, "general.no-permission");
            return;
        }
        if (args.length < 2) {
            messageService.send(sender, "admin.help");
            return;
        }
        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null || !target.isOnline()) {
            messageService.send(sender, "admin.player-not-online", Placeholder.unparsed("target", args[1]));
            return;
        }
        if (limboManager.isAuthenticated(target.getUniqueId())) {
            messageService.send(sender, "admin.forcelogin-already", Placeholder.unparsed("target", target.getName()));
            return;
        }

        Instant now = Instant.now();
        String ip = LimboManager.extractIp(target);
        storageProvider.findByUuid(target.getUniqueId()).whenComplete((opt, ex) -> {
            if (!plugin.isEnabled()) {
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!target.isOnline()) {
                    return;
                }
                AccountRecord record = opt.orElseGet(() ->
                        new AccountRecord(target.getUniqueId(), target.getName(), null, false, now, now, ip)
                );
                limboManager.authenticatePlayer(target, record);
                messageService.send(target, "auth.login-success");
                messageService.send(sender, "admin.forcelogin-success", Placeholder.unparsed("target", target.getName()));
            });
        });
    }

    private void handleUnregister(CommandSender sender, String[] args) {
        if (!sender.hasPermission("omnicord.admin.unregister")) {
            messageService.send(sender, "general.no-permission");
            return;
        }
        if (args.length < 2) {
            messageService.send(sender, "admin.help");
            return;
        }

        String targetArg = args[1];
        Player onlineTarget = Bukkit.getPlayerExact(targetArg);

        lookupAccount(onlineTarget, targetArg).thenCompose(opt -> {
            if (opt.isEmpty()) {
                return CompletableFuture.completedFuture((AccountRecord) null);
            }
            AccountRecord rec = opt.get();
            return storageProvider.deleteAccount(rec.uuid())
                    .thenApply(deleted -> deleted ? rec : null);
        }).whenComplete((deletedRecord, ex) -> {
            if (!plugin.isEnabled()) {
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (ex != null) {
                    plugin.getLogger().log(Level.SEVERE, "Failed unregistering player " + targetArg, ex);
                    messageService.send(sender, "general.internal-error");
                    return;
                }
                if (deletedRecord == null) {
                    messageService.send(sender, "admin.player-not-found", Placeholder.unparsed("target", targetArg));
                    return;
                }

                limboManager.invalidateAccountSession(deletedRecord.uuid());
                Player live = Bukkit.getPlayer(deletedRecord.uuid());
                if (live != null && live.isOnline() && !limboManager.isInLimbo(live.getUniqueId())) {
                    LimboSession limbo = limboManager.enterLimbo(live);
                    limbo.setAccountRegistered(false);
                }
                messageService.send(sender, "admin.unregister-success", Placeholder.unparsed("target", deletedRecord.username()));
            });
        });
    }

    private CompletableFuture<Optional<AccountRecord>> lookupAccount(Player onlineTarget, String targetArg) {
        if (onlineTarget != null) {
            return storageProvider.findByUuid(onlineTarget.getUniqueId());
        }
        try {
            UUID parsed = UUID.fromString(targetArg);
            return storageProvider.findByUuid(parsed);
        } catch (IllegalArgumentException ignored) {
            return storageProvider.findByUsername(targetArg);
        }
    }

    private String resolveAuthStateDisplay(UUID uuid, boolean isOnline) {
        if (!isOnline) {
            return "<gray>Offline</gray>";
        }
        if (limboManager.isAuthenticated(uuid)) {
            return "<green>Authenticated (Online)</green>";
        }
        if (limboManager.isInLimbo(uuid)) {
            return "<red>Unauthenticated (Limbo)</red>";
        }
        return "<yellow>Pending</yellow>";
    }

    private String resolveSessionTimeoutDisplay(UUID uuid) {
        Optional<LimboManager.AuthSession> authSession = limboManager.getAuthSession(uuid);
        if (authSession.isPresent()) {
            LimboManager.AuthSession s = authSession.get();
            Duration rem = Duration.between(Instant.now(), s.expiresAt());
            long totalSecs = Math.max(0L, rem.toSeconds());
            long mins = totalSecs / 60L;
            long secs = totalSecs % 60L;
            return String.format("%dm %02ds remaining (expires %s)", mins, secs, DISPLAY_TIMESTAMP.format(s.expiresAt()));
        }
        Optional<LimboSession> limboSession = limboManager.getLimboSession(uuid);
        if (limboSession.isPresent()) {
            return "Limbo expires in " + limboSession.get().getRemainingSeconds() + "s";
        }
        return "No active session (Offline)";
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            String prefix = args[0].toLowerCase(Locale.ROOT);
            return SUBCOMMANDS.stream()
                    .filter(s -> s.startsWith(prefix))
                    .filter(s -> sender.hasPermission("omnicord.admin." + s))
                    .toList();
        }
        if (args.length == 2 && (args[0].equalsIgnoreCase("inspect")
                || args[0].equalsIgnoreCase("forcelogin")
                || args[0].equalsIgnoreCase("unregister"))) {
            String prefix = args[1].toLowerCase(Locale.ROOT);
            return Bukkit.getOnlinePlayers().stream()
                    .map(Player::getName)
                    .filter(name -> name.toLowerCase(Locale.ROOT).startsWith(prefix))
                    .toList();
        }
        return List.of();
    }
}
