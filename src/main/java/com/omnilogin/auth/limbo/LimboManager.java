package com.omnilogin.auth.limbo;

import com.omnilogin.auth.OmniLogin;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.storage.AccountRecord;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import org.bukkit.Bukkit;
import org.bukkit.NamespacedKey;
import org.bukkit.Registry;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitTask;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Coordinates player limbo sessions, countdown kick timers, potion blindness/slowness,
 * BossBar/Title/ActionBar displays, player visibility hiding, and session timeouts.
 */
public final class LimboManager {

    public record AuthSession(
            UUID uuid,
            String username,
            String ipAddress,
            boolean premium,
            Instant authenticatedAt,
            Instant expiresAt,
            Instant registeredAt
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    private record LockoutEntry(int failedAttempts, Instant lockedUntil) {
        boolean isLocked() {
            return lockedUntil != null && Instant.now().isBefore(lockedUntil);
        }

        long remainingSeconds() {
            if (lockedUntil == null) {
                return 0L;
            }
            return Math.max(0L, (lockedUntil.toEpochMilli() - System.currentTimeMillis() + 999L) / 1000L);
        }
    }

    private final OmniLogin plugin;
    private final MessageService messageService;

    private final Map<UUID, LimboSession> limboSessions = new ConcurrentHashMap<>();
    private final Map<UUID, AuthSession> activeAuthSessions = new ConcurrentHashMap<>();
    private final Map<UUID, AuthSession> resumableSessions = new ConcurrentHashMap<>();
    private final Map<String, LockoutEntry> lockouts = new ConcurrentHashMap<>();

    private final PotionEffectType blindnessType;
    private final PotionEffectType slownessType;

    private volatile int timeoutSeconds = 30;
    private volatile boolean allowHeadRotation = false;
    private volatile boolean hideUnauthenticatedPlayers = true;
    private volatile boolean hideOthersFromLimbo = true;
    private volatile boolean applyBlindness = true;
    private volatile boolean applySlowness = true;
    private volatile int slownessAmplifier = 4;
    private volatile int reminderIntervalSeconds = 5;
    private volatile Set<String> allowedCommands = Set.of("login", "l", "register", "reg");
    private volatile boolean bossBarEnabled = true;
    private volatile BossBar.Color bossBarColor = BossBar.Color.BLUE;
    private volatile BossBar.Overlay bossBarOverlay = BossBar.Overlay.PROGRESS;
    private volatile boolean actionBarEnabled = true;
    private volatile boolean titleEnabled = true;
    private volatile int maxLoginAttempts = 5;
    private volatile int lockoutSeconds = 300;
    private volatile int sessionTimeoutMinutes = 60;
    private volatile boolean sessionResumeSameIp = false;

    private BukkitTask tickerTask;

    public LimboManager(OmniLogin plugin, MessageService messageService) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
        this.blindnessType = resolvePotionEffect("blindness", "BLINDNESS", null);
        this.slownessType = resolvePotionEffect("slowness", "SLOWNESS", "SLOW");
    }

    public void reloadFromConfig(FileConfiguration config) {
        this.timeoutSeconds = Math.max(5, config.getInt("limbo.timeout-seconds", 30));
        this.allowHeadRotation = config.getBoolean("limbo.allow-head-rotation", false);
        this.hideUnauthenticatedPlayers = config.getBoolean("limbo.hide-unauthenticated-players", true);
        this.hideOthersFromLimbo = config.getBoolean("limbo.hide-others-from-limbo", true);
        this.applyBlindness = config.getBoolean("limbo.apply-blindness", true);
        this.applySlowness = config.getBoolean("limbo.apply-slowness", true);
        this.slownessAmplifier = Math.max(0, Math.min(255, config.getInt("limbo.slowness-amplifier", 4)));
        this.reminderIntervalSeconds = Math.max(0, config.getInt("limbo.reminder-interval-seconds", 5));

        Set<String> cmds = new HashSet<>();
        for (String cmd : config.getStringList("limbo.allowed-commands")) {
            if (cmd != null && !cmd.isBlank()) {
                cmds.add(cmd.trim().toLowerCase(Locale.ROOT));
            }
        }
        if (cmds.isEmpty()) {
            cmds.addAll(Set.of("login", "l", "register", "reg"));
        }
        this.allowedCommands = Set.copyOf(cmds);

        this.bossBarEnabled = config.getBoolean("limbo.display.bossbar.enabled", true);
        this.bossBarColor = parseBossBarColor(config.getString("limbo.display.bossbar.color", "BLUE"));
        this.bossBarOverlay = parseBossBarOverlay(config.getString("limbo.display.bossbar.overlay", "PROGRESS"));
        this.actionBarEnabled = config.getBoolean("limbo.display.actionbar.enabled", true);
        this.titleEnabled = config.getBoolean("limbo.display.title.enabled", true);

        this.maxLoginAttempts = Math.max(1, config.getInt("security.max-login-attempts", 5));
        this.lockoutSeconds = Math.max(10, config.getInt("security.lockout-seconds", 300));
        this.sessionTimeoutMinutes = Math.max(1, config.getInt("security.session-timeout-minutes", 60));
        this.sessionResumeSameIp = config.getBoolean("security.session-resume-same-ip", false);

        startTickerIfNeeded();
    }

    private void startTickerIfNeeded() {
        if (tickerTask != null) {
            return;
        }
        tickerTask = Bukkit.getScheduler().runTaskTimer(plugin, this::tickLimboSessions, 20L, 20L);
    }

    public void shutdown() {
        if (tickerTask != null) {
            tickerTask.cancel();
            tickerTask = null;
        }
        for (UUID uuid : Set.copyOf(limboSessions.keySet())) {
            Player player = Bukkit.getPlayer(uuid);
            if (player != null) {
                cleanupLimboVisuals(player, limboSessions.remove(uuid));
                restoreAllVisibilityFor(player);
            } else {
                limboSessions.remove(uuid);
            }
        }
        activeAuthSessions.clear();
        resumableSessions.clear();
    }

    public boolean isAuthenticated(UUID uuid) {
        return activeAuthSessions.containsKey(uuid) && !limboSessions.containsKey(uuid);
    }

    public boolean isInLimbo(UUID uuid) {
        return limboSessions.containsKey(uuid);
    }

    public Optional<LimboSession> getLimboSession(UUID uuid) {
        return Optional.ofNullable(limboSessions.get(uuid));
    }

    public Optional<AuthSession> getAuthSession(UUID uuid) {
        return Optional.ofNullable(activeAuthSessions.get(uuid));
    }

    public boolean isAllowHeadRotation() {
        return allowHeadRotation;
    }

    public Set<String> getAllowedCommands() {
        return allowedCommands;
    }

    public int getMaxLoginAttempts() {
        return maxLoginAttempts;
    }

    public int getLockoutSeconds() {
        return lockoutSeconds;
    }

    public long getLockoutRemainingSeconds(UUID uuid, String ip) {
        LockoutEntry entry = lockouts.get(lockoutKey(uuid, ip));
        if (entry == null) {
            return 0L;
        }
        if (!entry.isLocked()) {
            if (entry.lockedUntil() != null) {
                lockouts.remove(lockoutKey(uuid, ip));
            }
            return 0L;
        }
        return entry.remainingSeconds();
    }

    public int recordFailedLoginAttempt(Player player, LimboSession session) {
        int sessionAttempts = session.incrementFailedAttempts();
        String key = lockoutKey(player.getUniqueId(), session.getIpAddress());
        LockoutEntry prev = lockouts.get(key);
        int totalFailures = Math.max(sessionAttempts, (prev != null ? prev.failedAttempts() : 0) + 1);
        if (totalFailures >= maxLoginAttempts) {
            lockouts.put(key, new LockoutEntry(totalFailures, Instant.now().plusSeconds(lockoutSeconds)));
            return 0;
        }
        lockouts.put(key, new LockoutEntry(totalFailures, null));
        return maxLoginAttempts - totalFailures;
    }

    public void clearLockout(UUID uuid, String ip) {
        lockouts.remove(lockoutKey(uuid, ip));
    }

    public boolean canResumeSameIpSession(UUID uuid, String ipAddress) {
        if (!sessionResumeSameIp) {
            return false;
        }
        AuthSession previous = resumableSessions.get(uuid);
        if (previous == null || previous.isExpired()) {
            resumableSessions.remove(uuid);
            return false;
        }
        return ipAddress != null && ipAddress.equals(previous.ipAddress());
    }

    public LimboSession enterLimbo(Player player) {
        UUID uuid = player.getUniqueId();
        activeAuthSessions.remove(uuid);

        boolean prevAllowFlight = player.getAllowFlight();
        boolean prevFlying = player.isFlying();
        if (!prevAllowFlight) {
            // Prevents vanilla anti-fly kick if player spawns mid-air while movement is cancelled
            player.setAllowFlight(true);
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(timeoutSeconds);
        String ip = extractIp(player);
        LimboSession session = new LimboSession(
                uuid,
                player.getName(),
                ip,
                now,
                expiresAt,
                prevAllowFlight,
                prevFlying
        );
        session.setLastReminderEpochSec(now.getEpochSecond());
        limboSessions.put(uuid, session);

        applyLimboEffects(player);
        applyVisibilityForLimboPlayer(player);

        if (bossBarEnabled) {
            BossBar bar = BossBar.bossBar(
                    messageService.deserializeKey("limbo.bossbar-title", Placeholder.unparsed("seconds", String.valueOf(timeoutSeconds))),
                    1.0f,
                    bossBarColor,
                    bossBarOverlay
            );
            session.setBossBar(bar);
            messageService.showBossBar(player, bar);
        }

        renderCountdownDisplays(player, session, false);
        return session;
    }

    public void authenticatePlayer(Player player, AccountRecord account) {
        UUID uuid = player.getUniqueId();
        LimboSession limbo = limboSessions.remove(uuid);
        if (limbo != null) {
            cleanupLimboVisuals(player, limbo);
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(sessionTimeoutMinutes * 60L);
        String ip = extractIp(player);
        clearLockout(uuid, ip);

        AuthSession authSession = new AuthSession(
                uuid,
                player.getName(),
                ip,
                account.premium(),
                now,
                expiresAt,
                account.registeredAt()
        );
        activeAuthSessions.put(uuid, authSession);
        if (sessionResumeSameIp) {
            resumableSessions.put(uuid, authSession);
        }

        applyVisibilityForAuthenticatedPlayer(player);
        player.closeInventory();
    }

    public void handleQuit(Player player) {
        UUID uuid = player.getUniqueId();
        LimboSession limbo = limboSessions.remove(uuid);
        if (limbo != null) {
            cleanupLimboVisuals(player, limbo);
        }
        AuthSession active = activeAuthSessions.remove(uuid);
        if (active != null && sessionResumeSameIp && !active.isExpired()) {
            resumableSessions.put(uuid, active);
        }
    }

    public void invalidateAccountSession(UUID uuid) {
        activeAuthSessions.remove(uuid);
        resumableSessions.remove(uuid);
    }

    private void tickLimboSessions() {
        long nowSec = Instant.now().getEpochSecond();
        for (Map.Entry<UUID, LimboSession> entry : limboSessions.entrySet()) {
            Player player = Bukkit.getPlayer(entry.getKey());
            LimboSession session = entry.getValue();
            if (player == null || !player.isOnline()) {
                limboSessions.remove(entry.getKey());
                continue;
            }

            long remaining = session.getRemainingSeconds();
            if (remaining <= 0L) {
                limboSessions.remove(entry.getKey());
                cleanupLimboVisuals(player, session);
                String kickMsg = messageService.toLegacyKey(
                        "limbo.timeout-kick",
                        Placeholder.unparsed("seconds", String.valueOf(timeoutSeconds))
                );
                player.kickPlayer(kickMsg);
                continue;
            }

            boolean sendReminder = reminderIntervalSeconds > 0
                    && (nowSec - session.getLastReminderEpochSec()) >= reminderIntervalSeconds;
            if (sendReminder) {
                session.setLastReminderEpochSec(nowSec);
            }
            renderCountdownDisplays(player, session, sendReminder);
        }
    }

    private void renderCountdownDisplays(Player player, LimboSession session, boolean sendChatReminder) {
        long remaining = Math.max(0L, session.getRemainingSeconds());
        String secondsText = String.valueOf(remaining);
        boolean registered = Boolean.TRUE.equals(session.getAccountRegistered());

        if (session.getBossBar() != null && bossBarEnabled) {
            float progress = Math.max(0.0f, Math.min(1.0f, (float) remaining / (float) timeoutSeconds));
            session.getBossBar().progress(progress);
            session.getBossBar().name(
                    messageService.deserializeKey("limbo.bossbar-title", Placeholder.unparsed("seconds", secondsText))
            );
        }

        if (actionBarEnabled) {
            String key = registered ? "limbo.actionbar-login" : "limbo.actionbar-register";
            messageService.sendActionBar(player, key, Placeholder.unparsed("seconds", secondsText));
        }

        if (titleEnabled) {
            Component main = messageService.deserializeKey("limbo.title-main");
            String subKey = registered ? "limbo.title-subtitle-login" : "limbo.title-subtitle-register";
            Component sub = messageService.deserializeKey(subKey, Placeholder.unparsed("seconds", secondsText));
            messageService.showTitle(player, main, sub, Duration.ZERO, Duration.ofMillis(1500), Duration.ofMillis(400));
        }

        if (sendChatReminder) {
            String promptKey = registered ? "limbo.login-prompt" : "limbo.register-prompt";
            messageService.send(player, promptKey, Placeholder.unparsed("seconds", secondsText));
        }
    }

    private void applyLimboEffects(Player player) {
        int durationTicks = (timeoutSeconds + 10) * 20;
        if (applyBlindness && blindnessType != null) {
            player.addPotionEffect(new PotionEffect(blindnessType, durationTicks, 0, false, false, false));
        }
        if (applySlowness && slownessType != null) {
            player.addPotionEffect(new PotionEffect(slownessType, durationTicks, slownessAmplifier, false, false, false));
        }
    }

    private void cleanupLimboVisuals(Player player, LimboSession session) {
        if (session != null) {
            if (session.getBossBar() != null) {
                messageService.hideBossBar(player, session.getBossBar());
            }
            player.setFlying(session.isPreviousFlying() && session.isPreviousAllowFlight());
            player.setAllowFlight(session.isPreviousAllowFlight());
        }
        if (blindnessType != null) {
            player.removePotionEffect(blindnessType);
        }
        if (slownessType != null) {
            player.removePotionEffect(slownessType);
        }
        messageService.clearTitle(player);
    }

    private void applyVisibilityForLimboPlayer(Player limboPlayer) {
        if (!hideUnauthenticatedPlayers && !hideOthersFromLimbo) {
            return;
        }
        for (Player other : Bukkit.getOnlinePlayers()) {
            if (other.getUniqueId().equals(limboPlayer.getUniqueId())) {
                continue;
            }
            if (hideUnauthenticatedPlayers && isAuthenticated(other.getUniqueId())) {
                other.hidePlayer(plugin, limboPlayer);
            }
            if (hideOthersFromLimbo) {
                limboPlayer.hidePlayer(plugin, other);
                if (hideUnauthenticatedPlayers && !isAuthenticated(other.getUniqueId())) {
                    other.hidePlayer(plugin, limboPlayer);
                }
            }
        }
    }

    private void applyVisibilityForAuthenticatedPlayer(Player authPlayer) {
        for (Player other : Bukkit.getOnlinePlayers()) {
            if (other.getUniqueId().equals(authPlayer.getUniqueId())) {
                continue;
            }
            if (isAuthenticated(other.getUniqueId())) {
                other.showPlayer(plugin, authPlayer);
                authPlayer.showPlayer(plugin, other);
            } else {
                if (hideUnauthenticatedPlayers) {
                    authPlayer.hidePlayer(plugin, other);
                } else {
                    authPlayer.showPlayer(plugin, other);
                }
                if (!hideOthersFromLimbo) {
                    other.showPlayer(plugin, authPlayer);
                }
            }
        }
    }

    private void restoreAllVisibilityFor(Player player) {
        for (Player other : Bukkit.getOnlinePlayers()) {
            if (!other.getUniqueId().equals(player.getUniqueId())) {
                other.showPlayer(plugin, player);
                player.showPlayer(plugin, other);
            }
        }
    }

    public static String extractIp(Player player) {
        InetSocketAddress addr = player.getAddress();
        if (addr == null || addr.getAddress() == null) {
            return "unknown";
        }
        return addr.getAddress().getHostAddress();
    }

    private static String lockoutKey(UUID uuid, String ip) {
        return uuid + "|" + (ip != null ? ip : "unknown");
    }

    @SuppressWarnings("deprecation")
    private static PotionEffectType resolvePotionEffect(String minecraftKey, String modernName, String legacyName) {
        try {
            PotionEffectType type = Registry.EFFECT.get(NamespacedKey.minecraft(minecraftKey));
            if (type != null) {
                return type;
            }
        } catch (Throwable ignored) {
        }
        PotionEffectType byModern = PotionEffectType.getByName(modernName);
        if (byModern != null) {
            return byModern;
        }
        return legacyName != null ? PotionEffectType.getByName(legacyName) : null;
    }

    private static BossBar.Color parseBossBarColor(String raw) {
        try {
            return BossBar.Color.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            return BossBar.Color.BLUE;
        }
    }

    private static BossBar.Overlay parseBossBarOverlay(String raw) {
        try {
            return BossBar.Overlay.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            return BossBar.Overlay.PROGRESS;
        }
    }
}
