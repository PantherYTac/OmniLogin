package com.omnilogin.auth.premium;

import com.omnilogin.auth.config.ConfigManager;
import com.omnilogin.auth.config.MessageService;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Coordinates hybrid premium/cracked Mojang verification, local TTL caching,
 * spoof rejection, and Netty RSA/AES handshake management.
 */
public final class PremiumLoginManager {

    private static final long HANDSHAKE_TOKEN_TTL_MS = 30_000L;

    private final Logger logger;
    private final ConfigManager configManager;
    private final MessageService messageService;
    private final MojangApiClient mojangApi;
    private final KeyPair rsaKeyPair;
    private final NettyHandshakeInjector nettyInjector;

    private final Map<String, VerifiedPremiumSession> pendingVerifiedHandshakes = new ConcurrentHashMap<>();
    private final Map<UUID, VerifiedPremiumSession> verifiedJoinSessions = new ConcurrentHashMap<>();

    private volatile boolean enabled;
    private volatile boolean nettyHandshakeEnabled;
    private volatile boolean strictRejectUnverifiedPremium;
    private volatile boolean applyMojangUuid;
    private volatile boolean applyMojangSkin;
    private volatile boolean denyOnApiError;

    public PremiumLoginManager(Logger logger, ConfigManager configManager, MessageService messageService) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.configManager = Objects.requireNonNull(configManager, "configManager");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
        this.mojangApi = new MojangApiClient(logger);
        this.rsaKeyPair = generateRsaKeyPair();
        this.nettyInjector = new NettyHandshakeInjector(logger, this, mojangApi, rsaKeyPair);
    }

    public void reloadFromConfig(FileConfiguration config) {
        this.enabled = config.getBoolean("premium-auto-login.enabled", false);
        this.nettyHandshakeEnabled = config.getBoolean("premium-auto-login.netty-encryption-handshake", true);
        this.strictRejectUnverifiedPremium = config.getBoolean("premium-auto-login.strict-reject-unverified-premium", true);
        this.applyMojangUuid = config.getBoolean("premium-auto-login.apply-mojang-uuid", true);
        this.applyMojangSkin = config.getBoolean("premium-auto-login.apply-mojang-skin", true);
        this.denyOnApiError = "DENY".equalsIgnoreCase(config.getString("premium-auto-login.on-api-error", "FALLBACK_OFFLINE"));

        mojangApi.configure(
                config.getLong("premium-auto-login.cache-ttl-minutes", 30),
                config.getLong("premium-auto-login.negative-cache-ttl-minutes", 10),
                config.getInt("premium-auto-login.cache-max-entries", 10_000),
                config.getLong("premium-auto-login.api-timeout-ms", 4000)
        );

        if (enabled && nettyHandshakeEnabled && !Bukkit.getOnlineMode()) {
            boolean injected = nettyInjector.inject();
            if (injected) {
                logger.info("Hybrid Mojang Netty encryption handshake enabled for premium auto-login.");
            }
        } else {
            nettyInjector.shutdown();
        }
    }

    public void shutdown() {
        nettyInjector.shutdown();
        pendingVerifiedHandshakes.clear();
        verifiedJoinSessions.clear();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isNettyHandshakeEnabled() {
        return nettyHandshakeEnabled;
    }

    public boolean isDenyOnApiError() {
        return denyOnApiError;
    }

    public void registerVerifiedHandshake(VerifiedPremiumSession session) {
        String key = buildHandshakeKey(session.canonicalUsername(), session.remoteAddress());
        pendingVerifiedHandshakes.put(key, session);
    }

    public Optional<VerifiedPremiumSession> consumeVerifiedJoinSession(UUID playerUuid) {
        return Optional.ofNullable(verifiedJoinSessions.remove(playerUuid));
    }

    /**
     * Evaluates pre-login authenticity during {@link AsyncPlayerPreLoginEvent}.
     */
    public void handleAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enabled) {
            return;
        }

        // If the server itself runs with online-mode=true, Mojang session check already passed natively
        if (Bukkit.getOnlineMode()) {
            verifiedJoinSessions.put(event.getUniqueId(), new VerifiedPremiumSession(
                    event.getUniqueId(),
                    event.getName(),
                    java.util.List.of(),
                    event.getAddress(),
                    Instant.now()
            ));
            return;
        }

        String handshakeKey = buildHandshakeKey(event.getName(), event.getAddress());
        VerifiedPremiumSession verified = pendingVerifiedHandshakes.remove(handshakeKey);
        if (verified != null && !isHandshakeExpired(verified)) {
            UUID finalUuid = event.getUniqueId();
            if (tryApplyPaperProfile(event, verified) && applyMojangUuid) {
                finalUuid = verified.mojangUuid();
            }
            verifiedJoinSessions.put(finalUuid, verified);
            return;
        }

        // Not verified by Netty encryption handshake: check if username is owned by a Mojang account
        MojangApiClient.MojangLookupResult lookup = mojangApi.lookupUsername(event.getName()).join();
        switch (lookup.status()) {
            case OFFLINE_AVAILABLE -> {
                // Non-premium name: allow entry into standard Limbo registration/login flow
            }
            case ERROR -> {
                if (denyOnApiError) {
                    event.disallow(
                            AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            messageService.toLegacyKey("premium.api-error-kick")
                    );
                }
            }
            case PREMIUM -> {
                // Accept if running behind a modern proxy that already forwarded signed Mojang textures
                if (hasPaperSignedTextures(event)) {
                    verifiedJoinSessions.put(event.getUniqueId(), new VerifiedPremiumSession(
                            lookup.uuid(),
                            lookup.canonicalName(),
                            java.util.List.of(),
                            event.getAddress(),
                            Instant.now()
                    ));
                    return;
                }

                if (strictRejectUnverifiedPremium) {
                    event.disallow(
                            AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            messageService.toLegacyKey("premium.spoof-kick")
                    );
                }
            }
        }
    }

    public String getSpoofKickPlainMessage() {
        return PlainTextComponentSerializer.plainText().serialize(messageService.deserializeKey("premium.spoof-kick"));
    }

    public String getApiErrorKickReason() {
        return PlainTextComponentSerializer.plainText().serialize(messageService.deserializeKey("premium.api-error-kick"));
    }

    private boolean tryApplyPaperProfile(AsyncPlayerPreLoginEvent event, VerifiedPremiumSession session) {
        if (!applyMojangUuid && !applyMojangSkin) {
            return false;
        }
        try {
            return PaperProfileHelper.applyVerifiedProfile(event, session, applyMojangUuid, applyMojangSkin);
        } catch (NoClassDefFoundError | NoSuchMethodError ex) {
            // Spigot fallback without Paper PlayerProfile API
            return false;
        }
    }

    private boolean hasPaperSignedTextures(AsyncPlayerPreLoginEvent event) {
        try {
            return PaperProfileHelper.hasSignedTextures(event);
        } catch (NoClassDefFoundError | NoSuchMethodError ex) {
            return false;
        }
    }

    private static boolean isHandshakeExpired(VerifiedPremiumSession session) {
        return Instant.now().toEpochMilli() - session.verifiedAt().toEpochMilli() > HANDSHAKE_TOKEN_TTL_MS;
    }

    private static String buildHandshakeKey(String username, InetAddress address) {
        String ip = address != null ? address.getHostAddress() : "unknown";
        return username.toLowerCase(Locale.ROOT) + "|" + ip;
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA KeyPairGenerator unavailable", ex);
        }
    }
}
