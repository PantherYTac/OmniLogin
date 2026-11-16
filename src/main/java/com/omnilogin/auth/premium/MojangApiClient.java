package com.omnilogin.auth.premium;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Non-blocking Mojang Profile & Session API client with bounded TTL caching.
 */
public final class MojangApiClient {

    public enum LookupStatus {
        PREMIUM,
        OFFLINE_AVAILABLE,
        ERROR
    }

    public record MojangLookupResult(LookupStatus status, UUID uuid, String canonicalName) {
        public static MojangLookupResult premium(UUID uuid, String canonicalName) {
            return new MojangLookupResult(LookupStatus.PREMIUM, uuid, canonicalName);
        }

        public static MojangLookupResult offlineAvailable() {
            return new MojangLookupResult(LookupStatus.OFFLINE_AVAILABLE, null, null);
        }

        public static MojangLookupResult error() {
            return new MojangLookupResult(LookupStatus.ERROR, null, null);
        }
    }

    private record CacheEntry(MojangLookupResult result, long expiresAtMillis) {
        boolean isExpired(long now) {
            return now >= expiresAtMillis;
        }
    }

    private static final String PROFILE_ENDPOINT = "https://api.mojang.com/users/profiles/minecraft/";
    private static final String SESSION_HAS_JOINED_ENDPOINT = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

    private final Logger logger;
    private final HttpClient httpClient;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    private volatile Duration apiTimeout = Duration.ofMillis(4000);
    private volatile long positiveCacheTtlMs = Duration.ofMinutes(30).toMillis();
    private volatile long negativeCacheTtlMs = Duration.ofMinutes(10).toMillis();
    private volatile int maxCacheEntries = 10_000;

    public MojangApiClient(Logger logger) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(4000))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public void configure(long positiveTtlMinutes, long negativeTtlMinutes, int maxEntries, long timeoutMs) {
        this.positiveCacheTtlMs = Math.max(1000L, Duration.ofMinutes(Math.max(1, positiveTtlMinutes)).toMillis());
        this.negativeCacheTtlMs = Math.max(1000L, Duration.ofMinutes(Math.max(1, negativeTtlMinutes)).toMillis());
        this.maxCacheEntries = Math.max(100, maxEntries);
        this.apiTimeout = Duration.ofMillis(Math.max(500L, timeoutMs));
    }

    public void clearCache() {
        cache.clear();
    }

    public CompletableFuture<MojangLookupResult> lookupUsername(String username) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.completedFuture(MojangLookupResult.offlineAvailable());
        }

        String key = username.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && !cached.isExpired(now)) {
            return CompletableFuture.completedFuture(cached.result());
        }

        String encoded = URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(PROFILE_ENDPOINT + encoded))
                .timeout(apiTimeout)
                .header("Accept", "application/json")
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> {
                    int status = response.statusCode();
                    if (status == 200) {
                        JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                        UUID uuid = parseUndashedUuid(json.get("id").getAsString());
                        String canonical = json.get("name").getAsString();
                        MojangLookupResult result = MojangLookupResult.premium(uuid, canonical);
                        putCache(key, result, positiveCacheTtlMs);
                        return result;
                    }
                    if (status == 204 || status == 404) {
                        MojangLookupResult result = MojangLookupResult.offlineAvailable();
                        putCache(key, result, negativeCacheTtlMs);
                        return result;
                    }
                    logger.warning("Unexpected HTTP " + status + " from Mojang profile API for username " + username);
                    return MojangLookupResult.error();
                })
                .exceptionally(ex -> {
                    logger.log(Level.WARNING, "Failed to query Mojang profile API for " + username, ex);
                    return MojangLookupResult.error();
                });
    }

    public CompletableFuture<Optional<VerifiedPremiumSession>> verifyHasJoined(
            String username,
            String serverIdHash,
            InetAddress remoteAddress
    ) {
        String encodedUser = URLEncoder.encode(username, StandardCharsets.UTF_8);
        String encodedHash = URLEncoder.encode(serverIdHash, StandardCharsets.UTF_8);
        String uri = SESSION_HAS_JOINED_ENDPOINT + "?username=" + encodedUser + "&serverId=" + encodedHash;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(apiTimeout)
                .header("Accept", "application/json")
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> {
                    if (response.statusCode() != 200 || response.body() == null || response.body().isBlank()) {
                        return Optional.<VerifiedPremiumSession>empty();
                    }
                    JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                    UUID uuid = parseUndashedUuid(json.get("id").getAsString());
                    String canonicalName = json.get("name").getAsString();

                    List<VerifiedPremiumSession.SkinProperty> properties = new ArrayList<>();
                    if (json.has("properties") && json.get("properties").isJsonArray()) {
                        JsonArray propArray = json.getAsJsonArray("properties");
                        for (JsonElement element : propArray) {
                            JsonObject propObj = element.getAsJsonObject();
                            String name = propObj.get("name").getAsString();
                            String value = propObj.get("value").getAsString();
                            String signature = propObj.has("signature") && !propObj.get("signature").isJsonNull()
                                    ? propObj.get("signature").getAsString()
                                    : null;
                            properties.add(new VerifiedPremiumSession.SkinProperty(name, value, signature));
                        }
                    }

                    return Optional.of(new VerifiedPremiumSession(
                            uuid,
                            canonicalName,
                            List.copyOf(properties),
                            remoteAddress,
                            Instant.now()
                    ));
                })
                .exceptionally(ex -> {
                    logger.log(Level.WARNING, "Failed Mojang session verification for " + username, ex);
                    return Optional.empty();
                });
    }

    /**
     * Computes Minecraft's signed two's-complement SHA-1 server hash used by {@code hasJoined}.
     */
    public static String computeServerHash(String serverId, SecretKey sharedSecret, PublicKey publicKey) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(serverId.getBytes(StandardCharsets.ISO_8859_1));
            sha1.update(sharedSecret.getEncoded());
            sha1.update(publicKey.getEncoded());
            return new BigInteger(sha1.digest()).toString(16);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-1 algorithm unavailable", ex);
        }
    }

    public static UUID parseUndashedUuid(String hex32) {
        if (hex32 == null || hex32.length() != 32) {
            throw new IllegalArgumentException("Invalid undashed Mojang UUID: " + hex32);
        }
        String formatted = hex32.substring(0, 8) + "-"
                + hex32.substring(8, 12) + "-"
                + hex32.substring(12, 16) + "-"
                + hex32.substring(16, 20) + "-"
                + hex32.substring(20, 32);
        return UUID.fromString(formatted);
    }

    private void putCache(String key, MojangLookupResult result, long ttlMs) {
        long now = System.currentTimeMillis();
        if (cache.size() >= maxCacheEntries) {
            cache.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
            if (cache.size() >= maxCacheEntries) {
                cache.clear();
            }
        }
        cache.put(key, new CacheEntry(result, now + ttlMs));
    }
}
