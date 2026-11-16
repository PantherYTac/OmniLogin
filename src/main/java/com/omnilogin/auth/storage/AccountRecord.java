package com.omnilogin.auth.storage;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable account credential and metadata record persisted by {@link StorageProvider}.
 */
public record AccountRecord(
        UUID uuid,
        String username,
        String passwordHash,
        boolean premium,
        Instant registeredAt,
        Instant lastLoginAt,
        String lastIp
) {
    public AccountRecord {
        Objects.requireNonNull(uuid, "uuid");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(registeredAt, "registeredAt");
        lastIp = lastIp != null ? lastIp : "unknown";
    }

    public AccountRecord withLoginSuccess(String currentUsername, String ip, Instant loginTime) {
        return new AccountRecord(uuid, currentUsername, passwordHash, premium, registeredAt, loginTime, ip);
    }

    public AccountRecord withPasswordHash(String newHash, String currentUsername, String ip, Instant now) {
        return new AccountRecord(uuid, currentUsername, newHash, premium, registeredAt, now, ip);
    }

    public AccountRecord withPremiumStatus(boolean isPremium, String currentUsername, String ip, Instant now) {
        return new AccountRecord(uuid, currentUsername, passwordHash, isPremium, registeredAt, now, ip);
    }
}
