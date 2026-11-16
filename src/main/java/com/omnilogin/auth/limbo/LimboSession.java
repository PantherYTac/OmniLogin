package com.omnilogin.auth.limbo;

import net.kyori.adventure.bossbar.BossBar;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-memory state for a single player currently awaiting authentication in limbo.
 */
public final class LimboSession {

    private final UUID playerUuid;
    private final String username;
    private final String ipAddress;
    private final Instant joinedAt;
    private final Instant expiresAt;
    private final boolean previousAllowFlight;
    private final boolean previousFlying;
    private final AtomicBoolean authInProgress = new AtomicBoolean(false);

    private volatile Boolean accountRegistered;
    private volatile int failedAttempts;
    private volatile long lastReminderEpochSec;
    private volatile BossBar bossBar;

    public LimboSession(
            UUID playerUuid,
            String username,
            String ipAddress,
            Instant joinedAt,
            Instant expiresAt,
            boolean previousAllowFlight,
            boolean previousFlying
    ) {
        this.playerUuid = playerUuid;
        this.username = username;
        this.ipAddress = ipAddress;
        this.joinedAt = joinedAt;
        this.expiresAt = expiresAt;
        this.previousAllowFlight = previousAllowFlight;
        this.previousFlying = previousFlying;
    }

    public UUID getPlayerUuid() {
        return playerUuid;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public Instant getJoinedAt() {
        return joinedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isPreviousAllowFlight() {
        return previousAllowFlight;
    }

    public boolean isPreviousFlying() {
        return previousFlying;
    }

    public boolean tryBeginAuthOperation() {
        return authInProgress.compareAndSet(false, true);
    }

    public void endAuthOperation() {
        authInProgress.set(false);
    }

    public Boolean getAccountRegistered() {
        return accountRegistered;
    }

    public void setAccountRegistered(Boolean accountRegistered) {
        this.accountRegistered = accountRegistered;
    }

    public int incrementFailedAttempts() {
        return ++failedAttempts;
    }

    public long getLastReminderEpochSec() {
        return lastReminderEpochSec;
    }

    public void setLastReminderEpochSec(long lastReminderEpochSec) {
        this.lastReminderEpochSec = lastReminderEpochSec;
    }

    public BossBar getBossBar() {
        return bossBar;
    }

    public void setBossBar(BossBar bossBar) {
        this.bossBar = bossBar;
    }

    public long getRemainingSeconds() {
        long millis = expiresAt.toEpochMilli() - System.currentTimeMillis();
        return Math.max(0L, (millis + 999L) / 1000L);
    }
}
