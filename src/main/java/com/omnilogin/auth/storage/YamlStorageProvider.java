package com.omnilogin.auth.storage;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread-safe asynchronous YAML file storage provider for single-server setups.
 */
public final class YamlStorageProvider implements StorageProvider {

    private final Logger logger;
    private final File storageFile;
    private final ExecutorService ioExecutor;
    private final Map<UUID, AccountRecord> cacheByUuid = new ConcurrentHashMap<>();
    private final Map<String, UUID> uuidByUsernameLower = new ConcurrentHashMap<>();

    public YamlStorageProvider(Logger logger, File storageFile) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.storageFile = Objects.requireNonNull(storageFile, "storageFile");
        this.ioExecutor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "OmniLogin-YAML-IO");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public CompletableFuture<Void> initialize() {
        return CompletableFuture.runAsync(() -> {
            File parent = storageFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            cacheByUuid.clear();
            uuidByUsernameLower.clear();

            if (!storageFile.exists()) {
                persistYaml();
                return;
            }

            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(storageFile);
            for (String key : yaml.getKeys(false)) {
                ConfigurationSection section = yaml.getConfigurationSection(key);
                if (section == null) {
                    continue;
                }
                try {
                    UUID uuid = UUID.fromString(key);
                    String username = section.getString("username", "Unknown");
                    String passwordHash = section.getString("password_hash");
                    boolean premium = section.getBoolean("is_premium", false);
                    String regRaw = section.getString("registered_at");
                    Instant registeredAt = regRaw != null && !regRaw.isBlank()
                            ? Instant.parse(regRaw)
                            : Instant.now();
                    String loginRaw = section.getString("last_login_at");
                    Instant lastLoginAt = loginRaw != null && !loginRaw.isBlank()
                            ? Instant.parse(loginRaw)
                            : null;
                    String lastIp = section.getString("last_ip", "unknown");

                    AccountRecord record = new AccountRecord(uuid, username, passwordHash, premium, registeredAt, lastLoginAt, lastIp);
                    cacheByUuid.put(uuid, record);
                    uuidByUsernameLower.put(username.toLowerCase(Locale.ROOT), uuid);
                } catch (IllegalArgumentException ex) {
                    logger.log(Level.WARNING, "Skipping malformed YAML account entry: " + key, ex);
                }
            }
        }, ioExecutor);
    }

    @Override
    public CompletableFuture<Optional<AccountRecord>> findByUuid(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        return CompletableFuture.supplyAsync(() -> Optional.ofNullable(cacheByUuid.get(uuid)), ioExecutor);
    }

    @Override
    public CompletableFuture<Optional<AccountRecord>> findByUsername(String username) {
        Objects.requireNonNull(username, "username");
        return CompletableFuture.supplyAsync(() -> {
            UUID uuid = uuidByUsernameLower.get(username.toLowerCase(Locale.ROOT));
            return uuid != null ? Optional.ofNullable(cacheByUuid.get(uuid)) : Optional.empty();
        }, ioExecutor);
    }

    @Override
    public CompletableFuture<Void> saveAccount(AccountRecord record) {
        Objects.requireNonNull(record, "record");
        return CompletableFuture.runAsync(() -> {
            AccountRecord previous = cacheByUuid.put(record.uuid(), record);
            if (previous != null && !previous.username().equalsIgnoreCase(record.username())) {
                uuidByUsernameLower.remove(previous.username().toLowerCase(Locale.ROOT));
            }
            uuidByUsernameLower.put(record.username().toLowerCase(Locale.ROOT), record.uuid());
            persistYaml();
        }, ioExecutor);
    }

    @Override
    public CompletableFuture<Boolean> deleteAccount(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        return CompletableFuture.supplyAsync(() -> {
            AccountRecord removed = cacheByUuid.remove(uuid);
            if (removed == null) {
                return false;
            }
            uuidByUsernameLower.remove(removed.username().toLowerCase(Locale.ROOT));
            persistYaml();
            return true;
        }, ioExecutor);
    }

    @Override
    public CompletableFuture<Integer> countAccountsByIp(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return CompletableFuture.completedFuture(0);
        }
        return CompletableFuture.supplyAsync(() -> {
            int count = 0;
            for (AccountRecord record : cacheByUuid.values()) {
                if (!record.premium() && ipAddress.equals(record.lastIp())) {
                    count++;
                }
            }
            return count;
        }, ioExecutor);
    }

    @Override
    public CompletableFuture<List<AccountRecord>> listAllAccounts() {
        return CompletableFuture.supplyAsync(() -> new ArrayList<>(cacheByUuid.values()), ioExecutor);
    }

    @Override
    public String getTypeName() {
        return "YAML";
    }

    @Override
    public void close() {
        ioExecutor.shutdown();
        try {
            if (!ioExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                ioExecutor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            ioExecutor.shutdownNow();
        }
    }

    private void persistYaml() {
        YamlConfiguration yaml = new YamlConfiguration();
        for (AccountRecord record : cacheByUuid.values()) {
            ConfigurationSection section = yaml.createSection(record.uuid().toString());
            section.set("username", record.username());
            section.set("password_hash", record.passwordHash());
            section.set("is_premium", record.premium());
            section.set("registered_at", record.registeredAt().toString());
            section.set("last_login_at", record.lastLoginAt() != null ? record.lastLoginAt().toString() : null);
            section.set("last_ip", record.lastIp());
        }
        try {
            yaml.save(storageFile);
        } catch (IOException ex) {
            throw new CompletionException("Failed to save YAML accounts file", ex);
        }
    }
}
