package com.omnilogin.auth.storage;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Asynchronous credential storage contract implemented by SQLite, MySQL, and YAML backends.
 */
public interface StorageProvider extends AutoCloseable {

    CompletableFuture<Void> initialize();

    CompletableFuture<Optional<AccountRecord>> findByUuid(UUID uuid);

    CompletableFuture<Optional<AccountRecord>> findByUsername(String username);

    CompletableFuture<Void> saveAccount(AccountRecord record);

    CompletableFuture<Boolean> deleteAccount(UUID uuid);

    CompletableFuture<Integer> countAccountsByIp(String ipAddress);

    CompletableFuture<List<AccountRecord>> listAllAccounts();

    String getTypeName();

    @Override
    void close();
}
