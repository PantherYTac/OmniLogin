package com.omnilogin.auth.storage;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Shared HikariCP-backed asynchronous SQL storage engine for SQLite and MySQL backends.
 */
public abstract class SqlStorageProvider implements StorageProvider {

    protected final Logger logger;
    protected final String tableName;
    private final ExecutorService dbExecutor;
    protected HikariDataSource dataSource;

    protected SqlStorageProvider(Logger logger, String tableName, String poolThreadPrefix) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.tableName = sanitizeTableName(tableName);
        this.dbExecutor = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, poolThreadPrefix);
            thread.setDaemon(true);
            return thread;
        });
    }

    protected abstract HikariConfig buildHikariConfig();

    protected abstract String getCreateTableSql();

    protected abstract String getCreateIndexSql();

    protected abstract String getUpsertSql();

    @Override
    public CompletableFuture<Void> initialize() {
        return CompletableFuture.runAsync(() -> {
            HikariConfig hikariConfig = buildHikariConfig();
            this.dataSource = new HikariDataSource(hikariConfig);
            try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
                stmt.execute(getCreateTableSql());
                String indexSql = getCreateIndexSql();
                if (indexSql != null && !indexSql.isBlank()) {
                    try {
                        stmt.execute(indexSql);
                    } catch (SQLException ignored) {
                        // Index may already exist on MySQL versions without IF NOT EXISTS support
                    }
                }
            } catch (SQLException ex) {
                throw new CompletionException("Failed to initialize " + getTypeName() + " storage schema", ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<Optional<AccountRecord>> findByUuid(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, username, password_hash, is_premium, registered_at, last_login_at, last_ip "
                    + "FROM " + tableName + " WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapRow(rs));
                    }
                    return Optional.empty();
                }
            } catch (SQLException ex) {
                throw new CompletionException("Failed to query account by UUID " + uuid, ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<Optional<AccountRecord>> findByUsername(String username) {
        Objects.requireNonNull(username, "username");
        String lower = username.toLowerCase(Locale.ROOT);
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, username, password_hash, is_premium, registered_at, last_login_at, last_ip "
                    + "FROM " + tableName + " WHERE username_lower = ? LIMIT 1";
            try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, lower);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapRow(rs));
                    }
                    return Optional.empty();
                }
            } catch (SQLException ex) {
                throw new CompletionException("Failed to query account by username " + username, ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<Void> saveAccount(AccountRecord record) {
        Objects.requireNonNull(record, "record");
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(getUpsertSql())) {
                ps.setString(1, record.uuid().toString());
                ps.setString(2, record.username());
                ps.setString(3, record.username().toLowerCase(Locale.ROOT));
                ps.setString(4, record.passwordHash());
                ps.setBoolean(5, record.premium());
                ps.setString(6, record.registeredAt().toString());
                ps.setString(7, record.lastLoginAt() != null ? record.lastLoginAt().toString() : null);
                ps.setString(8, record.lastIp());
                ps.executeUpdate();
            } catch (SQLException ex) {
                throw new CompletionException("Failed to save account " + record.uuid(), ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<Boolean> deleteAccount(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        return CompletableFuture.supplyAsync(() -> {
            String sql = "DELETE FROM " + tableName + " WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                return ps.executeUpdate() > 0;
            } catch (SQLException ex) {
                throw new CompletionException("Failed to delete account " + uuid, ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<Integer> countAccountsByIp(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return CompletableFuture.completedFuture(0);
        }
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT COUNT(*) FROM " + tableName + " WHERE last_ip = ? AND is_premium = ?";
            try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, ipAddress);
                ps.setBoolean(2, false);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            } catch (SQLException ex) {
                throw new CompletionException("Failed to count accounts by IP", ex);
            }
        }, dbExecutor);
    }

    @Override
    public CompletableFuture<List<AccountRecord>> listAllAccounts() {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, username, password_hash, is_premium, registered_at, last_login_at, last_ip FROM " + tableName;
            List<AccountRecord> results = new ArrayList<>();
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(mapRow(rs));
                }
                return results;
            } catch (SQLException ex) {
                throw new CompletionException("Failed to list accounts", ex);
            }
        }, dbExecutor);
    }

    @Override
    public void close() {
        dbExecutor.shutdown();
        try {
            if (!dbExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                dbExecutor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            dbExecutor.shutdownNow();
        }
        if (dataSource != null && !dataSource.isClosed()) {
            try {
                dataSource.close();
            } catch (Exception ex) {
                logger.log(Level.WARNING, "Error closing HikariDataSource for " + getTypeName(), ex);
            }
        }
    }

    private AccountRecord mapRow(ResultSet rs) throws SQLException {
        UUID uuid = UUID.fromString(rs.getString("uuid"));
        String username = rs.getString("username");
        String hash = rs.getString("password_hash");
        boolean premium = rs.getBoolean("is_premium");
        Instant registeredAt = parseInstant(rs.getString("registered_at"), Instant.now());
        Instant lastLoginAt = parseInstant(rs.getString("last_login_at"), null);
        String lastIp = rs.getString("last_ip");
        return new AccountRecord(uuid, username, hash, premium, registeredAt, lastLoginAt, lastIp);
    }

    private static Instant parseInstant(String raw, Instant fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        return Instant.parse(raw);
    }

    private static String sanitizeTableName(String raw) {
        if (raw == null || !raw.matches("[a-zA-Z0-9_]+")) {
            return "omnilogin_accounts";
        }
        return raw;
    }
}
