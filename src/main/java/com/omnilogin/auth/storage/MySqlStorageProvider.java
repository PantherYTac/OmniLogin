package com.omnilogin.auth.storage;

import com.zaxxer.hikari.HikariConfig;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * HikariCP-backed MySQL storage provider with prepared statement caching.
 */
public final class MySqlStorageProvider extends SqlStorageProvider {

    public record MySqlSettings(
            String host,
            int port,
            String database,
            String username,
            String password,
            boolean useSsl,
            int poolSize,
            int minimumIdle,
            long connectionTimeoutMs,
            long maxLifetimeMs,
            String tablePrefix
    ) {
    }

    private final MySqlSettings settings;

    public MySqlStorageProvider(Logger logger, MySqlSettings settings) {
        super(logger, (settings.tablePrefix() != null ? settings.tablePrefix() : "omnilogin_") + "accounts", "OmniLogin-MySQL");
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    @Override
    protected HikariConfig buildHikariConfig() {
        HikariConfig config = new HikariConfig();
        config.setPoolName("OmniLogin-MySQL-Pool");
        config.setDriverClassName("com.mysql.cj.jdbc.Driver");
        config.setJdbcUrl(String.format(
                "jdbc:mysql://%s:%d/%s?useSSL=%s&allowPublicKeyRetrieval=true&serverTimezone=UTC&useUnicode=true&characterEncoding=utf8",
                settings.host(),
                settings.port(),
                settings.database(),
                settings.useSsl()
        ));
        config.setUsername(settings.username());
        config.setPassword(settings.password());
        config.setMaximumPoolSize(Math.max(1, settings.poolSize()));
        config.setMinimumIdle(Math.max(1, Math.min(settings.minimumIdle(), settings.poolSize())));
        config.setConnectionTimeout(Math.max(1000L, settings.connectionTimeoutMs()));
        config.setMaxLifetime(Math.max(30_000L, settings.maxLifetimeMs()));

        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        config.addDataSourceProperty("useServerPrepStmts", "true");
        return config;
    }

    @Override
    protected String getCreateTableSql() {
        return "CREATE TABLE IF NOT EXISTS " + tableName + " ("
                + "uuid VARCHAR(36) PRIMARY KEY NOT NULL, "
                + "username VARCHAR(32) NOT NULL, "
                + "username_lower VARCHAR(32) NOT NULL, "
                + "password_hash VARCHAR(255), "
                + "is_premium TINYINT(1) NOT NULL DEFAULT 0, "
                + "registered_at VARCHAR(64) NOT NULL, "
                + "last_login_at VARCHAR(64), "
                + "last_ip VARCHAR(64) NOT NULL, "
                + "INDEX idx_" + tableName + "_user_lower (username_lower)"
                + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    }

    @Override
    protected String getCreateIndexSql() {
        return "";
    }

    @Override
    protected String getUpsertSql() {
        return "INSERT INTO " + tableName + " "
                + "(uuid, username, username_lower, password_hash, is_premium, registered_at, last_login_at, last_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                + "ON DUPLICATE KEY UPDATE "
                + "username = VALUES(username), "
                + "username_lower = VALUES(username_lower), "
                + "password_hash = VALUES(password_hash), "
                + "is_premium = VALUES(is_premium), "
                + "registered_at = VALUES(registered_at), "
                + "last_login_at = VALUES(last_login_at), "
                + "last_ip = VALUES(last_ip)";
    }

    @Override
    public String getTypeName() {
        return "MySQL";
    }
}
