package com.omnilogin.auth.storage;

import com.zaxxer.hikari.HikariConfig;

import java.io.File;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * HikariCP-backed SQLite implementation using WAL mode for concurrent reads and safe writes.
 */
public final class SqliteStorageProvider extends SqlStorageProvider {

    private final File databaseFile;

    public SqliteStorageProvider(Logger logger, File databaseFile) {
        super(logger, "omnilogin_accounts", "OmniLogin-SQLite");
        this.databaseFile = Objects.requireNonNull(databaseFile, "databaseFile");
    }

    @Override
    protected HikariConfig buildHikariConfig() {
        File parent = databaseFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        HikariConfig config = new HikariConfig();
        config.setPoolName("OmniLogin-SQLite-Pool");
        config.setDriverClassName("org.sqlite.JDBC");
        config.setJdbcUrl("jdbc:sqlite:" + databaseFile.getAbsolutePath());
        config.setMaximumPoolSize(1);
        config.setConnectionTimeout(10_000L);
        config.setConnectionInitSql("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;");
        return config;
    }

    @Override
    protected String getCreateTableSql() {
        return "CREATE TABLE IF NOT EXISTS " + tableName + " ("
                + "uuid VARCHAR(36) PRIMARY KEY NOT NULL, "
                + "username VARCHAR(32) NOT NULL, "
                + "username_lower VARCHAR(32) NOT NULL, "
                + "password_hash VARCHAR(255), "
                + "is_premium BOOLEAN NOT NULL DEFAULT 0, "
                + "registered_at VARCHAR(64) NOT NULL, "
                + "last_login_at VARCHAR(64), "
                + "last_ip VARCHAR(64) NOT NULL"
                + ")";
    }

    @Override
    protected String getCreateIndexSql() {
        return "CREATE INDEX IF NOT EXISTS idx_" + tableName + "_user_lower ON " + tableName + "(username_lower)";
    }

    @Override
    protected String getUpsertSql() {
        return "INSERT INTO " + tableName + " "
                + "(uuid, username, username_lower, password_hash, is_premium, registered_at, last_login_at, last_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT(uuid) DO UPDATE SET "
                + "username = excluded.username, "
                + "username_lower = excluded.username_lower, "
                + "password_hash = excluded.password_hash, "
                + "is_premium = excluded.is_premium, "
                + "registered_at = excluded.registered_at, "
                + "last_login_at = excluded.last_login_at, "
                + "last_ip = excluded.last_ip";
    }

    @Override
    public String getTypeName() {
        return "SQLite";
    }
}
