package com.omnilogin.auth.storage;

import org.bukkit.configuration.file.FileConfiguration;

import java.io.File;
import java.util.Locale;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Instantiates the configured {@link StorageProvider} backend (SQLite, MySQL, or YAML).
 */
public final class StorageFactory {

    private StorageFactory() {
    }

    public static StorageProvider create(Logger logger, File dataFolder, FileConfiguration config) {
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(dataFolder, "dataFolder");
        Objects.requireNonNull(config, "config");

        String type = config.getString("storage.type", "SQLITE").trim().toUpperCase(Locale.ROOT);
        return switch (type) {
            case "MYSQL" -> new MySqlStorageProvider(logger, new MySqlStorageProvider.MySqlSettings(
                    config.getString("storage.mysql.host", "127.0.0.1"),
                    config.getInt("storage.mysql.port", 3306),
                    config.getString("storage.mysql.database", "omnilogin"),
                    config.getString("storage.mysql.username", "root"),
                    config.getString("storage.mysql.password", ""),
                    config.getBoolean("storage.mysql.use-ssl", false),
                    config.getInt("storage.mysql.pool-size", 10),
                    config.getInt("storage.mysql.minimum-idle", 2),
                    config.getLong("storage.mysql.connection-timeout-ms", 10_000L),
                    config.getLong("storage.mysql.max-lifetime-ms", 1_800_000L),
                    config.getString("storage.mysql.table-prefix", "omnilogin_")
            ));
            case "YAML" -> {
                String fileName = config.getString("storage.yaml.file", "accounts.yml");
                yield new YamlStorageProvider(logger, new File(dataFolder, fileName));
            }
            case "SQLITE" -> {
                String fileName = config.getString("storage.sqlite.file", "omnilogin.db");
                yield new SqliteStorageProvider(logger, new File(dataFolder, fileName));
            }
            default -> {
                logger.warning("Unknown storage.type '" + type + "'; defaulting to SQLITE.");
                String fileName = config.getString("storage.sqlite.file", "omnilogin.db");
                yield new SqliteStorageProvider(logger, new File(dataFolder, fileName));
            }
        };
    }
}
