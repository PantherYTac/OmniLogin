package com.omnilogin.auth.config;

import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.logging.Level;

/**
 * Manages loading, defaults merging, and reloading for {@code config.yml},
 * {@code messages.yml}, and {@code guis.yml}.
 */
public final class ConfigManager {

    private final JavaPlugin plugin;
    private FileConfiguration config;
    private FileConfiguration messages;
    private FileConfiguration guis;

    public ConfigManager(JavaPlugin plugin) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
    }

    public void loadAll() {
        ensureDefaultResource("config.yml");
        ensureDefaultResource("messages.yml");
        ensureDefaultResource("guis.yml");

        plugin.reloadConfig();
        this.config = plugin.getConfig();
        applyEmbeddedDefaults(this.config, "config.yml");

        this.messages = loadYamlWithDefaults("messages.yml");
        this.guis = loadYamlWithDefaults("guis.yml");
    }

    public FileConfiguration getConfig() {
        return config;
    }

    public FileConfiguration getMessages() {
        return messages;
    }

    public FileConfiguration getGuis() {
        return guis;
    }

    private void ensureDefaultResource(String fileName) {
        File target = new File(plugin.getDataFolder(), fileName);
        if (!target.exists()) {
            plugin.saveResource(fileName, false);
        }
    }

    private FileConfiguration loadYamlWithDefaults(String fileName) {
        File file = new File(plugin.getDataFolder(), fileName);
        YamlConfiguration loaded = YamlConfiguration.loadConfiguration(file);
        applyEmbeddedDefaults(loaded, fileName);
        return loaded;
    }

    private void applyEmbeddedDefaults(FileConfiguration target, String resourceName) {
        try (InputStream stream = plugin.getResource(resourceName)) {
            if (stream == null) {
                return;
            }
            try (InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                YamlConfiguration defaults = YamlConfiguration.loadConfiguration(reader);
                target.setDefaults(defaults);
            }
        } catch (IOException ex) {
            plugin.getLogger().log(Level.WARNING, "Failed to read embedded defaults for " + resourceName, ex);
        }
    }
}
