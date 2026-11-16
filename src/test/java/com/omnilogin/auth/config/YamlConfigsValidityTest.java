package com.omnilogin.auth.config;

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class YamlConfigsValidityTest {

    @Test
    void parsesAllBundledYamlResourcesAndVerifiesRequiredDefaults() throws Exception {
        YamlConfiguration config = loadResource("config.yml");
        assertTrue(config.getBoolean("password-security.reject-weak-passwords"));
        assertFalse(config.getBoolean("premium-auto-login.enabled"));
        assertFalse(config.getBoolean("gui-auth.enabled"));
        assertFalse(config.contains("security.plaintext-storage-unsafe"));
        assertEquals(30, config.getInt("limbo.timeout-seconds"));
        assertEquals("SQLITE", config.getString("storage.type"));

        YamlConfiguration messages = loadResource("messages.yml");
        assertNotNull(messages.getString("prefix"));
        assertNotNull(messages.getString("premium.spoof-kick"));
        assertNotNull(messages.getString("admin.inspect-card"));

        YamlConfiguration guis = loadResource("guis.yml");
        assertEquals(45, guis.getInt("pin-pad.size"));
        assertEquals(10, guis.getConfigurationSection("pin-pad.digits.head-textures").getKeys(false).size());

        YamlConfiguration pluginYml = loadResource("plugin.yml");
        assertEquals("OmniLogin", pluginYml.getString("name"));
        assertEquals("0.0.1-alpha", pluginYml.getString("version"));
        assertEquals("com.omnilogin.auth.OmniLogin", pluginYml.getString("main"));
        assertNotNull(pluginYml.getConfigurationSection("commands.login"));
        assertNotNull(pluginYml.getConfigurationSection("commands.register"));
        assertNotNull(pluginYml.getConfigurationSection("commands.changepassword"));
        assertNotNull(pluginYml.getConfigurationSection("commands.omnicord"));
        assertNotNull(pluginYml.getConfigurationSection("permissions.omnicord.admin.inspect"));
    }

    private static YamlConfiguration loadResource(String name) throws Exception {
        try (InputStream is = YamlConfigsValidityTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(is, "Missing resource: " + name);
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                YamlConfiguration yaml = new YamlConfiguration();
                yaml.load(reader);
                return yaml;
            }
        }
    }
}
