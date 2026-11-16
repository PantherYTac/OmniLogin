package com.omnilogin.auth.config;

import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.platform.bukkit.BukkitAudiences;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Renders Adventure MiniMessage templates from {@code messages.yml} across Paper,
 * Spigot, and Purpur via {@link BukkitAudiences} and legacy hex serialization.
 */
public final class MessageService {

    private static final LegacyComponentSerializer LEGACY_HEX = LegacyComponentSerializer.builder()
            .hexColors()
            .useUnusualXRepeatedCharacterHexFormat()
            .character('§')
            .build();

    private final ConfigManager configManager;
    private final MiniMessage miniMessage;
    private BukkitAudiences audiences;

    public MessageService(ConfigManager configManager) {
        this.configManager = Objects.requireNonNull(configManager, "configManager");
        this.miniMessage = MiniMessage.miniMessage();
    }

    public void initialize(JavaPlugin plugin) {
        close();
        this.audiences = BukkitAudiences.create(plugin);
    }

    public void close() {
        if (this.audiences != null) {
            this.audiences.close();
            this.audiences = null;
        }
    }

    public String getRawTemplate(String key) {
        FileConfiguration messages = configManager.getMessages();
        if (messages == null) {
            return key;
        }
        return messages.getString(key, "<red>Missing message: " + key + "</red>");
    }

    public Component deserializeKey(String key, TagResolver... resolvers) {
        return deserialize(getRawTemplate(key), resolvers);
    }

    public Component deserialize(String template, TagResolver... resolvers) {
        String prefix = configManager.getMessages() != null
                ? configManager.getMessages().getString("prefix", "")
                : "";
        TagResolver prefixResolver = Placeholder.parsed("prefix", prefix);
        TagResolver combined = TagResolver.builder()
                .resolver(prefixResolver)
                .resolvers(resolvers)
                .build();
        return miniMessage.deserialize(template, combined);
    }

    public String toLegacyKey(String key, TagResolver... resolvers) {
        return LEGACY_HEX.serialize(deserializeKey(key, resolvers));
    }

    public String toLegacy(String template, TagResolver... resolvers) {
        return LEGACY_HEX.serialize(deserialize(template, resolvers));
    }

    public List<String> toLegacyList(List<String> templates, TagResolver... resolvers) {
        return templates.stream()
                .map(line -> toLegacy(line, resolvers))
                .toList();
    }

    public void send(CommandSender sender, String key, TagResolver... resolvers) {
        sendComponent(sender, deserializeKey(key, resolvers));
    }

    public void sendRaw(CommandSender sender, String miniMessageTemplate, TagResolver... resolvers) {
        sendComponent(sender, deserialize(miniMessageTemplate, resolvers));
    }

    public void sendComponent(CommandSender sender, Component component) {
        if (audiences != null) {
            Audience audience = audiences.sender(sender);
            audience.sendMessage(component);
        } else {
            sender.sendMessage(LEGACY_HEX.serialize(component));
        }
    }

    public void sendActionBar(Player player, String key, TagResolver... resolvers) {
        Component component = deserializeKey(key, resolvers);
        if (audiences != null) {
            audiences.player(player).sendActionBar(component);
        }
    }

    public void showTitle(Player player, Component title, Component subtitle, Duration fadeIn, Duration stay, Duration fadeOut) {
        if (audiences != null) {
            Title.Times times = Title.Times.times(fadeIn, stay, fadeOut);
            audiences.player(player).showTitle(Title.title(title, subtitle, times));
        } else {
            player.sendTitle(
                    LEGACY_HEX.serialize(title),
                    LEGACY_HEX.serialize(subtitle),
                    (int) (fadeIn.toMillis() / 50L),
                    (int) (stay.toMillis() / 50L),
                    (int) (fadeOut.toMillis() / 50L)
            );
        }
    }

    public void clearTitle(Player player) {
        if (audiences != null) {
            audiences.player(player).clearTitle();
        } else {
            player.resetTitle();
        }
    }

    public void showBossBar(Player player, BossBar bossBar) {
        if (audiences != null) {
            audiences.player(player).showBossBar(bossBar);
        }
    }

    public void hideBossBar(Player player, BossBar bossBar) {
        if (audiences != null) {
            audiences.player(player).hideBossBar(bossBar);
        }
    }
}
