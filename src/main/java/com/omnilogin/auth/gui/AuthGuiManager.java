package com.omnilogin.auth.gui;

import com.omnilogin.auth.OmniLogin;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.limbo.LimboManager;
import com.omnilogin.auth.limbo.LimboSession;
import com.omnilogin.auth.security.PasswordValidator;
import com.omnilogin.auth.service.AuthService;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Coordinates PIN-pad GUI lifecycle, config toggles, and seamless fallback to chat commands.
 */
public final class AuthGuiManager {

    private final OmniLogin plugin;
    private final LimboManager limboManager;
    private final PinPadGui pinPadGui;
    private final Set<UUID> transitioningPlayers = ConcurrentHashMap.newKeySet();

    private volatile boolean enabled = false;
    private volatile long openDelayTicks = 2L;
    private volatile boolean reopenOnClose = false;
    private volatile boolean blockChatCommandsWhenEnabled = false;

    public AuthGuiManager(
            OmniLogin plugin,
            LimboManager limboManager,
            MessageService messageService,
            AuthService authService,
            PasswordValidator passwordValidator
    ) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.limboManager = Objects.requireNonNull(limboManager, "limboManager");
        this.pinPadGui = new PinPadGui(messageService, authService, passwordValidator, this);
    }

    public void reloadFromConfig(FileConfiguration config, FileConfiguration guis) {
        this.enabled = config.getBoolean("gui-auth.enabled", false);
        this.openDelayTicks = Math.max(1L, config.getLong("gui-auth.open-delay-ticks", 2L));
        this.reopenOnClose = config.getBoolean("gui-auth.reopen-on-close", false);
        this.blockChatCommandsWhenEnabled = config.getBoolean("gui-auth.block-chat-commands-when-enabled", false);
        this.pinPadGui.reloadFromConfig(config, guis);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isReopenOnClose() {
        return reopenOnClose;
    }

    public boolean isBlockChatCommandsWhenEnabled() {
        return blockChatCommandsWhenEnabled;
    }

    public PinPadGui getPinPadGui() {
        return pinPadGui;
    }

    public void scheduleOpenForLimbo(Player player, boolean registered) {
        if (!enabled || !plugin.isEnabled()) {
            return;
        }
        UUID uuid = player.getUniqueId();
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            if (!player.isOnline() || !limboManager.isInLimbo(uuid)) {
                return;
            }
            PinPadHolder.Mode mode = registered ? PinPadHolder.Mode.LOGIN : PinPadHolder.Mode.REGISTER;
            pinPadGui.open(player, mode, null);
        }, openDelayTicks);
    }

    public void handleGuiClosed(Player player, PinPadHolder holder) {
        UUID uuid = player.getUniqueId();
        if (transitioningPlayers.remove(uuid)) {
            return;
        }
        if (!enabled || !reopenOnClose || !plugin.isEnabled()) {
            return;
        }
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            if (!player.isOnline() || !limboManager.isInLimbo(uuid)) {
                return;
            }
            boolean registered = limboManager.getLimboSession(uuid)
                    .map(LimboSession::getAccountRegistered)
                    .orElse(holder.getMode() == PinPadHolder.Mode.LOGIN);
            pinPadGui.open(player, registered ? PinPadHolder.Mode.LOGIN : PinPadHolder.Mode.REGISTER, null);
        }, 1L);
    }

    public void markIntentionalTransition(UUID uuid) {
        transitioningPlayers.add(uuid);
        Bukkit.getScheduler().runTaskLater(plugin, () -> transitioningPlayers.remove(uuid), 2L);
    }

    public void clearPendingState(UUID uuid) {
        transitioningPlayers.remove(uuid);
    }
}
