package com.omnilogin.auth.commands;

import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.gui.AuthGuiManager;
import com.omnilogin.auth.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;

import java.util.List;
import java.util.Objects;

/**
 * Handles {@code /login <password>} (and {@code /l}).
 */
public final class LoginCommand implements TabExecutor {

    private final AuthService authService;
    private final AuthGuiManager guiManager;
    private final MessageService messageService;

    public LoginCommand(AuthService authService, AuthGuiManager guiManager, MessageService messageService) {
        this.authService = Objects.requireNonNull(authService, "authService");
        this.guiManager = Objects.requireNonNull(guiManager, "guiManager");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            messageService.send(sender, "general.player-only");
            return true;
        }
        if (guiManager.isEnabled() && guiManager.isBlockChatCommandsWhenEnabled()) {
            messageService.send(player, "auth.gui-commands-disabled");
            return true;
        }
        if (args.length != 1) {
            messageService.send(player, "auth.login-usage");
            return true;
        }
        authService.login(player, args[0], null);
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        return List.of();
    }
}
