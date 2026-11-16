package com.omnilogin.auth.commands;

import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.gui.AuthGuiManager;
import com.omnilogin.auth.security.PasswordValidator;
import com.omnilogin.auth.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;

import java.util.List;
import java.util.Objects;

/**
 * Handles {@code /register <password> <confirmPassword>} (and {@code /reg}).
 */
public final class RegisterCommand implements TabExecutor {

    private final AuthService authService;
    private final AuthGuiManager guiManager;
    private final MessageService messageService;

    public RegisterCommand(AuthService authService, AuthGuiManager guiManager, MessageService messageService) {
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
        if (args.length != 2) {
            messageService.send(player, "auth.register-usage");
            return true;
        }
        if (!args[0].equals(args[1])) {
            messageService.send(player, "auth.passwords-do-not-match");
            return true;
        }
        authService.register(player, args[0], PasswordValidator.ValidationContext.COMMAND, null);
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        return List.of();
    }
}
