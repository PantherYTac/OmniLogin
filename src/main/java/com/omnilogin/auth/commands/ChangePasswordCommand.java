package com.omnilogin.auth.commands;

import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;

import java.util.List;
import java.util.Objects;

/**
 * Handles {@code /changepassword <oldPassword> <newPassword> [confirmPassword]}.
 */
public final class ChangePasswordCommand implements TabExecutor {

    private final AuthService authService;
    private final MessageService messageService;

    public ChangePasswordCommand(AuthService authService, MessageService messageService) {
        this.authService = Objects.requireNonNull(authService, "authService");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            messageService.send(sender, "general.player-only");
            return true;
        }
        if (args.length < 2 || args.length > 3) {
            messageService.send(player, "auth.changepass-usage");
            return true;
        }
        if (args.length == 3 && !args[1].equals(args[2])) {
            messageService.send(player, "auth.passwords-do-not-match");
            return true;
        }
        authService.changePassword(player, args[0], args[1]);
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        return List.of();
    }
}
