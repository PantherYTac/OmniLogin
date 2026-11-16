package com.omnilogin.auth.premium;

import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.util.Objects;

/**
 * Hooks {@link AsyncPlayerPreLoginEvent} to enforce hybrid Mojang verification and anti-spoofing.
 */
public final class PremiumLoginListener implements Listener {

    private final PremiumLoginManager premiumLoginManager;

    public PremiumLoginListener(PremiumLoginManager premiumLoginManager) {
        this.premiumLoginManager = Objects.requireNonNull(premiumLoginManager, "premiumLoginManager");
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onAsyncPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) {
            return;
        }
        premiumLoginManager.handleAsyncPreLogin(event);
    }
}
