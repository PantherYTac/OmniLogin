package com.omnilogin.auth.gui;

import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryDragEvent;

import java.util.Objects;

/**
 * Intercepts all click, drag, shift-click, hotbar-swap, and close events for {@link PinPadHolder}.
 */
public final class AuthGuiListener implements Listener {

    private final AuthGuiManager guiManager;

    public AuthGuiListener(AuthGuiManager guiManager) {
        this.guiManager = Objects.requireNonNull(guiManager, "guiManager");
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryClick(InventoryClickEvent event) {
        if (!(event.getInventory().getHolder() instanceof PinPadHolder holder)) {
            return;
        }
        // Strictly block all item movement, shift-clicks, number-key hotbar swaps, and offhand swaps
        event.setCancelled(true);
        event.setResult(Event.Result.DENY);

        if (!(event.getWhoClicked() instanceof Player player)) {
            return;
        }
        if (!player.getUniqueId().equals(holder.getPlayerUuid())) {
            return;
        }
        if (event.getClickedInventory() == null || !event.getClickedInventory().equals(event.getInventory())) {
            return;
        }
        guiManager.getPinPadGui().handleClick(player, holder, event.getRawSlot());
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getInventory().getHolder() instanceof PinPadHolder) {
            event.setCancelled(true);
            event.setResult(Event.Result.DENY);
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onInventoryClose(InventoryCloseEvent event) {
        if (event.getInventory().getHolder() instanceof PinPadHolder holder
                && event.getPlayer() instanceof Player player
                && player.getUniqueId().equals(holder.getPlayerUuid())) {
            guiManager.handleGuiClosed(player, holder);
        }
    }
}
