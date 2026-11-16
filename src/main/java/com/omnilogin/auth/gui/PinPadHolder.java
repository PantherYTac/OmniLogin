package com.omnilogin.auth.gui;

import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Custom {@link InventoryHolder} identifying an OmniLogin PIN-pad GUI instance and holding
 * the player's current masked PIN entry buffer.
 */
public final class PinPadHolder implements InventoryHolder {

    public enum Mode {
        LOGIN,
        REGISTER,
        REGISTER_CONFIRM
    }

    private final UUID playerUuid;
    private final Mode mode;
    private final String firstPin;
    private final StringBuilder pinBuffer = new StringBuilder();
    private final Map<Integer, PinAction> slotActions = new HashMap<>();
    private Inventory inventory;

    public PinPadHolder(UUID playerUuid, Mode mode, String firstPin) {
        this.playerUuid = playerUuid;
        this.mode = mode;
        this.firstPin = firstPin;
    }

    @Override
    public Inventory getInventory() {
        return inventory;
    }

    public void setInventory(Inventory inventory) {
        this.inventory = inventory;
    }

    public UUID getPlayerUuid() {
        return playerUuid;
    }

    public Mode getMode() {
        return mode;
    }

    public String getFirstPin() {
        return firstPin;
    }

    public StringBuilder getPinBuffer() {
        return pinBuffer;
    }

    public void putAction(int slot, PinAction action) {
        slotActions.put(slot, action);
    }

    public PinAction getAction(int slot) {
        return slotActions.getOrDefault(slot, PinAction.NONE);
    }

    public Map<Integer, PinAction> getSlotActions() {
        return Collections.unmodifiableMap(slotActions);
    }
}
