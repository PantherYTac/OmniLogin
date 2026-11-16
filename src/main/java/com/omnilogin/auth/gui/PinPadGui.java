package com.omnilogin.auth.gui;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.security.PasswordValidator;
import com.omnilogin.auth.service.AuthService;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.Sound;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemFlag;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.inventory.meta.SkullMeta;
import org.bukkit.profile.PlayerProfile;
import org.bukkit.profile.PlayerTextures;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Renders and handles interactions for the chest-based 0-9 virtual PIN-pad GUI.
 */
public final class PinPadGui {

    public enum RenderMode {
        STAINED_GLASS,
        PLAYER_HEAD
    }

    private final MessageService messageService;
    private final AuthService authService;
    private final PasswordValidator passwordValidator;
    private final AuthGuiManager guiManager;
    private final Map<String, URL> decodedTextureUrls = new ConcurrentHashMap<>();

    private volatile int size = 45;
    private volatile String loginTitle = "<aqua>Enter PIN</aqua>";
    private volatile String registerTitle = "<aqua>Create PIN</aqua>";
    private volatile String registerConfirmTitle = "<aqua>Confirm PIN</aqua>";
    private volatile RenderMode renderMode = RenderMode.STAINED_GLASS;

    private volatile Sound digitSound = Sound.UI_BUTTON_CLICK;
    private volatile Sound backspaceSound = Sound.BLOCK_NOTE_BLOCK_BASS;
    private volatile Sound clearSound = Sound.ITEM_SHIELD_BREAK;
    private volatile Sound submitSound = Sound.ENTITY_EXPERIENCE_ORB_PICKUP;
    private volatile Sound errorSound = Sound.ENTITY_VILLAGER_NO;

    private volatile Material fillerMaterial = Material.BLACK_STAINED_GLASS_PANE;
    private volatile String fillerName = " ";

    private volatile int displaySlot = 4;
    private volatile Material displayMaterial = Material.NETHER_STAR;
    private volatile String displayName = "<aqua><bold>Entered PIN</bold></aqua>";
    private volatile List<String> displayLore = List.of("<gray>Digits:</gray> <white><masked_pin></white>");

    private volatile int clearSlot = 38;
    private volatile int backspaceSlot = 39;
    private volatile int submitSlot = 42;
    private final int[] digitSlots = new int[]{40, 12, 13, 14, 21, 22, 23, 30, 31, 32};

    private volatile Material digitGlassMaterial = Material.LIGHT_BLUE_STAINED_GLASS_PANE;
    private volatile String digitNameFormat = "<aqua><bold> [ <digit> ] </bold></aqua>";
    private volatile List<String> digitLore = List.of("<gray>Click to append <white><digit></white></gray>");
    private final Map<Integer, String> headTextures = new ConcurrentHashMap<>();

    private volatile Material clearMaterial = Material.RED_STAINED_GLASS_PANE;
    private volatile String clearName = "<red><bold>Clear</bold></red>";
    private volatile List<String> clearLore = List.of("<gray>Reset all entered digits</gray>");

    private volatile Material backspaceMaterial = Material.ORANGE_STAINED_GLASS_PANE;
    private volatile String backspaceName = "<gold><bold>Backspace</bold></gold>";
    private volatile List<String> backspaceLore = List.of("<gray>Remove the last digit</gray>");

    private volatile Material submitMaterial = Material.LIME_STAINED_GLASS_PANE;
    private volatile String submitName = "<green><bold>Submit</bold></green>";
    private volatile List<String> submitLore = List.of("<gray>Submit your PIN</gray>");

    private volatile boolean confirmOnRegister = true;
    private volatile int minPinLength = 4;
    private volatile int maxPinLength = 12;
    private volatile boolean randomizeDigits = false;

    public PinPadGui(
            MessageService messageService,
            AuthService authService,
            PasswordValidator passwordValidator,
            AuthGuiManager guiManager
    ) {
        this.messageService = Objects.requireNonNull(messageService, "messageService");
        this.authService = Objects.requireNonNull(authService, "authService");
        this.passwordValidator = Objects.requireNonNull(passwordValidator, "passwordValidator");
        this.guiManager = Objects.requireNonNull(guiManager, "guiManager");
    }

    public void reloadFromConfig(FileConfiguration config, FileConfiguration guis) {
        this.confirmOnRegister = config.getBoolean("gui-auth.confirm-pin-on-register", true);
        this.minPinLength = Math.max(1, config.getInt("gui-auth.min-pin-length", 4));
        this.maxPinLength = Math.max(minPinLength, Math.min(32, config.getInt("gui-auth.max-pin-length", 12)));
        this.randomizeDigits = config.getBoolean("gui-auth.randomize-digits", false);

        int rawSize = guis.getInt("pin-pad.size", 45);
        int clampedSize = Math.max(27, Math.min(54, ((rawSize + 8) / 9) * 9));
        this.size = clampedSize;

        this.loginTitle = guis.getString("pin-pad.titles.login", this.loginTitle);
        this.registerTitle = guis.getString("pin-pad.titles.register", this.registerTitle);
        this.registerConfirmTitle = guis.getString("pin-pad.titles.register-confirm", this.registerConfirmTitle);

        String modeStr = guis.getString("pin-pad.render-mode", "STAINED_GLASS").trim().toUpperCase(Locale.ROOT);
        this.renderMode = "PLAYER_HEAD".equals(modeStr) ? RenderMode.PLAYER_HEAD : RenderMode.STAINED_GLASS;

        this.digitSound = parseSound(guis.getString("pin-pad.sounds.digit"), Sound.UI_BUTTON_CLICK);
        this.backspaceSound = parseSound(guis.getString("pin-pad.sounds.backspace"), Sound.BLOCK_NOTE_BLOCK_BASS);
        this.clearSound = parseSound(guis.getString("pin-pad.sounds.clear"), Sound.ITEM_SHIELD_BREAK);
        this.submitSound = parseSound(guis.getString("pin-pad.sounds.submit"), Sound.ENTITY_EXPERIENCE_ORB_PICKUP);
        this.errorSound = parseSound(guis.getString("pin-pad.sounds.error"), Sound.ENTITY_VILLAGER_NO);

        this.fillerMaterial = parseMaterial(guis.getString("pin-pad.filler.material"), Material.BLACK_STAINED_GLASS_PANE);
        this.fillerName = guis.getString("pin-pad.filler.name", " ");

        this.displaySlot = clampSlot(guis.getInt("pin-pad.display.slot", 4), clampedSize);
        this.displayMaterial = parseMaterial(guis.getString("pin-pad.display.material"), Material.NETHER_STAR);
        this.displayName = guis.getString("pin-pad.display.name", this.displayName);
        this.displayLore = readStringList(guis, "pin-pad.display.lore", this.displayLore);

        this.clearSlot = clampSlot(guis.getInt("pin-pad.slots.clear", 38), clampedSize);
        this.backspaceSlot = clampSlot(guis.getInt("pin-pad.slots.backspace", 39), clampedSize);
        this.submitSlot = clampSlot(guis.getInt("pin-pad.slots.submit", 42), clampedSize);

        int[] defaults = {40, 12, 13, 14, 21, 22, 23, 30, 31, 32};
        for (int digit = 0; digit <= 9; digit++) {
            digitSlots[digit] = clampSlot(guis.getInt("pin-pad.slots.digit-" + digit, defaults[digit]), clampedSize);
            String texture = guis.getString("pin-pad.digits.head-textures." + digit, "");
            if (!texture.isBlank()) {
                headTextures.put(digit, texture);
            }
        }

        this.digitGlassMaterial = parseMaterial(guis.getString("pin-pad.digits.glass-material"), Material.LIGHT_BLUE_STAINED_GLASS_PANE);
        this.digitNameFormat = guis.getString("pin-pad.digits.name-format", this.digitNameFormat);
        this.digitLore = readStringList(guis, "pin-pad.digits.lore", this.digitLore);

        this.clearMaterial = parseMaterial(guis.getString("pin-pad.actions.clear.material"), Material.RED_STAINED_GLASS_PANE);
        this.clearName = guis.getString("pin-pad.actions.clear.name", this.clearName);
        this.clearLore = readStringList(guis, "pin-pad.actions.clear.lore", this.clearLore);

        this.backspaceMaterial = parseMaterial(guis.getString("pin-pad.actions.backspace.material"), Material.ORANGE_STAINED_GLASS_PANE);
        this.backspaceName = guis.getString("pin-pad.actions.backspace.name", this.backspaceName);
        this.backspaceLore = readStringList(guis, "pin-pad.actions.backspace.lore", this.backspaceLore);

        this.submitMaterial = parseMaterial(guis.getString("pin-pad.actions.submit.material"), Material.LIME_STAINED_GLASS_PANE);
        this.submitName = guis.getString("pin-pad.actions.submit.name", this.submitName);
        this.submitLore = readStringList(guis, "pin-pad.actions.submit.lore", this.submitLore);
    }

    public void open(Player player, PinPadHolder.Mode mode, String firstPin) {
        String titleTemplate = switch (mode) {
            case LOGIN -> loginTitle;
            case REGISTER -> registerTitle;
            case REGISTER_CONFIRM -> registerConfirmTitle;
        };
        String legacyTitle = messageService.toLegacy(titleTemplate);
        PinPadHolder holder = new PinPadHolder(player.getUniqueId(), mode, firstPin);
        Inventory inventory = Bukkit.createInventory(holder, size, legacyTitle);
        holder.setInventory(inventory);

        populateInventory(inventory, holder);

        guiManager.markIntentionalTransition(player.getUniqueId());
        player.openInventory(inventory);
    }

    private void populateInventory(Inventory inventory, PinPadHolder holder) {
        ItemStack filler = createSimpleItem(fillerMaterial, fillerName, List.of());
        for (int slot = 0; slot < inventory.getSize(); slot++) {
            inventory.setItem(slot, filler);
            holder.putAction(slot, PinAction.NONE);
        }

        List<Integer> slotOrder = new ArrayList<>(10);
        for (int digit = 0; digit <= 9; digit++) {
            slotOrder.add(digitSlots[digit]);
        }
        if (randomizeDigits) {
            Collections.shuffle(slotOrder);
        }

        for (int digit = 0; digit <= 9; digit++) {
            int slot = slotOrder.get(digit);
            inventory.setItem(slot, createDigitItem(digit));
            holder.putAction(slot, PinAction.ofDigit(digit));
        }

        inventory.setItem(clearSlot, createSimpleItem(clearMaterial, clearName, clearLore));
        holder.putAction(clearSlot, PinAction.CLEAR);

        inventory.setItem(backspaceSlot, createSimpleItem(backspaceMaterial, backspaceName, backspaceLore));
        holder.putAction(backspaceSlot, PinAction.BACKSPACE);

        inventory.setItem(submitSlot, createSimpleItem(submitMaterial, submitName, submitLore));
        holder.putAction(submitSlot, PinAction.SUBMIT);

        refreshDisplayItem(holder);
    }

    public void handleClick(Player player, PinPadHolder holder, int rawSlot) {
        if (rawSlot < 0 || rawSlot >= holder.getInventory().getSize()) {
            return;
        }
        PinAction action = holder.getAction(rawSlot);
        switch (action.type()) {
            case DIGIT -> appendDigit(player, holder, action.digit());
            case BACKSPACE -> removeLastDigit(player, holder);
            case CLEAR -> clearPin(player, holder);
            case SUBMIT -> submitPin(player, holder);
            case NONE -> {
            }
        }
    }

    private void appendDigit(Player player, PinPadHolder holder, int digit) {
        StringBuilder buffer = holder.getPinBuffer();
        if (buffer.length() >= maxPinLength) {
            playSound(player, errorSound);
            messageService.send(
                    player,
                    "gui.pin-too-long",
                    Placeholder.unparsed("max", String.valueOf(maxPinLength))
            );
            return;
        }
        buffer.append(digit);
        playSound(player, digitSound);
        refreshDisplayItem(holder);
    }

    private void removeLastDigit(Player player, PinPadHolder holder) {
        StringBuilder buffer = holder.getPinBuffer();
        if (!buffer.isEmpty()) {
            buffer.deleteCharAt(buffer.length() - 1);
            playSound(player, backspaceSound);
            refreshDisplayItem(holder);
        }
    }

    private void clearPin(Player player, PinPadHolder holder) {
        if (!holder.getPinBuffer().isEmpty()) {
            holder.getPinBuffer().setLength(0);
            refreshDisplayItem(holder);
        }
        playSound(player, clearSound);
    }

    private void submitPin(Player player, PinPadHolder holder) {
        String pin = holder.getPinBuffer().toString();
        if (pin.length() < minPinLength) {
            playSound(player, errorSound);
            messageService.send(
                    player,
                    "gui.pin-too-short",
                    Placeholder.unparsed("min", String.valueOf(minPinLength))
            );
            return;
        }

        switch (holder.getMode()) {
            case LOGIN -> {
                playSound(player, submitSound);
                authService.login(player, pin, () -> {
                    if (player.isOnline()) {
                        playSound(player, errorSound);
                        holder.getPinBuffer().setLength(0);
                        refreshDisplayItem(holder);
                    }
                });
            }
            case REGISTER -> {
                PasswordValidator.ValidationResult validation = passwordValidator.validate(
                        pin,
                        player.getName(),
                        PasswordValidator.ValidationContext.PIN_PAD
                );
                if (!validation.valid()) {
                    playSound(player, errorSound);
                    authService.sendValidationErrors(player, validation);
                    holder.getPinBuffer().setLength(0);
                    refreshDisplayItem(holder);
                    return;
                }
                playSound(player, submitSound);
                if (confirmOnRegister) {
                    messageService.send(player, "gui.pin-confirm-step");
                    open(player, PinPadHolder.Mode.REGISTER_CONFIRM, pin);
                } else {
                    authService.register(player, pin, PasswordValidator.ValidationContext.PIN_PAD, () -> {
                        if (player.isOnline()) {
                            holder.getPinBuffer().setLength(0);
                            refreshDisplayItem(holder);
                        }
                    });
                }
            }
            case REGISTER_CONFIRM -> {
                if (!pin.equals(holder.getFirstPin())) {
                    playSound(player, errorSound);
                    messageService.send(player, "gui.pin-mismatch");
                    open(player, PinPadHolder.Mode.REGISTER, null);
                    return;
                }
                playSound(player, submitSound);
                authService.register(player, pin, PasswordValidator.ValidationContext.PIN_PAD, () -> {
                    if (player.isOnline()) {
                        open(player, PinPadHolder.Mode.REGISTER, null);
                    }
                });
            }
        }
    }

    private void refreshDisplayItem(PinPadHolder holder) {
        int len = holder.getPinBuffer().length();
        String masked = len == 0 ? "<i>empty</i>" : "•".repeat(len);
        String name = messageService.toLegacy(displayName);
        List<String> lore = messageService.toLegacyList(
                displayLore,
                Placeholder.parsed("masked_pin", masked),
                Placeholder.unparsed("length", String.valueOf(len)),
                Placeholder.unparsed("max", String.valueOf(maxPinLength))
        );
        ItemStack display = new ItemStack(displayMaterial);
        ItemMeta meta = display.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(name);
            meta.setLore(lore);
            meta.addItemFlags(ItemFlag.values());
            display.setItemMeta(meta);
        }
        holder.getInventory().setItem(displaySlot, display);
    }

    private ItemStack createDigitItem(int digit) {
        String digitStr = String.valueOf(digit);
        String name = messageService.toLegacy(digitNameFormat, Placeholder.unparsed("digit", digitStr));
        List<String> lore = messageService.toLegacyList(digitLore, Placeholder.unparsed("digit", digitStr));

        if (renderMode == RenderMode.PLAYER_HEAD) {
            String base64 = headTextures.get(digit);
            if (base64 != null && !base64.isBlank()) {
                ItemStack head = createHeadItem(digit, base64, name, lore);
                if (head != null) {
                    return head;
                }
            }
        }

        ItemStack glass = new ItemStack(digitGlassMaterial);
        ItemMeta meta = glass.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(name);
            meta.setLore(lore);
            meta.addItemFlags(ItemFlag.values());
            glass.setItemMeta(meta);
        }
        return glass;
    }

    private ItemStack createHeadItem(int digit, String base64, String name, List<String> lore) {
        try {
            URL skinUrl = decodedTextureUrls.computeIfAbsent(base64, this::decodeSkinUrl);
            if (skinUrl == null) {
                return null;
            }
            ItemStack head = new ItemStack(Material.PLAYER_HEAD);
            if (!(head.getItemMeta() instanceof SkullMeta skullMeta)) {
                return null;
            }
            UUID profileUuid = UUID.nameUUIDFromBytes(("OmniLoginDigit-" + digit).getBytes(StandardCharsets.UTF_8));
            PlayerProfile profile = Bukkit.createPlayerProfile(profileUuid, "Digit" + digit);
            PlayerTextures textures = profile.getTextures();
            textures.setSkin(skinUrl);
            profile.setTextures(textures);
            skullMeta.setOwnerProfile(profile);
            skullMeta.setDisplayName(name);
            skullMeta.setLore(lore);
            skullMeta.addItemFlags(ItemFlag.values());
            head.setItemMeta(skullMeta);
            return head;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private URL decodeSkinUrl(String base64) {
        try {
            String json = new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            String urlString = root.getAsJsonObject("textures")
                    .getAsJsonObject("SKIN")
                    .get("url")
                    .getAsString();
            return URI.create(urlString).toURL();
        } catch (Exception ex) {
            return null;
        }
    }

    private ItemStack createSimpleItem(Material material, String nameTemplate, List<String> loreTemplates) {
        ItemStack item = new ItemStack(material);
        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(messageService.toLegacy(nameTemplate));
            if (!loreTemplates.isEmpty()) {
                meta.setLore(messageService.toLegacyList(loreTemplates));
            }
            meta.addItemFlags(ItemFlag.values());
            item.setItemMeta(meta);
        }
        return item;
    }

    private static void playSound(Player player, Sound sound) {
        if (sound != null) {
            player.playSound(player.getLocation(), sound, 0.8f, 1.0f);
        }
    }

    private static Material parseMaterial(String name, Material fallback) {
        if (name == null || name.isBlank()) {
            return fallback;
        }
        Material mat = Material.matchMaterial(name.trim());
        return mat != null ? mat : fallback;
    }

    private static Sound parseSound(String name, Sound fallback) {
        if (name == null || name.isBlank()) {
            return fallback;
        }
        try {
            return Sound.valueOf(name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return fallback;
        }
    }

    private static List<String> readStringList(FileConfiguration config, String path, List<String> fallback) {
        List<String> list = config.getStringList(path);
        return list.isEmpty() ? fallback : list;
    }

    private static int clampSlot(int slot, int size) {
        return Math.max(0, Math.min(size - 1, slot));
    }
}
