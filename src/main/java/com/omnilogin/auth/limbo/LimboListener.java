package com.omnilogin.auth.limbo;

import com.omnilogin.auth.OmniLogin;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.gui.AuthGuiManager;
import com.omnilogin.auth.gui.PinPadHolder;
import com.omnilogin.auth.premium.PremiumLoginManager;
import com.omnilogin.auth.premium.VerifiedPremiumSession;
import com.omnilogin.auth.storage.AccountRecord;
import com.omnilogin.auth.storage.StorageProvider;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.EntityTargetLivingEntityEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerArmorStandManipulateEvent;
import org.bukkit.event.player.PlayerBedEnterEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerEditBookEvent;
import org.bukkit.event.player.PlayerFishEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPortalEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

/**
 * Enforces all pre-authentication limbo restrictions and routes joining players
 * into premium auto-login, session resumption, or limbo authentication.
 */
@SuppressWarnings("deprecation")
public final class LimboListener implements Listener {

    private final OmniLogin plugin;
    private final LimboManager limboManager;
    private final PremiumLoginManager premiumLoginManager;
    private final StorageProvider storageProvider;
    private final AuthGuiManager guiManager;
    private final MessageService messageService;

    public LimboListener(
            OmniLogin plugin,
            LimboManager limboManager,
            PremiumLoginManager premiumLoginManager,
            StorageProvider storageProvider,
            AuthGuiManager guiManager,
            MessageService messageService
    ) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.limboManager = Objects.requireNonNull(limboManager, "limboManager");
        this.premiumLoginManager = Objects.requireNonNull(premiumLoginManager, "premiumLoginManager");
        this.storageProvider = Objects.requireNonNull(storageProvider, "storageProvider");
        this.guiManager = Objects.requireNonNull(guiManager, "guiManager");
        this.messageService = Objects.requireNonNull(messageService, "messageService");
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        String ip = LimboManager.extractIp(player);

        // 1. Auto-authenticate verified Mojang premium accounts immediately
        Optional<VerifiedPremiumSession> verifiedPremium = premiumLoginManager.consumeVerifiedJoinSession(uuid);
        if (verifiedPremium.isPresent()) {
            handlePremiumAutoLogin(player, ip);
            return;
        }

        // 2. Check brute-force lockout before entering limbo
        long lockoutRemaining = limboManager.getLockoutRemainingSeconds(uuid, ip);
        if (lockoutRemaining > 0L) {
            player.kickPlayer(messageService.toLegacyKey(
                    "auth.ip-locked-out",
                    Placeholder.unparsed("seconds", String.valueOf(lockoutRemaining))
            ));
            return;
        }

        // 3. Check optional IP-bound session resumption
        if (limboManager.canResumeSameIpSession(uuid, ip)) {
            storageProvider.findByUuid(uuid).whenComplete((optRecord, ex) -> {
                if (!plugin.isEnabled()) {
                    return;
                }
                Bukkit.getScheduler().runTask(plugin, () -> {
                    if (!player.isOnline()) {
                        return;
                    }
                    if (ex == null && optRecord.isPresent()) {
                        AccountRecord updated = optRecord.get().withLoginSuccess(player.getName(), ip, Instant.now());
                        storageProvider.saveAccount(updated);
                        limboManager.authenticatePlayer(player, updated);
                        messageService.send(player, "auth.session-resumed");
                    } else {
                        enterStandardLimbo(player);
                    }
                });
            });
            return;
        }

        // 4. Standard cracked / unauthenticated limbo placement
        enterStandardLimbo(player);
    }

    private void handlePremiumAutoLogin(Player player, String ip) {
        UUID uuid = player.getUniqueId();
        Instant now = Instant.now();

        // Create provisional authenticated session immediately so no limbo restrictions trigger
        AccountRecord provisional = new AccountRecord(uuid, player.getName(), null, true, now, now, ip);
        limboManager.authenticatePlayer(player, provisional);
        messageService.send(player, "premium.auto-login-success");

        storageProvider.findByUuid(uuid).thenCompose(existingOpt -> {
            AccountRecord toSave = existingOpt
                    .map(existing -> existing.withPremiumStatus(true, player.getName(), ip, now))
                    .orElse(provisional);
            return storageProvider.saveAccount(toSave);
        }).whenComplete((ignored, ex) -> {
            if (ex != null) {
                plugin.getLogger().log(Level.WARNING, "Failed to persist premium account record for " + player.getName(), ex);
            }
        });
    }

    private void enterStandardLimbo(Player player) {
        LimboSession session = limboManager.enterLimbo(player);
        UUID uuid = player.getUniqueId();

        storageProvider.findByUuid(uuid).whenComplete((recordOpt, ex) -> {
            if (!plugin.isEnabled()) {
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!player.isOnline() || !limboManager.isInLimbo(uuid)) {
                    return;
                }
                boolean registered = ex == null && recordOpt.isPresent();
                session.setAccountRegistered(registered);

                String promptKey = registered ? "limbo.login-prompt" : "limbo.register-prompt";
                messageService.send(player, promptKey, Placeholder.unparsed("seconds", String.valueOf(session.getRemainingSeconds())));

                if (guiManager.isEnabled()) {
                    guiManager.scheduleOpenForLimbo(player, registered);
                }
            });
        });
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        limboManager.handleQuit(event.getPlayer());
        guiManager.clearPendingState(event.getPlayer().getUniqueId());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (limboManager.isAuthenticated(player.getUniqueId())) {
            return;
        }
        if (!limboManager.isAllowHeadRotation()) {
            event.setCancelled(true);
            return;
        }
        Location from = event.getFrom();
        Location to = event.getTo();
        if (to == null) {
            return;
        }
        if (from.getX() != to.getX() || from.getY() != to.getY() || from.getZ() != to.getZ()) {
            Location locked = from.clone();
            locked.setYaw(to.getYaw());
            locked.setPitch(to.getPitch());
            event.setTo(locked);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        Player player = event.getPlayer();
        if (!limboManager.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
            messageService.send(player, "limbo.chat-blocked");
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlayerCommandPreprocess(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (limboManager.isAuthenticated(player.getUniqueId())) {
            return;
        }

        String raw = event.getMessage().trim();
        if (!raw.startsWith("/")) {
            event.setCancelled(true);
            return;
        }

        String withoutSlash = raw.substring(1).trim();
        String firstToken = withoutSlash.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        int colonIdx = firstToken.indexOf(':');
        String rootCommand = colonIdx >= 0 ? firstToken.substring(colonIdx + 1) : firstToken;

        if (!limboManager.getAllowedCommands().contains(rootCommand)) {
            event.setCancelled(true);
            messageService.send(player, "limbo.command-blocked");
            return;
        }

        if (guiManager.isEnabled() && guiManager.isBlockChatCommandsWhenEnabled()
                && (rootCommand.equals("login") || rootCommand.equals("l")
                || rootCommand.equals("register") || rootCommand.equals("reg"))) {
            event.setCancelled(true);
            messageService.send(player, "auth.gui-commands-disabled");
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommandSend(PlayerCommandSendEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.getCommands().removeIf(cmd -> !limboManager.getAllowedCommands().contains(cmd.toLowerCase(Locale.ROOT)));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (!(event.getWhoClicked() instanceof Player player)) {
            return;
        }
        if (limboManager.isAuthenticated(player.getUniqueId())) {
            return;
        }
        if (!(event.getInventory().getHolder() instanceof PinPadHolder)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player && !limboManager.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player
                && !limboManager.isAuthenticated(player.getUniqueId())
                && !(event.getInventory().getHolder() instanceof PinPadHolder)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onItemDrop(PlayerDropItemEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onItemPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && !limboManager.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSwapHandItems(PlayerSwapHandItemsEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEntityDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player victim && !limboManager.isAuthenticated(victim.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player attacker && !limboManager.isAuthenticated(attacker.getUniqueId())) {
            event.setCancelled(true);
            return;
        }
        if (event.getDamager() instanceof Projectile projectile
                && projectile.getShooter() instanceof Player shooter
                && !limboManager.isAuthenticated(shooter.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEntityTarget(EntityTargetLivingEntityEvent event) {
        if (event.getTarget() instanceof Player target && !limboManager.isAuthenticated(target.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onFoodLevelChange(FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player player && !limboManager.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onArmorStand(PlayerArmorStandManipulateEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBedEnter(PlayerBedEnterEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPortal(PlayerPortalEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEditBook(PlayerEditBookEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onConsume(PlayerItemConsumeEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onFish(PlayerFishEvent event) {
        if (!limboManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }
}
