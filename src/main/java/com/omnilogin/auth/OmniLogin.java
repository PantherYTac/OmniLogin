package com.omnilogin.auth;

import com.omnilogin.auth.commands.ChangePasswordCommand;
import com.omnilogin.auth.commands.LoginCommand;
import com.omnilogin.auth.commands.OmniCordCommand;
import com.omnilogin.auth.commands.RegisterCommand;
import com.omnilogin.auth.config.ConfigManager;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.gui.AuthGuiListener;
import com.omnilogin.auth.gui.AuthGuiManager;
import com.omnilogin.auth.limbo.LimboListener;
import com.omnilogin.auth.limbo.LimboManager;
import com.omnilogin.auth.limbo.LimboSession;
import com.omnilogin.auth.premium.PremiumLoginListener;
import com.omnilogin.auth.premium.PremiumLoginManager;
import com.omnilogin.auth.security.ConsoleCommandFilter;
import com.omnilogin.auth.security.PasswordHasher;
import com.omnilogin.auth.security.PasswordValidator;
import com.omnilogin.auth.service.AuthService;
import com.omnilogin.auth.storage.StorageFactory;
import com.omnilogin.auth.storage.StorageProvider;
import org.bukkit.Bukkit;
import org.bukkit.command.PluginCommand;
import org.bukkit.command.TabExecutor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.PluginManager;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.logging.Level;

/**
 * Main lifecycle entrypoint for the OmniLogin authentication plugin.
 */
public final class OmniLogin extends JavaPlugin {

    private ConfigManager configManager;
    private MessageService messageService;
    private ConsoleCommandFilter consoleCommandFilter;
    private PasswordHasher passwordHasher;
    private PasswordValidator passwordValidator;
    private StorageProvider storageProvider;
    private LimboManager limboManager;
    private PremiumLoginManager premiumLoginManager;
    private AuthService authService;
    private AuthGuiManager guiManager;

    @Override
    public void onEnable() {
        long startMillis = System.currentTimeMillis();

        this.configManager = new ConfigManager(this);
        this.configManager.loadAll();
        FileConfiguration config = configManager.getConfig();

        this.messageService = new MessageService(configManager);
        this.messageService.initialize(this);

        this.consoleCommandFilter = new ConsoleCommandFilter();
        this.consoleCommandFilter.setActive(config.getBoolean("security.mask-console-passwords", true));

        this.passwordHasher = new PasswordHasher();
        this.passwordHasher.reloadFromConfig(config);

        this.passwordValidator = new PasswordValidator();
        this.passwordValidator.reloadFromConfig(config);

        this.storageProvider = StorageFactory.create(getLogger(), getDataFolder(), config);
        try {
            this.storageProvider.initialize().join();
            getLogger().info("Initialized " + storageProvider.getTypeName() + " credential storage backend.");
        } catch (Exception ex) {
            getLogger().log(Level.SEVERE, "Failed to initialize storage backend; disabling OmniLogin!", ex);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        this.limboManager = new LimboManager(this, messageService);
        this.limboManager.reloadFromConfig(config);

        this.premiumLoginManager = new PremiumLoginManager(getLogger(), configManager, messageService);
        this.premiumLoginManager.reloadFromConfig(config);

        this.authService = new AuthService(
                this,
                storageProvider,
                passwordHasher,
                passwordValidator,
                limboManager,
                messageService
        );
        this.authService.reloadFromConfig(config);

        this.guiManager = new AuthGuiManager(
                this,
                limboManager,
                messageService,
                authService,
                passwordValidator
        );
        this.guiManager.reloadFromConfig(config, configManager.getGuis());

        registerListeners();
        registerCommands();
        secureOnlinePlayersOnReload();

        long elapsed = System.currentTimeMillis() - startMillis;
        getLogger().info("OmniLogin v" + getDescription().getVersion() + " enabled in " + elapsed + "ms.");
    }

    @Override
    public void onDisable() {
        if (premiumLoginManager != null) {
            premiumLoginManager.shutdown();
        }
        if (limboManager != null) {
            limboManager.shutdown();
        }
        if (authService != null) {
            authService.close();
        }
        if (storageProvider != null) {
            storageProvider.close();
        }
        if (consoleCommandFilter != null) {
            consoleCommandFilter.shutdown();
        }
        if (messageService != null) {
            messageService.close();
        }
    }

    public void reloadPlugin() {
        configManager.loadAll();
        FileConfiguration config = configManager.getConfig();

        consoleCommandFilter.setActive(config.getBoolean("security.mask-console-passwords", true));
        passwordHasher.reloadFromConfig(config);
        passwordValidator.reloadFromConfig(config);
        limboManager.reloadFromConfig(config);
        premiumLoginManager.reloadFromConfig(config);
        authService.reloadFromConfig(config);
        guiManager.reloadFromConfig(config, configManager.getGuis());
    }

    private void registerListeners() {
        PluginManager pm = getServer().getPluginManager();
        pm.registerEvents(new PremiumLoginListener(premiumLoginManager), this);
        pm.registerEvents(new LimboListener(
                this,
                limboManager,
                premiumLoginManager,
                storageProvider,
                guiManager,
                messageService
        ), this);
        pm.registerEvents(new AuthGuiListener(guiManager), this);
    }

    private void registerCommands() {
        bindCommand("login", new LoginCommand(authService, guiManager, messageService));
        bindCommand("register", new RegisterCommand(authService, guiManager, messageService));
        bindCommand("changepassword", new ChangePasswordCommand(authService, messageService));
        bindCommand("omnicord", new OmniCordCommand(
                this,
                storageProvider,
                limboManager,
                messageService
        ));
    }

    private void bindCommand(String name, TabExecutor executor) {
        PluginCommand command = getCommand(name);
        if (command == null) {
            getLogger().warning("Command '" + name + "' is missing from plugin.yml!");
            return;
        }
        command.setExecutor(executor);
        command.setTabCompleter(executor);
    }

    private void secureOnlinePlayersOnReload() {
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (!limboManager.isAuthenticated(player.getUniqueId())) {
                LimboSession session = limboManager.enterLimbo(player);
                storageProvider.findByUuid(player.getUniqueId()).whenComplete((opt, ex) -> {
                    if (!isEnabled()) {
                        return;
                    }
                    Bukkit.getScheduler().runTask(this, () -> {
                        if (player.isOnline() && limboManager.isInLimbo(player.getUniqueId())) {
                            session.setAccountRegistered(ex == null && opt.isPresent());
                        }
                    });
                });
            }
        }
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public MessageService getMessageService() {
        return messageService;
    }

    public StorageProvider getStorageProvider() {
        return storageProvider;
    }

    public LimboManager getLimboManager() {
        return limboManager;
    }

    public PasswordValidator getPasswordValidator() {
        return passwordValidator;
    }

    public PasswordHasher getPasswordHasher() {
        return passwordHasher;
    }

    public PremiumLoginManager getPremiumLoginManager() {
        return premiumLoginManager;
    }

    public AuthGuiManager getGuiManager() {
        return guiManager;
    }
}
