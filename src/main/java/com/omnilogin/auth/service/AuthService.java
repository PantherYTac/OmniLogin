package com.omnilogin.auth.service;

import com.omnilogin.auth.OmniLogin;
import com.omnilogin.auth.config.MessageService;
import com.omnilogin.auth.limbo.LimboManager;
import com.omnilogin.auth.limbo.LimboSession;
import com.omnilogin.auth.security.PasswordHasher;
import com.omnilogin.auth.security.PasswordValidator;
import com.omnilogin.auth.storage.AccountRecord;
import com.omnilogin.auth.storage.StorageProvider;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * Shared asynchronous authentication workflow orchestrator used by chat commands
 * and the PIN-pad GUI to prevent duplicated business logic or race conditions.
 */
public final class AuthService implements AutoCloseable {

    private final OmniLogin plugin;
    private final StorageProvider storageProvider;
    private final PasswordHasher passwordHasher;
    private final PasswordValidator passwordValidator;
    private final LimboManager limboManager;
    private final MessageService messageService;
    private final ExecutorService cryptoExecutor;
    private final Set<UUID> pendingPasswordChanges = ConcurrentHashMap.newKeySet();

    private volatile int maxAccountsPerIp = 0;

    public AuthService(
            OmniLogin plugin,
            StorageProvider storageProvider,
            PasswordHasher passwordHasher,
            PasswordValidator passwordValidator,
            LimboManager limboManager,
            MessageService messageService
    ) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.storageProvider = Objects.requireNonNull(storageProvider, "storageProvider");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher");
        this.passwordValidator = Objects.requireNonNull(passwordValidator, "passwordValidator");
        this.limboManager = Objects.requireNonNull(limboManager, "limboManager");
        this.messageService = Objects.requireNonNull(messageService, "messageService");

        int threads = Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors()));
        this.cryptoExecutor = Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "OmniLogin-Crypto");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void reloadFromConfig(FileConfiguration config) {
        this.maxAccountsPerIp = Math.max(0, config.getInt("security.max-accounts-per-ip", 0));
    }

    public void register(
            Player player,
            String password,
            PasswordValidator.ValidationContext context,
            Runnable onFailureUiCallback
    ) {
        UUID uuid = player.getUniqueId();
        if (limboManager.isAuthenticated(uuid)) {
            messageService.send(player, "auth.already-authenticated");
            return;
        }

        LimboSession session = limboManager.getLimboSession(uuid).orElse(null);
        if (session == null || !session.tryBeginAuthOperation()) {
            return;
        }

        PasswordValidator.ValidationResult validation = passwordValidator.validate(password, player.getName(), context);
        if (!validation.valid()) {
            sendValidationErrors(player, validation);
            session.endAuthOperation();
            runCallback(onFailureUiCallback);
            return;
        }

        String ip = session.getIpAddress();
        storageProvider.findByUuid(uuid).thenCompose(existingOpt -> {
            if (existingOpt.isPresent()) {
                return CompletableFuture.completedFuture(RegistrationOutcome.ALREADY_REGISTERED);
            }
            CompletableFuture<Boolean> ipAllowedFuture = maxAccountsPerIp > 0
                    ? storageProvider.countAccountsByIp(ip).thenApply(count -> count < maxAccountsPerIp)
                    : CompletableFuture.completedFuture(true);

            return ipAllowedFuture.thenCompose(allowed -> {
                if (!allowed) {
                    return CompletableFuture.completedFuture(RegistrationOutcome.IP_LIMIT_REACHED);
                }
                return CompletableFuture.supplyAsync(() -> passwordHasher.hash(password), cryptoExecutor)
                        .thenCompose(hash -> {
                            Instant now = Instant.now();
                            AccountRecord record = new AccountRecord(uuid, player.getName(), hash, false, now, now, ip);
                            return storageProvider.saveAccount(record)
                                    .thenApply(ignored -> RegistrationOutcome.success(record));
                        });
            });
        }).whenComplete((outcome, ex) -> {
            if (!plugin.isEnabled()) {
                session.endAuthOperation();
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                try {
                    if (!player.isOnline() || !limboManager.isInLimbo(uuid)) {
                        return;
                    }
                    if (ex != null || outcome == null) {
                        plugin.getLogger().log(Level.SEVERE, "Registration error for " + player.getName(), ex);
                        messageService.send(player, "general.internal-error");
                        runCallback(onFailureUiCallback);
                        return;
                    }
                    switch (outcome.status()) {
                        case ALREADY_REGISTERED -> {
                            session.setAccountRegistered(true);
                            messageService.send(player, "auth.already-registered");
                            runCallback(onFailureUiCallback);
                        }
                        case IP_LIMIT_REACHED -> {
                            messageService.send(
                                    player,
                                    "auth.max-accounts-per-ip",
                                    Placeholder.unparsed("max", String.valueOf(maxAccountsPerIp))
                            );
                            runCallback(onFailureUiCallback);
                        }
                        case SUCCESS -> {
                            limboManager.authenticatePlayer(player, outcome.record());
                            messageService.send(player, "auth.register-success");
                        }
                    }
                } finally {
                    session.endAuthOperation();
                }
            });
        });
    }

    public void login(Player player, String password, Runnable onInvalidPasswordCallback) {
        UUID uuid = player.getUniqueId();
        if (limboManager.isAuthenticated(uuid)) {
            messageService.send(player, "auth.already-authenticated");
            return;
        }

        LimboSession session = limboManager.getLimboSession(uuid).orElse(null);
        if (session == null || !session.tryBeginAuthOperation()) {
            return;
        }

        String ip = session.getIpAddress();
        long lockedSeconds = limboManager.getLockoutRemainingSeconds(uuid, ip);
        if (lockedSeconds > 0L) {
            session.endAuthOperation();
            player.kickPlayer(messageService.toLegacyKey(
                    "auth.ip-locked-out",
                    Placeholder.unparsed("seconds", String.valueOf(lockedSeconds))
            ));
            return;
        }

        storageProvider.findByUuid(uuid).thenCompose(recordOpt -> {
            if (recordOpt.isEmpty()) {
                return CompletableFuture.completedFuture(LoginOutcome.NOT_REGISTERED);
            }
            AccountRecord existing = recordOpt.get();
            if (existing.passwordHash() == null || existing.passwordHash().isBlank()) {
                return CompletableFuture.completedFuture(LoginOutcome.NOT_REGISTERED);
            }

            return CompletableFuture.supplyAsync(() -> {
                if (!passwordHasher.verify(password, existing.passwordHash())) {
                    return null;
                }
                String finalHash = passwordHasher.needsRehash(existing.passwordHash())
                        ? passwordHasher.hash(password)
                        : existing.passwordHash();
                return existing.withPasswordHash(finalHash, player.getName(), ip, Instant.now());
            }, cryptoExecutor).thenCompose(updated -> {
                if (updated == null) {
                    return CompletableFuture.completedFuture(LoginOutcome.WRONG_PASSWORD);
                }
                return storageProvider.saveAccount(updated)
                        .thenApply(ignored -> LoginOutcome.success(updated));
            });
        }).whenComplete((outcome, ex) -> {
            if (!plugin.isEnabled()) {
                session.endAuthOperation();
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                try {
                    if (!player.isOnline() || !limboManager.isInLimbo(uuid)) {
                        return;
                    }
                    if (ex != null || outcome == null) {
                        plugin.getLogger().log(Level.SEVERE, "Login error for " + player.getName(), ex);
                        messageService.send(player, "general.internal-error");
                        runCallback(onInvalidPasswordCallback);
                        return;
                    }
                    switch (outcome.status()) {
                        case NOT_REGISTERED -> {
                            session.setAccountRegistered(false);
                            messageService.send(player, "auth.not-registered");
                            runCallback(onInvalidPasswordCallback);
                        }
                        case WRONG_PASSWORD -> {
                            int remaining = limboManager.recordFailedLoginAttempt(player, session);
                            if (remaining <= 0) {
                                String kick = messageService.toLegacyKey(
                                        "auth.too-many-attempts-kick",
                                        Placeholder.unparsed("seconds", String.valueOf(limboManager.getLockoutSeconds()))
                                );
                                player.kickPlayer(kick);
                            } else {
                                messageService.send(
                                        player,
                                        "auth.wrong-password",
                                        Placeholder.unparsed("attempts", String.valueOf(remaining))
                                );
                                runCallback(onInvalidPasswordCallback);
                            }
                        }
                        case SUCCESS -> {
                            limboManager.authenticatePlayer(player, outcome.record());
                            messageService.send(player, "auth.login-success");
                        }
                    }
                } finally {
                    session.endAuthOperation();
                }
            });
        });
    }

    public void changePassword(Player player, String oldPassword, String newPassword) {
        UUID uuid = player.getUniqueId();
        if (!limboManager.isAuthenticated(uuid)) {
            messageService.send(player, "auth.not-authenticated");
            return;
        }

        if (oldPassword.equals(newPassword)) {
            messageService.send(player, "auth.same-password-error");
            return;
        }

        PasswordValidator.ValidationResult validation = passwordValidator.validate(
                newPassword,
                player.getName(),
                PasswordValidator.ValidationContext.COMMAND
        );
        if (!validation.valid()) {
            sendValidationErrors(player, validation);
            return;
        }

        if (!pendingPasswordChanges.add(uuid)) {
            return;
        }

        String ip = LimboManager.extractIp(player);
        storageProvider.findByUuid(uuid).thenCompose(recordOpt -> {
            if (recordOpt.isEmpty()) {
                return CompletableFuture.completedFuture(ChangePasswordStatus.NOT_REGISTERED);
            }
            AccountRecord existing = recordOpt.get();
            if (existing.premium() && (existing.passwordHash() == null || existing.passwordHash().isBlank())) {
                return CompletableFuture.completedFuture(ChangePasswordStatus.PREMIUM_NO_LOCAL_PASS);
            }

            return CompletableFuture.supplyAsync(() -> {
                if (!passwordHasher.verify(oldPassword, existing.passwordHash())) {
                    return null;
                }
                String newHash = passwordHasher.hash(newPassword);
                return existing.withPasswordHash(newHash, player.getName(), ip, Instant.now());
            }, cryptoExecutor).thenCompose(updated -> {
                if (updated == null) {
                    return CompletableFuture.completedFuture(ChangePasswordStatus.WRONG_OLD_PASSWORD);
                }
                return storageProvider.saveAccount(updated)
                        .thenApply(ignored -> ChangePasswordStatus.SUCCESS);
            });
        }).whenComplete((status, ex) -> {
            pendingPasswordChanges.remove(uuid);
            if (!plugin.isEnabled()) {
                return;
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!player.isOnline()) {
                    return;
                }
                if (ex != null || status == null) {
                    plugin.getLogger().log(Level.SEVERE, "Failed changing password for " + player.getName(), ex);
                    messageService.send(player, "general.internal-error");
                    return;
                }
                switch (status) {
                    case NOT_REGISTERED -> messageService.send(player, "auth.not-registered");
                    case PREMIUM_NO_LOCAL_PASS -> messageService.send(player, "auth.premium-cannot-changepass");
                    case WRONG_OLD_PASSWORD -> messageService.send(player, "auth.wrong-old-password");
                    case SUCCESS -> messageService.send(player, "auth.changepass-success");
                }
            });
        });
    }

    public void sendValidationErrors(Player player, PasswordValidator.ValidationResult result) {
        messageService.send(player, "password-validation.header");
        for (PasswordValidator.ValidationFailure failure : result.failures()) {
            Component reason = messageService.deserializeKey(failure.messageKey(), failure.resolvers());
            messageService.send(
                    player,
                    "password-validation.item-format",
                    Placeholder.component("reason", reason)
            );
        }
    }

    private static void runCallback(Runnable callback) {
        if (callback != null) {
            callback.run();
        }
    }

    @Override
    public void close() {
        cryptoExecutor.shutdown();
        try {
            if (!cryptoExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cryptoExecutor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            cryptoExecutor.shutdownNow();
        }
    }

    private record RegistrationOutcome(Status status, AccountRecord record) {
        enum Status {
            SUCCESS,
            ALREADY_REGISTERED,
            IP_LIMIT_REACHED
        }

        static final RegistrationOutcome ALREADY_REGISTERED = new RegistrationOutcome(Status.ALREADY_REGISTERED, null);
        static final RegistrationOutcome IP_LIMIT_REACHED = new RegistrationOutcome(Status.IP_LIMIT_REACHED, null);

        static RegistrationOutcome success(AccountRecord record) {
            return new RegistrationOutcome(Status.SUCCESS, record);
        }
    }

    private record LoginOutcome(Status status, AccountRecord record) {
        enum Status {
            SUCCESS,
            NOT_REGISTERED,
            WRONG_PASSWORD
        }

        static final LoginOutcome NOT_REGISTERED = new LoginOutcome(Status.NOT_REGISTERED, null);
        static final LoginOutcome WRONG_PASSWORD = new LoginOutcome(Status.WRONG_PASSWORD, null);

        static LoginOutcome success(AccountRecord record) {
            return new LoginOutcome(Status.SUCCESS, record);
        }
    }

    private enum ChangePasswordStatus {
        SUCCESS,
        NOT_REGISTERED,
        PREMIUM_NO_LOCAL_PASS,
        WRONG_OLD_PASSWORD
    }
}
