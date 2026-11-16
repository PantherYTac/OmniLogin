package com.omnilogin.auth.security;

import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bukkit.configuration.file.FileConfiguration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Modular, config-driven password strength validator providing toggleable checks
 * with structured MiniMessage failure reporting.
 */
public final class PasswordValidator {

    public enum ValidationContext {
        COMMAND,
        PIN_PAD
    }

    public record ValidationFailure(String messageKey, TagResolver... resolvers) {
    }

    public record ValidationResult(boolean valid, List<ValidationFailure> failures) {
        public static ValidationResult ok() {
            return new ValidationResult(true, List.of());
        }

        public static ValidationResult fail(List<ValidationFailure> failures) {
            return new ValidationResult(false, List.copyOf(failures));
        }
    }

    @FunctionalInterface
    private interface PasswordCheck {
        void check(String password, String username, ValidationContext context, List<ValidationFailure> failures);
    }

    private static final List<String> KEYBOARD_SEQUENCES = List.of(
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "qazwsxedc",
            "1qaz2wsx3edc"
    );

    private final Set<String> embeddedBlacklist;
    private volatile Settings settings;

    public record Settings(
            boolean rejectWeakPasswords,
            boolean lengthEnabled,
            int minLength,
            int maxLength,
            boolean disallowUsername,
            boolean blacklistEnabled,
            Set<String> mergedBlacklist,
            boolean requireNumber,
            boolean requireUppercase,
            boolean requireSpecialChar,
            String specialChars,
            boolean patternDetectionEnabled,
            int maxRepeatedChars,
            int minSequenceLength,
            boolean allowNumericOnlyPin
    ) {
        public static Settings defaults(Set<String> embeddedBlacklist) {
            return new Settings(
                    true,
                    true,
                    6,
                    32,
                    true,
                    true,
                    embeddedBlacklist,
                    true,
                    true,
                    true,
                    "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~",
                    true,
                    3,
                    4,
                    true
            );
        }
    }

    public PasswordValidator() {
        this.embeddedBlacklist = loadEmbeddedBlacklist();
        this.settings = Settings.defaults(embeddedBlacklist);
    }

    public void reloadFromConfig(FileConfiguration config) {
        Objects.requireNonNull(config, "config");

        boolean rejectWeak = config.getBoolean("password-security.reject-weak-passwords", true);
        boolean lengthEnabled = config.getBoolean("password-security.checks.length.enabled", true);
        int minLen = Math.max(1, config.getInt("password-security.checks.length.min", 6));
        int maxLen = Math.max(minLen, config.getInt("password-security.checks.length.max", 32));
        boolean disallowUser = config.getBoolean("password-security.checks.disallow-username.enabled", true);

        boolean blacklistEnabled = config.getBoolean("password-security.checks.common-blacklist.enabled", true);
        Set<String> merged = new HashSet<>(embeddedBlacklist);
        for (String extra : config.getStringList("password-security.checks.common-blacklist.extra-passwords")) {
            if (extra != null && !extra.isBlank()) {
                merged.add(extra.trim().toLowerCase(Locale.ROOT));
            }
        }

        boolean reqNum = config.getBoolean("password-security.checks.require-number.enabled", true);
        boolean reqUpper = config.getBoolean("password-security.checks.require-uppercase.enabled", true);
        boolean reqSpecial = config.getBoolean("password-security.checks.require-special-char.enabled", true);
        String specialChars = config.getString(
                "password-security.checks.require-special-char.special-chars",
                "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"
        );

        boolean patternEnabled = config.getBoolean("password-security.checks.pattern-detection.enabled", true);
        int maxRepeated = Math.max(2, config.getInt("password-security.checks.pattern-detection.max-repeated-chars", 3));
        int minSeqLen = Math.max(3, config.getInt("password-security.checks.pattern-detection.min-sequence-length", 4));
        boolean allowNumericPin = config.getBoolean("gui-auth.allow-numeric-only-pin", true);

        this.settings = new Settings(
                rejectWeak,
                lengthEnabled,
                minLen,
                maxLen,
                disallowUser,
                blacklistEnabled,
                Collections.unmodifiableSet(merged),
                reqNum,
                reqUpper,
                reqSpecial,
                specialChars,
                patternEnabled,
                maxRepeated,
                minSeqLen,
                allowNumericPin
        );
    }

    public ValidationResult validate(String password, String username) {
        return validate(password, username, ValidationContext.COMMAND);
    }

    public ValidationResult validate(String password, String username, ValidationContext context) {
        Settings cfg = this.settings;
        if (password == null) {
            return ValidationResult.fail(List.of(
                    new ValidationFailure("password-validation.too-short", Placeholder.unparsed("min", String.valueOf(cfg.minLength())))
            ));
        }

        if (!cfg.rejectWeakPasswords()) {
            return ValidationResult.ok();
        }

        List<PasswordCheck> checks = List.of(
                this::checkLength,
                this::checkUsernameMatch,
                this::checkCommonBlacklist,
                this::checkComplexity,
                this::checkPatterns
        );

        List<ValidationFailure> failures = new ArrayList<>();
        for (PasswordCheck check : checks) {
            check.check(password, username, context, failures);
        }

        return failures.isEmpty() ? ValidationResult.ok() : ValidationResult.fail(failures);
    }

    private void checkLength(String password, String username, ValidationContext context, List<ValidationFailure> failures) {
        Settings cfg = this.settings;
        if (!cfg.lengthEnabled()) {
            return;
        }
        int effectiveMin = (context == ValidationContext.PIN_PAD && cfg.allowNumericOnlyPin())
                ? Math.min(cfg.minLength(), 4)
                : cfg.minLength();
        if (password.length() < effectiveMin) {
            failures.add(new ValidationFailure(
                    "password-validation.too-short",
                    Placeholder.unparsed("min", String.valueOf(effectiveMin))
            ));
        }
        if (password.length() > cfg.maxLength()) {
            failures.add(new ValidationFailure(
                    "password-validation.too-long",
                    Placeholder.unparsed("max", String.valueOf(cfg.maxLength()))
            ));
        }
    }

    private void checkUsernameMatch(String password, String username, ValidationContext context, List<ValidationFailure> failures) {
        Settings cfg = this.settings;
        if (!cfg.disallowUsername() || username == null || username.isBlank()) {
            return;
        }
        String lowerPass = password.toLowerCase(Locale.ROOT);
        String lowerUser = username.toLowerCase(Locale.ROOT);
        if (lowerPass.contains(lowerUser)) {
            failures.add(new ValidationFailure("password-validation.contains-username"));
        }
    }

    private void checkCommonBlacklist(String password, String username, ValidationContext context, List<ValidationFailure> failures) {
        Settings cfg = this.settings;
        if (!cfg.blacklistEnabled()) {
            return;
        }
        String normalized = password.trim().toLowerCase(Locale.ROOT);
        if (cfg.mergedBlacklist().contains(normalized)) {
            failures.add(new ValidationFailure("password-validation.blacklisted"));
        }
    }

    private void checkComplexity(String password, String username, ValidationContext context, List<ValidationFailure> failures) {
        Settings cfg = this.settings;
        boolean skipAlphaSymbolForPin = context == ValidationContext.PIN_PAD && cfg.allowNumericOnlyPin();

        boolean hasNumber = false;
        boolean hasUppercase = false;
        boolean hasSpecial = false;

        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isDigit(c)) {
                hasNumber = true;
            } else if (Character.isUpperCase(c)) {
                hasUppercase = true;
            } else if (!Character.isLetterOrDigit(c)
                    && (cfg.specialChars().isEmpty() || cfg.specialChars().indexOf(c) >= 0)) {
                hasSpecial = true;
            }
        }

        if (cfg.requireNumber() && !hasNumber) {
            failures.add(new ValidationFailure("password-validation.missing-number"));
        }
        if (!skipAlphaSymbolForPin && cfg.requireUppercase() && !hasUppercase) {
            failures.add(new ValidationFailure("password-validation.missing-uppercase"));
        }
        if (!skipAlphaSymbolForPin && cfg.requireSpecialChar() && !hasSpecial) {
            failures.add(new ValidationFailure("password-validation.missing-special"));
        }
    }

    private void checkPatterns(String password, String username, ValidationContext context, List<ValidationFailure> failures) {
        Settings cfg = this.settings;
        if (!cfg.patternDetectionEnabled() || password.isEmpty()) {
            return;
        }

        if (hasRepetitivePattern(password, cfg.maxRepeatedChars())) {
            failures.add(new ValidationFailure("password-validation.repetitive-pattern"));
        }

        if (hasSequentialPattern(password, cfg.minSequenceLength())) {
            failures.add(new ValidationFailure("password-validation.sequential-pattern"));
        }
    }

    private static boolean hasRepetitivePattern(String password, int maxRepeatedChars) {
        int consecutive = 1;
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1)) {
                consecutive++;
                if (consecutive > maxRepeatedChars) {
                    return true;
                }
            } else {
                consecutive = 1;
            }
        }

        // Catch periodic short cycles such as "121212" or "abcabc"
        int len = password.length();
        if (len >= 4) {
            for (int period = 1; period <= Math.min(3, len / 2); period++) {
                if (len % period == 0) {
                    String unit = password.substring(0, period);
                    if (unit.repeat(len / period).equals(password)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean hasSequentialPattern(String password, int minSeqLength) {
        String lower = password.toLowerCase(Locale.ROOT);
        int ascRun = 1;
        int descRun = 1;

        for (int i = 1; i < lower.length(); i++) {
            char prev = lower.charAt(i - 1);
            char curr = lower.charAt(i);
            boolean bothDigits = Character.isDigit(prev) && Character.isDigit(curr);
            boolean bothAsciiLetters = isAsciiLetter(prev) && isAsciiLetter(curr);

            if ((bothDigits || bothAsciiLetters) && curr - prev == 1) {
                ascRun++;
                descRun = 1;
                if (ascRun >= minSeqLength) {
                    return true;
                }
            } else if ((bothDigits || bothAsciiLetters) && prev - curr == 1) {
                descRun++;
                ascRun = 1;
                if (descRun >= minSeqLength) {
                    return true;
                }
            } else {
                ascRun = 1;
                descRun = 1;
            }
        }

        // Also check common keyboard walks of length >= minSeqLength
        for (String row : KEYBOARD_SEQUENCES) {
            String reversed = new StringBuilder(row).reverse().toString();
            for (int start = 0; start + minSeqLength <= row.length(); start++) {
                String slice = row.substring(start, start + minSeqLength);
                String revSlice = reversed.substring(start, start + minSeqLength);
                if (lower.contains(slice) || lower.contains(revSlice)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isAsciiLetter(char c) {
        return c >= 'a' && c <= 'z';
    }

    private static Set<String> loadEmbeddedBlacklist() {
        Set<String> set = new HashSet<>();
        try (InputStream is = PasswordValidator.class.getClassLoader().getResourceAsStream("common-passwords.txt")) {
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String trimmed = line.trim().toLowerCase(Locale.ROOT);
                        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                            set.add(trimmed);
                        }
                    }
                }
            }
        } catch (IOException ignored) {
            // Fallback seed below ensures blacklist always has baseline entries
        }
        if (set.isEmpty()) {
            set.addAll(List.of("123456", "password", "qwerty", "minecraft", "111111", "aaaaaa", "admin", "letmein"));
        }
        return Collections.unmodifiableSet(set);
    }
}
