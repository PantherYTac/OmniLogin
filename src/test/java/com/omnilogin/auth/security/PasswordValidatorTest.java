package com.omnilogin.auth.security;

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordValidatorTest {

    private PasswordValidator validator;

    @BeforeEach
    void setUp() {
        validator = new PasswordValidator();
    }

    @Test
    void acceptsStrongPassword() {
        var result = validator.validate("Str0ng!Pass#9", "Steve");
        assertTrue(result.valid());
        assertTrue(result.failures().isEmpty());
    }

    @Test
    void rejectsLengthViolations() {
        assertFalse(validator.validate("Ab1!", "Steve").valid());
        assertFalse(validator.validate("A1!" + "x".repeat(32), "Steve").valid());
    }

    @Test
    void rejectsUsernameContainedCaseInsensitive() {
        var result = validator.validate("MyStEvE99!", "Steve");
        assertFalse(result.valid());
        assertTrue(result.failures().stream().anyMatch(f -> f.messageKey().equals("password-validation.contains-username")));
    }

    @Test
    void rejectsEmbeddedAndConfiguredBlacklistedPasswords() {
        assertFalse(validator.validate("minecraft", "Alex").valid());
        assertFalse(validator.validate("password", "Alex").valid());
        assertFalse(validator.validate("qwerty", "Alex").valid());

        YamlConfiguration cfg = new YamlConfiguration();
        cfg.set("password-security.reject-weak-passwords", true);
        cfg.set("password-security.checks.common-blacklist.enabled", true);
        cfg.set("password-security.checks.common-blacklist.extra-passwords", java.util.List.of("CustomWeak1!"));
        validator.reloadFromConfig(cfg);

        var customRes = validator.validate("customweak1!", "Alex");
        assertFalse(customRes.valid());
        assertTrue(customRes.failures().stream().anyMatch(f -> f.messageKey().equals("password-validation.blacklisted")));
    }

    @Test
    void enforcesComplexityRequirements() {
        var noUpper = validator.validate("strong1!", "Alex");
        assertTrue(noUpper.failures().stream().anyMatch(f -> f.messageKey().equals("password-validation.missing-uppercase")));

        var noNumber = validator.validate("Strong!Pass", "Alex");
        assertTrue(noNumber.failures().stream().anyMatch(f -> f.messageKey().equals("password-validation.missing-number")));

        var noSpecial = validator.validate("Strong1Pass", "Alex");
        assertTrue(noSpecial.failures().stream().anyMatch(f -> f.messageKey().equals("password-validation.missing-special")));
    }

    @Test
    void rejectsRepetitiveAndSequentialPatterns() {
        assertTrue(validator.validate("aaaaaa", "Alex").failures().stream()
                .anyMatch(f -> f.messageKey().equals("password-validation.repetitive-pattern")));
        assertTrue(validator.validate("111111", "Alex").failures().stream()
                .anyMatch(f -> f.messageKey().equals("password-validation.repetitive-pattern")));
        assertTrue(validator.validate("Ab123456!", "Alex").failures().stream()
                .anyMatch(f -> f.messageKey().equals("password-validation.sequential-pattern")));
        assertTrue(validator.validate("Ab9876!", "Alex").failures().stream()
                .anyMatch(f -> f.messageKey().equals("password-validation.sequential-pattern")));
        assertTrue(validator.validate("Qwerty9!", "Alex").failures().stream()
                .anyMatch(f -> f.messageKey().equals("password-validation.sequential-pattern")));
    }

    @Test
    void honorsMasterRejectWeakToggleAndPinContext() {
        assertTrue(validator.validate("492817", "Alex", PasswordValidator.ValidationContext.PIN_PAD).valid());
        assertFalse(validator.validate("111111", "Alex", PasswordValidator.ValidationContext.PIN_PAD).valid());
        assertFalse(validator.validate("123456", "Alex", PasswordValidator.ValidationContext.PIN_PAD).valid());

        YamlConfiguration cfg = new YamlConfiguration();
        cfg.set("password-security.reject-weak-passwords", false);
        validator.reloadFromConfig(cfg);
        assertTrue(validator.validate("123456", "Alex").valid());
    }
}
