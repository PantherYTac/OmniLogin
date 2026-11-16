package com.omnilogin.auth.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class YamlStorageProviderTest {

    @TempDir
    Path tempDir;

    @Test
    void persistsAndReloadsAccountsAcrossRestarts() {
        File yamlFile = tempDir.resolve("accounts.yml").toFile();
        UUID uuid = UUID.randomUUID();
        Instant reg = Instant.parse("2026-11-11T12:00:00Z");

        try (YamlStorageProvider writer = new YamlStorageProvider(Logger.getLogger("Test"), yamlFile)) {
            writer.initialize().join();
            writer.saveAccount(new AccountRecord(uuid, "AlexTester", "$2b$12$abc", false, reg, reg, "192.168.1.5")).join();
        }

        try (YamlStorageProvider reader = new YamlStorageProvider(Logger.getLogger("Test"), yamlFile)) {
            reader.initialize().join();
            AccountRecord loaded = reader.findByUsername("alextester").join().orElseThrow();
            assertEquals(uuid, loaded.uuid());
            assertEquals("AlexTester", loaded.username());
            assertEquals("$2b$12$abc", loaded.passwordHash());
            assertEquals("192.168.1.5", loaded.lastIp());
            assertEquals(reg, loaded.registeredAt());
        }
    }
}
