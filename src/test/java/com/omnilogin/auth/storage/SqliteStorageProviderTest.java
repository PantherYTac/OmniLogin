package com.omnilogin.auth.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class SqliteStorageProviderTest {

    @TempDir
    Path tempDir;

    @Test
    void performsFullCrudLifecycleAsynchronously() {
        File dbFile = tempDir.resolve("omnilogin-test.db").toFile();
        try (SqliteStorageProvider storage = new SqliteStorageProvider(Logger.getLogger("Test"), dbFile)) {
            storage.initialize().join();

            UUID uuid = UUID.randomUUID();
            Instant now = Instant.parse("2026-11-11T10:15:30Z");
            AccountRecord initial = new AccountRecord(uuid, "NotchTest", "$argon2id$hash", false, now, now, "127.0.0.1");

            storage.saveAccount(initial).join();

            AccountRecord byUuid = storage.findByUuid(uuid).join().orElseThrow();
            assertEquals("NotchTest", byUuid.username());
            assertEquals("$argon2id$hash", byUuid.passwordHash());
            assertFalse(byUuid.premium());
            assertEquals(now, byUuid.registeredAt());
            assertEquals("127.0.0.1", byUuid.lastIp());

            AccountRecord byName = storage.findByUsername("notchtest").join().orElseThrow();
            assertEquals(uuid, byName.uuid());
            assertEquals(1, storage.countAccountsByIp("127.0.0.1").join());

            AccountRecord updated = initial.withLoginSuccess("NotchTest", "10.0.0.5", now.plusSeconds(60));
            storage.saveAccount(updated).join();
            assertEquals("10.0.0.5", storage.findByUuid(uuid).join().orElseThrow().lastIp());
            assertEquals(1, storage.listAllAccounts().join().size());

            assertTrue(storage.deleteAccount(uuid).join());
            assertTrue(storage.findByUuid(uuid).join().isEmpty());
        }
    }
}
