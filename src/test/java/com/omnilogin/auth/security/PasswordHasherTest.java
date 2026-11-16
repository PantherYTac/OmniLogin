package com.omnilogin.auth.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    void argon2idHashesWithUniqueSaltsAndVerifies() {
        PasswordHasher hasher = new PasswordHasher(PasswordHasher.Algorithm.ARGON2ID, 8192, 2, 1, 32, 16, 10);

        String hash1 = hasher.hash("MySecret!99");
        String hash2 = hasher.hash("MySecret!99");

        assertTrue(hash1.startsWith("$argon2id$v=19$"));
        assertNotEquals(hash1, hash2);
        assertTrue(hasher.verify("MySecret!99", hash1));
        assertTrue(hasher.verify("MySecret!99", hash2));
        assertFalse(hasher.verify("WrongPass!99", hash1));
        assertFalse(hasher.needsRehash(hash1));
    }

    @Test
    void bcryptHashesAndCrossVerifiesWhenSwitchedToArgon2() {
        PasswordHasher bcryptHasher = new PasswordHasher(PasswordHasher.Algorithm.BCRYPT, 8192, 2, 1, 32, 16, 10);
        String bcryptHash = bcryptHasher.hash("BcryptPass!42");

        assertTrue(bcryptHash.startsWith("$2b$10$"));
        assertTrue(bcryptHasher.verify("BcryptPass!42", bcryptHash));
        assertFalse(bcryptHasher.verify("OtherPass!42", bcryptHash));

        PasswordHasher argonHasher = new PasswordHasher(PasswordHasher.Algorithm.ARGON2ID, 8192, 2, 1, 32, 16, 10);
        assertTrue(argonHasher.verify("BcryptPass!42", bcryptHash));
        assertTrue(argonHasher.needsRehash(bcryptHash));
    }
}
