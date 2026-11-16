package com.omnilogin.auth.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bukkit.configuration.file.FileConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/**
 * Production password hashing and verification supporting RFC 9106 Argon2id
 * (PHC format) and OpenBSD BCrypt with per-user cryptographic salts.
 */
public final class PasswordHasher {

    public enum Algorithm {
        ARGON2ID,
        BCRYPT
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder B64_NO_PAD = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    private volatile Algorithm algorithm;
    private volatile int argon2MemoryKb;
    private volatile int argon2Iterations;
    private volatile int argon2Parallelism;
    private volatile int argon2HashLength;
    private volatile int argon2SaltLength;
    private volatile int bcryptCost;

    public PasswordHasher() {
        this(Algorithm.ARGON2ID, 65536, 3, 1, 32, 16, 12);
    }

    public PasswordHasher(
            Algorithm algorithm,
            int argon2MemoryKb,
            int argon2Iterations,
            int argon2Parallelism,
            int argon2HashLength,
            int argon2SaltLength,
            int bcryptCost
    ) {
        configure(algorithm, argon2MemoryKb, argon2Iterations, argon2Parallelism, argon2HashLength, argon2SaltLength, bcryptCost);
    }

    public void reloadFromConfig(FileConfiguration config) {
        String algoStr = config.getString("security.hashing.algorithm", "ARGON2ID")
                .trim()
                .toUpperCase(Locale.ROOT);
        Algorithm parsedAlgo;
        try {
            parsedAlgo = Algorithm.valueOf(algoStr);
        } catch (IllegalArgumentException ex) {
            parsedAlgo = Algorithm.ARGON2ID;
        }

        int memoryKb = Math.max(4096, config.getInt("security.hashing.argon2.memory-kb", 65536));
        int iterations = Math.max(1, config.getInt("security.hashing.argon2.iterations", 3));
        int parallelism = Math.max(1, config.getInt("security.hashing.argon2.parallelism", 1));
        int hashLen = Math.max(16, config.getInt("security.hashing.argon2.hash-length", 32));
        int saltLen = Math.max(8, config.getInt("security.hashing.argon2.salt-length", 16));
        int cost = Math.min(31, Math.max(4, config.getInt("security.hashing.bcrypt.cost", 12)));

        configure(parsedAlgo, memoryKb, iterations, parallelism, hashLen, saltLen, cost);
    }

    public void configure(
            Algorithm algorithm,
            int argon2MemoryKb,
            int argon2Iterations,
            int argon2Parallelism,
            int argon2HashLength,
            int argon2SaltLength,
            int bcryptCost
    ) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.argon2MemoryKb = argon2MemoryKb;
        this.argon2Iterations = argon2Iterations;
        this.argon2Parallelism = argon2Parallelism;
        this.argon2HashLength = argon2HashLength;
        this.argon2SaltLength = argon2SaltLength;
        this.bcryptCost = bcryptCost;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public String hash(String password) {
        Objects.requireNonNull(password, "password");
        char[] chars = password.toCharArray();
        try {
            return switch (algorithm) {
                case ARGON2ID -> hashArgon2id(chars);
                case BCRYPT -> hashBcrypt(chars);
            };
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    public boolean verify(String password, String storedHash) {
        if (password == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        char[] chars = password.toCharArray();
        try {
            if (storedHash.startsWith("$argon2")) {
                return verifyArgon2(chars, storedHash);
            }
            if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
                return OpenBSDBCrypt.checkPassword(storedHash, chars);
            }
            return false;
        } catch (IllegalArgumentException ex) {
            return false;
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    public boolean needsRehash(String storedHash) {
        if (storedHash == null || storedHash.isBlank()) {
            return true;
        }
        return switch (algorithm) {
            case ARGON2ID -> {
                if (!storedHash.startsWith("$argon2id$v=19$")) {
                    yield true;
                }
                String expectedPrefix = String.format(
                        Locale.ROOT,
                        "$argon2id$v=19$m=%d,t=%d,p=%d$",
                        argon2MemoryKb, argon2Iterations, argon2Parallelism
                );
                yield !storedHash.startsWith(expectedPrefix);
            }
            case BCRYPT -> {
                if (!(storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$"))) {
                    yield true;
                }
                String[] parts = storedHash.split("\\$");
                if (parts.length < 4) {
                    yield true;
                }
                try {
                    int existingCost = Integer.parseInt(parts[2]);
                    yield existingCost != bcryptCost;
                } catch (NumberFormatException ex) {
                    yield true;
                }
            }
        };
    }

    private String hashArgon2id(char[] passwordChars) {
        byte[] salt = new byte[argon2SaltLength];
        SECURE_RANDOM.nextBytes(salt);
        byte[] hash = new byte[argon2HashLength];
        byte[] passwordBytes = toUtf8Bytes(passwordChars);

        try {
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withMemoryAsKB(argon2MemoryKb)
                    .withIterations(argon2Iterations)
                    .withParallelism(argon2Parallelism)
                    .withSalt(salt)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            generator.generateBytes(passwordBytes, hash);

            return "$argon2id$v=19$m=" + argon2MemoryKb
                    + ",t=" + argon2Iterations
                    + ",p=" + argon2Parallelism
                    + "$" + B64_NO_PAD.encodeToString(salt)
                    + "$" + B64_NO_PAD.encodeToString(hash);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }

    private boolean verifyArgon2(char[] passwordChars, String phcHash) {
        // Format: $argon2(id|i|d)$v=19$m=...,t=...,p=...$salt$hash
        String[] parts = phcHash.split("\\$");
        if (parts.length != 6) {
            return false;
        }

        int type = switch (parts[1]) {
            case "argon2id" -> Argon2Parameters.ARGON2_id;
            case "argon2i" -> Argon2Parameters.ARGON2_i;
            case "argon2d" -> Argon2Parameters.ARGON2_d;
            default -> -1;
        };
        if (type == -1) {
            return false;
        }

        int version = Argon2Parameters.ARGON2_VERSION_13;
        if (parts[2].startsWith("v=")) {
            version = Integer.parseInt(parts[2].substring(2));
        }

        int memoryKb = 0;
        int iterations = 0;
        int parallelism = 0;
        for (String param : parts[3].split(",")) {
            if (param.startsWith("m=")) {
                memoryKb = Integer.parseInt(param.substring(2));
            } else if (param.startsWith("t=")) {
                iterations = Integer.parseInt(param.substring(2));
            } else if (param.startsWith("p=")) {
                parallelism = Integer.parseInt(param.substring(2));
            }
        }
        if (memoryKb <= 0 || iterations <= 0 || parallelism <= 0) {
            return false;
        }

        byte[] salt = B64_DECODER.decode(parts[4]);
        byte[] expectedHash = B64_DECODER.decode(parts[5]);
        byte[] computedHash = new byte[expectedHash.length];
        byte[] passwordBytes = toUtf8Bytes(passwordChars);

        try {
            Argon2Parameters params = new Argon2Parameters.Builder(type)
                    .withVersion(version)
                    .withMemoryAsKB(memoryKb)
                    .withIterations(iterations)
                    .withParallelism(parallelism)
                    .withSalt(salt)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            generator.generateBytes(passwordBytes, computedHash);

            return MessageDigest.isEqual(expectedHash, computedHash);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(computedHash, (byte) 0);
        }
    }

    private String hashBcrypt(char[] passwordChars) {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        // OpenBSDBCrypt supports $2b$ via "2b" version parameter in modern BouncyCastle
        return OpenBSDBCrypt.generate("2b", passwordChars, salt, bcryptCost);
    }

    private static byte[] toUtf8Bytes(char[] chars) {
        return new String(chars).getBytes(StandardCharsets.UTF_8);
    }
}
