package com.omnilogin.auth.premium;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Cryptographically verified Mojang session metadata established during Netty login handshake.
 */
public record VerifiedPremiumSession(
        UUID mojangUuid,
        String canonicalUsername,
        List<SkinProperty> properties,
        InetAddress remoteAddress,
        Instant verifiedAt
) {
    public record SkinProperty(String name, String value, String signature) {
    }
}
