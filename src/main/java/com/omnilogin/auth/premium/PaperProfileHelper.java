package com.omnilogin.auth.premium;

import com.destroystokyo.paper.profile.PlayerProfile;
import com.destroystokyo.paper.profile.ProfileProperty;
import org.bukkit.Bukkit;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.util.UUID;

/**
 * Isolated Paper-specific {@link PlayerProfile} helper so Spigot servers without
 * Paper's profile API never fail class verification.
 */
final class PaperProfileHelper {

    private PaperProfileHelper() {
    }

    static boolean applyVerifiedProfile(
            AsyncPlayerPreLoginEvent event,
            VerifiedPremiumSession session,
            boolean applyMojangUuid,
            boolean applyMojangSkin
    ) {
        UUID targetUuid = applyMojangUuid ? session.mojangUuid() : event.getUniqueId();
        String targetName = session.canonicalUsername() != null ? session.canonicalUsername() : event.getName();
        PlayerProfile profile = Bukkit.createProfile(targetUuid, targetName);

        if (applyMojangSkin && session.properties() != null) {
            for (VerifiedPremiumSession.SkinProperty prop : session.properties()) {
                profile.setProperty(new ProfileProperty(prop.name(), prop.value(), prop.signature()));
            }
        }
        event.setPlayerProfile(profile);
        return true;
    }

    static boolean hasSignedTextures(AsyncPlayerPreLoginEvent event) {
        PlayerProfile profile = event.getPlayerProfile();
        for (ProfileProperty prop : profile.getProperties()) {
            if ("textures".equals(prop.getName()) && prop.isSigned()) {
                return true;
            }
        }
        return false;
    }
}
