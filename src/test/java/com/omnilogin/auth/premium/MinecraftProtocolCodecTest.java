package com.omnilogin.auth.premium;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class MinecraftProtocolCodecTest {

    @Test
    void roundTripsHandshakeAndLoginStartPackets() {
        ByteBuf handshakeBuf = Unpooled.buffer();
        try {
            MinecraftProtocolCodec.writeVarInt(handshakeBuf, 0x00);
            MinecraftProtocolCodec.writeVarInt(handshakeBuf, 767);
            MinecraftProtocolCodec.writeString(handshakeBuf, "play.example.com");
            handshakeBuf.writeShort(25565);
            MinecraftProtocolCodec.writeVarInt(handshakeBuf, 2);

            var parsed = MinecraftProtocolCodec.parseHandshake(handshakeBuf);
            assertEquals(767, parsed.protocolVersion());
            assertEquals("play.example.com", parsed.serverAddress());
            assertEquals(25565, parsed.port());
            assertEquals(2, parsed.nextState());
        } finally {
            handshakeBuf.release();
        }

        ByteBuf loginStartBuf = Unpooled.buffer();
        try {
            MinecraftProtocolCodec.writeVarInt(loginStartBuf, 0x00);
            MinecraftProtocolCodec.writeString(loginStartBuf, "Notch");
            UUID uuid = UUID.randomUUID();
            loginStartBuf.writeLong(uuid.getMostSignificantBits());
            loginStartBuf.writeLong(uuid.getLeastSignificantBits());

            assertEquals("Notch", MinecraftProtocolCodec.parseLoginStartUsername(loginStartBuf));
        } finally {
            loginStartBuf.release();
        }
    }

    @Test
    void buildsVersionAwareEncryptionRequestPacket() {
        byte[] keyBytes = new byte[]{1, 2, 3, 4};
        byte[] token = new byte[]{5, 6, 7, 8};

        ByteBuf legacyReq = MinecraftProtocolCodec.buildEncryptionRequest(Unpooled.buffer().alloc(), "", keyBytes, token, 765);
        ByteBuf modernReq = MinecraftProtocolCodec.buildEncryptionRequest(Unpooled.buffer().alloc(), "", keyBytes, token, 767);
        try {
            assertEquals(0x01, MinecraftProtocolCodec.readVarInt(legacyReq));
            assertEquals("", MinecraftProtocolCodec.readString(legacyReq, 20));
            assertArrayEquals(keyBytes, MinecraftProtocolCodec.readByteArray(legacyReq, 1024));
            assertArrayEquals(token, MinecraftProtocolCodec.readByteArray(legacyReq, 64));
            assertEquals(0, legacyReq.readableBytes());

            assertEquals(0x01, MinecraftProtocolCodec.readVarInt(modernReq));
            assertEquals("", MinecraftProtocolCodec.readString(modernReq, 20));
            assertArrayEquals(keyBytes, MinecraftProtocolCodec.readByteArray(modernReq, 1024));
            assertArrayEquals(token, MinecraftProtocolCodec.readByteArray(modernReq, 64));
            assertTrue(modernReq.readBoolean());
            assertEquals(0, modernReq.readableBytes());
        } finally {
            legacyReq.release();
            modernReq.release();
        }
    }

    @Test
    void parsesUndashedMojangUuidAndComputesServerHash() throws Exception {
        UUID expected = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");
        assertEquals(expected, MojangApiClient.parseUndashedUuid("069a79f444e94726a5befca90e38aaf5"));

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        KeyPair kp = gen.generateKeyPair();
        SecretKey secret = new SecretKeySpec(new byte[16], "AES");

        String hash = MojangApiClient.computeServerHash("", secret, kp.getPublic());
        assertNotNull(hash);
        assertFalse(hash.isBlank());
        assertTrue(hash.matches("-?[0-9a-f]+"));
    }
}
