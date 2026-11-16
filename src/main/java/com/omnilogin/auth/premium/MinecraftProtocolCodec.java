package com.omnilogin.auth.premium;

import com.google.gson.JsonObject;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

import java.nio.charset.StandardCharsets;

/**
 * Low-level Minecraft Handshake and Login packet codec helpers (1.20 through 1.21+).
 */
public final class MinecraftProtocolCodec {

    public static final int PROTOCOL_1_20_5 = 766;

    public record HandshakePacket(int protocolVersion, String serverAddress, int port, int nextState) {
    }

    public record EncryptionResponsePacket(byte[] encryptedSharedSecret, byte[] encryptedVerifyToken) {
    }

    private MinecraftProtocolCodec() {
    }

    public static int readVarInt(ByteBuf buf) {
        int value = 0;
        int position = 0;
        byte currentByte;

        while (true) {
            currentByte = buf.readByte();
            value |= (currentByte & 0x7F) << position;
            if ((currentByte & 0x80) == 0) {
                break;
            }
            position += 7;
            if (position >= 32) {
                throw new IllegalArgumentException("VarInt is too big");
            }
        }
        return value;
    }

    public static void writeVarInt(ByteBuf buf, int value) {
        while ((value & ~0x7F) != 0) {
            buf.writeByte((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        buf.writeByte(value);
    }

    public static String readString(ByteBuf buf, int maxChars) {
        int byteLength = readVarInt(buf);
        if (byteLength < 0 || byteLength > maxChars * 3) {
            throw new IllegalArgumentException("Invalid UTF-8 string byte length: " + byteLength);
        }
        byte[] bytes = new byte[byteLength];
        buf.readBytes(bytes);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        if (decoded.length() > maxChars) {
            throw new IllegalArgumentException("String exceeds max char length: " + decoded.length());
        }
        return decoded;
    }

    public static void writeString(ByteBuf buf, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(buf, bytes.length);
        buf.writeBytes(bytes);
    }

    public static byte[] readByteArray(ByteBuf buf, int maxLen) {
        int length = readVarInt(buf);
        if (length < 0 || length > maxLen) {
            throw new IllegalArgumentException("Invalid byte array length: " + length);
        }
        byte[] bytes = new byte[length];
        buf.readBytes(bytes);
        return bytes;
    }

    public static void writeByteArray(ByteBuf buf, byte[] bytes) {
        writeVarInt(buf, bytes.length);
        buf.writeBytes(bytes);
    }

    public static HandshakePacket parseHandshake(ByteBuf unframedPacket) {
        int packetId = readVarInt(unframedPacket);
        if (packetId != 0x00) {
            throw new IllegalArgumentException("Expected Handshake packet 0x00, got 0x" + Integer.toHexString(packetId));
        }
        int protocolVersion = readVarInt(unframedPacket);
        String address = readString(unframedPacket, 255);
        int port = unframedPacket.readUnsignedShort();
        int nextState = readVarInt(unframedPacket);
        return new HandshakePacket(protocolVersion, address, port, nextState);
    }

    public static String parseLoginStartUsername(ByteBuf unframedPacket) {
        int packetId = readVarInt(unframedPacket);
        if (packetId != 0x00) {
            throw new IllegalArgumentException("Expected Login Start packet 0x00, got 0x" + Integer.toHexString(packetId));
        }
        return readString(unframedPacket, 16);
    }

    public static ByteBuf buildEncryptionRequest(
            ByteBufAllocator alloc,
            String serverId,
            byte[] publicKeyDer,
            byte[] verifyToken,
            int protocolVersion
    ) {
        ByteBuf buf = alloc.buffer();
        writeVarInt(buf, 0x01); // Clientbound Hello / Encryption Request
        writeString(buf, serverId);
        writeByteArray(buf, publicKeyDer);
        writeByteArray(buf, verifyToken);
        if (protocolVersion >= PROTOCOL_1_20_5) {
            buf.writeBoolean(true); // shouldAuthenticate
        }
        return buf;
    }

    public static EncryptionResponsePacket parseEncryptionResponse(ByteBuf unframedPacket) {
        int packetId = readVarInt(unframedPacket);
        if (packetId != 0x01) {
            throw new IllegalArgumentException("Expected Encryption Response 0x01, got 0x" + Integer.toHexString(packetId));
        }
        byte[] sharedSecret = readByteArray(unframedPacket, 512);
        byte[] verifyToken = readByteArray(unframedPacket, 512);
        return new EncryptionResponsePacket(sharedSecret, verifyToken);
    }

    public static ByteBuf buildLoginDisconnect(ByteBufAllocator alloc, String plainOrLegacyReason) {
        JsonObject component = new JsonObject();
        component.addProperty("text", plainOrLegacyReason);

        ByteBuf buf = alloc.buffer();
        writeVarInt(buf, 0x00); // Clientbound Login Disconnect
        writeString(buf, component.toString());
        return buf;
    }
}
