package com.omnilogin.auth.premium;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import org.bukkit.Bukkit;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Injects a lightweight Netty login interceptor into the server's active Netty listener
 * channels to perform cryptographic RSA + AES/CFB8 + Mojang {@code hasJoined} verification
 * for hybrid online/offline authentication on Paper, Spigot, and Purpur (1.20 - 1.21+).
 */
public final class NettyHandshakeInjector {

    public static final AttributeKey<VerifiedPremiumSession> VERIFIED_SESSION_ATTR =
            AttributeKey.valueOf("omnilogin_verified_premium_session");

    private static final String SERVER_HANDLER_NAME = "omnilogin_server_acceptor";
    private static final String CHILD_INIT_HANDLER_NAME = "omnilogin_child_init";
    private static final String AUTH_HANDLER_NAME = "omnilogin_login_auth";
    private static final String DECRYPT_HANDLER_NAME = "omnilogin_decrypt";
    private static final String ENCRYPT_HANDLER_NAME = "omnilogin_encrypt";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Logger logger;
    private final PremiumLoginManager manager;
    private final MojangApiClient mojangApi;
    private final KeyPair rsaKeyPair;

    private final Set<Channel> injectedServerChannels = ConcurrentHashMap.newKeySet();
    private final Set<Channel> activeChildChannels = ConcurrentHashMap.newKeySet();
    private volatile boolean active;

    public NettyHandshakeInjector(
            Logger logger,
            PremiumLoginManager manager,
            MojangApiClient mojangApi,
            KeyPair rsaKeyPair
    ) {
        this.logger = logger;
        this.manager = manager;
        this.mojangApi = mojangApi;
        this.rsaKeyPair = rsaKeyPair;
    }

    public boolean inject() {
        if (active) {
            return true;
        }
        try {
            List<ChannelFuture> channelFutures = locateServerChannelFutures();
            if (channelFutures.isEmpty()) {
                logger.warning("No Netty ChannelFutures found; hybrid auth will fall back to AsyncPlayerPreLoginEvent.");
                return false;
            }

            active = true;
            for (ChannelFuture future : channelFutures) {
                Channel serverChannel = future.channel();
                if (serverChannel == null || !serverChannel.isOpen()) {
                    continue;
                }
                ChannelPipeline pipeline = serverChannel.pipeline();
                if (pipeline.get(SERVER_HANDLER_NAME) == null) {
                    pipeline.addFirst(SERVER_HANDLER_NAME, new ServerChannelAcceptor());
                    injectedServerChannels.add(serverChannel);
                }
            }
            return !injectedServerChannels.isEmpty();
        } catch (Throwable ex) {
            active = false;
            logger.log(Level.WARNING, "Unable to hook Netty server pipeline; falling back to AsyncPlayerPreLoginEvent.", ex);
            return false;
        }
    }

    public void shutdown() {
        active = false;
        for (Channel serverChannel : injectedServerChannels) {
            try {
                if (serverChannel.isOpen() && serverChannel.pipeline().get(SERVER_HANDLER_NAME) != null) {
                    serverChannel.pipeline().remove(SERVER_HANDLER_NAME);
                }
            } catch (Exception ignored) {
            }
        }
        injectedServerChannels.clear();

        for (Channel child : activeChildChannels) {
            try {
                if (child.isOpen() && child.pipeline().get(AUTH_HANDLER_NAME) != null) {
                    child.pipeline().remove(AUTH_HANDLER_NAME);
                }
            } catch (Exception ignored) {
            }
        }
        activeChildChannels.clear();
    }

    @SuppressWarnings("unchecked")
    private List<ChannelFuture> locateServerChannelFutures() throws Exception {
        Object craftServer = Bukkit.getServer();
        Method getServerMethod = craftServer.getClass().getMethod("getServer");
        Object minecraftServer = getServerMethod.invoke(craftServer);
        if (minecraftServer == null) {
            return List.of();
        }

        List<Object> candidates = new ArrayList<>();
        try {
            Method getConnection = minecraftServer.getClass().getMethod("getConnection");
            Object conn = getConnection.invoke(minecraftServer);
            if (conn != null) {
                candidates.add(conn);
            }
        } catch (NoSuchMethodException ignored) {
        }

        // Scan MinecraftServer fields for ServerConnectionListener if getConnection() is obfuscated
        Class<?> cls = minecraftServer.getClass();
        while (cls != null && cls != Object.class) {
            for (Field field : cls.getDeclaredFields()) {
                if (field.getType().isPrimitive()
                        || field.getType().getName().startsWith("java.")
                        || field.getType().getName().startsWith("org.bukkit.")) {
                    continue;
                }
                field.setAccessible(true);
                Object val = field.get(minecraftServer);
                if (val != null && !candidates.contains(val)) {
                    candidates.add(val);
                }
            }
            cls = cls.getSuperclass();
        }

        for (Object candidate : candidates) {
            Class<?> c = candidate.getClass();
            while (c != null && c != Object.class) {
                for (Field field : c.getDeclaredFields()) {
                    if (!List.class.isAssignableFrom(field.getType())) {
                        continue;
                    }
                    field.setAccessible(true);
                    Object listObj = field.get(candidate);
                    if (listObj instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof ChannelFuture) {
                        return Collections.synchronizedList((List<ChannelFuture>) list);
                    }
                }
                c = c.getSuperclass();
            }
        }
        return List.of();
    }

    private void attachChildHandler(Channel child) {
        if (!active || child == null || !child.isOpen()) {
            return;
        }
        activeChildChannels.add(child);
        child.closeFuture().addListener(f -> activeChildChannels.remove(child));

        ChannelPipeline pipeline = child.pipeline();
        if (pipeline.get(CHILD_INIT_HANDLER_NAME) != null || pipeline.get(AUTH_HANDLER_NAME) != null) {
            return;
        }

        if (pipeline.context("decoder") != null) {
            insertLoginAuthHandler(pipeline);
        } else {
            pipeline.addLast(CHILD_INIT_HANDLER_NAME, new ChildChannelAttachInitializer());
        }
    }

    private void insertLoginAuthHandler(ChannelPipeline pipeline) {
        if (!active || pipeline.get(AUTH_HANDLER_NAME) != null) {
            return;
        }
        String decoderName = findHandlerName(pipeline, "decoder", "PacketDecoder");
        if (decoderName != null) {
            pipeline.addBefore(decoderName, AUTH_HANDLER_NAME, new OmniLoginLoginHandler());
        } else {
            pipeline.addLast(AUTH_HANDLER_NAME, new OmniLoginLoginHandler());
        }
    }

    private static String findHandlerName(ChannelPipeline pipeline, String preferredName, String classFragment) {
        if (pipeline.context(preferredName) != null) {
            return preferredName;
        }
        for (String name : pipeline.names()) {
            ChannelHandler handler = pipeline.get(name);
            if (handler != null && handler.getClass().getSimpleName().contains(classFragment)) {
                return name;
            }
        }
        return null;
    }

    @ChannelHandler.Sharable
    private final class ServerChannelAcceptor extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ctx.fireChannelRead(msg);
            if (active && msg instanceof Channel childChannel) {
                attachChildHandler(childChannel);
            }
        }
    }

    private final class ChildChannelAttachInitializer extends ChannelInitializer<Channel> {
        @Override
        protected void initChannel(Channel ch) {
            if (active) {
                insertLoginAuthHandler(ch.pipeline());
            }
        }
    }

    private final class OmniLoginLoginHandler extends ChannelDuplexHandler {

        private enum Stage {
            HANDSHAKING,
            AWAITING_LOGIN_START,
            LOOKING_UP_MOJANG,
            AWAITING_ENCRYPTION_RESPONSE,
            COMPLETED
        }

        private Stage stage = Stage.HANDSHAKING;
        private int protocolVersion = 765;
        private String pendingUsername;
        private byte[] verifyToken;
        private ByteBuf retainedLoginStart;

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (!(msg instanceof ByteBuf buf)) {
                ctx.fireChannelRead(msg);
                return;
            }

            if (stage == Stage.COMPLETED) {
                ctx.fireChannelRead(msg);
                return;
            }

            try {
                switch (stage) {
                    case HANDSHAKING -> handleHandshake(ctx, buf);
                    case AWAITING_LOGIN_START -> handleLoginStart(ctx, buf);
                    case AWAITING_ENCRYPTION_RESPONSE -> handleEncryptionResponse(ctx, buf);
                    case LOOKING_UP_MOJANG -> ReferenceCountUtil.release(buf);
                    default -> ctx.fireChannelRead(msg);
                }
            } catch (Throwable ex) {
                ReferenceCountUtil.release(buf);
                releaseRetainedLoginStart();
                logger.log(Level.FINE, "Netty login handshake exception; closing channel", ex);
                ctx.close();
            }
        }

        private void handleHandshake(ChannelHandlerContext ctx, ByteBuf buf) {
            ByteBuf slice = buf.slice();
            MinecraftProtocolCodec.HandshakePacket handshake = MinecraftProtocolCodec.parseHandshake(slice);
            this.protocolVersion = handshake.protocolVersion();

            if (handshake.nextState() == 2) {
                this.stage = Stage.AWAITING_LOGIN_START;
                ctx.fireChannelRead(buf);
            } else {
                // Status ping or transfer packet: bypass and detach our handler immediately
                this.stage = Stage.COMPLETED;
                ctx.fireChannelRead(buf);
                removeSelfSafely(ctx);
            }
        }

        private void handleLoginStart(ChannelHandlerContext ctx, ByteBuf buf) {
            if (!manager.isEnabled() || !manager.isNettyHandshakeEnabled()) {
                this.stage = Stage.COMPLETED;
                ctx.fireChannelRead(buf);
                removeSelfSafely(ctx);
                return;
            }

            ByteBuf slice = buf.slice();
            String username = MinecraftProtocolCodec.parseLoginStartUsername(slice);
            this.pendingUsername = username;
            this.retainedLoginStart = buf.retain();
            ReferenceCountUtil.release(buf);
            this.stage = Stage.LOOKING_UP_MOJANG;

            mojangApi.lookupUsername(username).whenComplete((lookup, throwable) ->
                    ctx.channel().eventLoop().execute(() -> onMojangLookupComplete(ctx, lookup, throwable))
            );
        }

        private void onMojangLookupComplete(
                ChannelHandlerContext ctx,
                MojangApiClient.MojangLookupResult lookup,
                Throwable throwable
        ) {
            if (!ctx.channel().isOpen()) {
                releaseRetainedLoginStart();
                return;
            }

            if (throwable != null || lookup == null || lookup.status() == MojangApiClient.LookupStatus.ERROR) {
                if (manager.isDenyOnApiError()) {
                    disconnectLogin(ctx, manager.getApiErrorKickReason());
                } else {
                    forwardLoginStartAndDetach(ctx);
                }
                return;
            }

            if (lookup.status() == MojangApiClient.LookupStatus.OFFLINE_AVAILABLE) {
                // Username does not belong to any Mojang account: proceed to normal registration/login
                forwardLoginStartAndDetach(ctx);
                return;
            }

            // Username IS a registered Mojang account: challenge client with Encryption Request
            this.verifyToken = new byte[4];
            SECURE_RANDOM.nextBytes(this.verifyToken);
            this.stage = Stage.AWAITING_ENCRYPTION_RESPONSE;

            ByteBuf hello = MinecraftProtocolCodec.buildEncryptionRequest(
                    ctx.alloc(),
                    "",
                    rsaKeyPair.getPublic().getEncoded(),
                    verifyToken,
                    protocolVersion
            );
            ctx.channel().writeAndFlush(hello);
        }

        private void handleEncryptionResponse(ChannelHandlerContext ctx, ByteBuf buf) throws Exception {
            MinecraftProtocolCodec.EncryptionResponsePacket response =
                    MinecraftProtocolCodec.parseEncryptionResponse(buf);
            ReferenceCountUtil.release(buf);

            Cipher rsaDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaDecrypt.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());

            byte[] sharedSecretBytes = rsaDecrypt.doFinal(response.encryptedSharedSecret());
            byte[] decryptedToken = rsaDecrypt.doFinal(response.encryptedVerifyToken());

            if (!MessageDigest.isEqual(verifyToken, decryptedToken) || sharedSecretBytes.length != 16) {
                disconnectLogin(ctx, manager.getSpoofKickPlainMessage());
                return;
            }

            SecretKey sharedSecret = new SecretKeySpec(sharedSecretBytes, "AES");
            enableAesEncryption(ctx.pipeline(), sharedSecret);

            String serverIdHash = MojangApiClient.computeServerHash("", sharedSecret, rsaKeyPair.getPublic());
            InetAddress remoteAddr = extractAddress(ctx.channel());

            this.stage = Stage.LOOKING_UP_MOJANG;
            mojangApi.verifyHasJoined(pendingUsername, serverIdHash, remoteAddr)
                    .whenComplete((sessionOpt, ex) ->
                            ctx.channel().eventLoop().execute(() -> onHasJoinedComplete(ctx, sessionOpt.orElse(null), ex))
                    );
        }

        private void onHasJoinedComplete(
                ChannelHandlerContext ctx,
                VerifiedPremiumSession session,
                Throwable ex
        ) {
            if (!ctx.channel().isOpen()) {
                releaseRetainedLoginStart();
                return;
            }

            if (ex != null || session == null) {
                disconnectLogin(ctx, manager.getSpoofKickPlainMessage());
                return;
            }

            ctx.channel().attr(VERIFIED_SESSION_ATTR).set(session);
            manager.registerVerifiedHandshake(session);
            forwardLoginStartAndDetach(ctx);
        }

        private void forwardLoginStartAndDetach(ChannelHandlerContext ctx) {
            ByteBuf loginStart = this.retainedLoginStart;
            this.retainedLoginStart = null;
            this.stage = Stage.COMPLETED;
            removeSelfSafely(ctx);
            if (loginStart != null && ctx.channel().isOpen()) {
                ctx.fireChannelRead(loginStart);
            } else if (loginStart != null) {
                ReferenceCountUtil.release(loginStart);
            }
        }

        private void disconnectLogin(ChannelHandlerContext ctx, String plainMessage) {
            releaseRetainedLoginStart();
            this.stage = Stage.COMPLETED;
            ByteBuf disconnect = MinecraftProtocolCodec.buildLoginDisconnect(ctx.alloc(), plainMessage);
            ctx.channel().writeAndFlush(disconnect).addListener(future -> ctx.close());
        }

        private void enableAesEncryption(ChannelPipeline pipeline, SecretKey sharedSecret) throws Exception {
            Cipher decryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, sharedSecret, new IvParameterSpec(sharedSecret.getEncoded()));

            Cipher encryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, sharedSecret, new IvParameterSpec(sharedSecret.getEncoded()));

            String splitterName = findHandlerName(pipeline, "splitter", "FrameDecoder");
            if (splitterName != null) {
                pipeline.addBefore(splitterName, DECRYPT_HANDLER_NAME, new AesDecryptDecoder(decryptCipher));
            } else {
                pipeline.addFirst(DECRYPT_HANDLER_NAME, new AesDecryptDecoder(decryptCipher));
            }

            String prependerName = findHandlerName(pipeline, "prepender", "LengthFieldPrepender");
            if (prependerName != null) {
                pipeline.addBefore(prependerName, ENCRYPT_HANDLER_NAME, new AesEncryptEncoder(encryptCipher));
            } else {
                pipeline.addFirst(ENCRYPT_HANDLER_NAME, new AesEncryptEncoder(encryptCipher));
            }
        }

        private void removeSelfSafely(ChannelHandlerContext ctx) {
            if (ctx.pipeline().get(AUTH_HANDLER_NAME) != null) {
                ctx.pipeline().remove(this);
            }
        }

        private void releaseRetainedLoginStart() {
            if (retainedLoginStart != null) {
                ReferenceCountUtil.release(retainedLoginStart);
                retainedLoginStart = null;
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            releaseRetainedLoginStart();
            super.channelInactive(ctx);
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
            releaseRetainedLoginStart();
            super.handlerRemoved(ctx);
        }

        private InetAddress extractAddress(Channel channel) {
            if (channel.remoteAddress() instanceof InetSocketAddress socketAddress) {
                return socketAddress.getAddress();
            }
            return null;
        }
    }

    private static final class AesDecryptDecoder extends ByteToMessageDecoder {
        private final Cipher cipher;

        AesDecryptDecoder(Cipher cipher) {
            this.cipher = cipher;
        }

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
            int readable = in.readableBytes();
            if (readable <= 0) {
                return;
            }
            byte[] input = new byte[readable];
            in.readBytes(input);
            byte[] output = cipher.update(input);
            if (output != null && output.length > 0) {
                ByteBuf decrypted = ctx.alloc().heapBuffer(output.length);
                decrypted.writeBytes(output);
                out.add(decrypted);
            }
        }
    }

    private static final class AesEncryptEncoder extends MessageToByteEncoder<ByteBuf> {
        private final Cipher cipher;

        AesEncryptEncoder(Cipher cipher) {
            this.cipher = cipher;
        }

        @Override
        protected void encode(ChannelHandlerContext ctx, ByteBuf msg, ByteBuf out) {
            int readable = msg.readableBytes();
            if (readable <= 0) {
                return;
            }
            byte[] input = new byte[readable];
            msg.readBytes(input);
            byte[] encrypted = cipher.update(input);
            if (encrypted != null && encrypted.length > 0) {
                out.writeBytes(encrypted);
            }
        }
    }
}
