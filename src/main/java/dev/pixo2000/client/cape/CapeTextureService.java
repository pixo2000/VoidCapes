package dev.pixo2000.client.cape;

import dev.pixo2000.Voidcapes;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.AbstractClientPlayerEntity;
import net.minecraft.client.texture.NativeImage;
import net.minecraft.client.texture.NativeImageBackedTexture;
import net.minecraft.client.texture.TextureManager;
import net.minecraft.util.Identifier;
import net.minecraft.util.Util;

public final class CapeTextureService {
    private static final String CAPE_ENDPOINT = "https://voidcube.de/capes/";
    private static final String USER_AGENT = "Voidcapes/1.0 (+https://voidcube.de)";
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final Map<UUID, CapeRecord> CAPES = new ConcurrentHashMap<>();

    private CapeTextureService() {
    }

    public static void initialize() {
        CAPES.clear();
    }

    public static Identifier getCapeTexture(AbstractClientPlayerEntity player) {
        UUID uuid = player.getUuid();
        CapeRecord record = CAPES.computeIfAbsent(uuid, ignored -> new CapeRecord());
        if (record.status == CapeStatus.READY) {
            AnimatedCapeState animated = record.animatedCape;
            if (animated != null) {
                Identifier current = animated.currentTexture();
                if (current != null) {
                    record.textureId = current;
                    return current;
                }
            }
            return record.textureId;
        }
        if (record.status == CapeStatus.UNCHECKED) {
            record.status = CapeStatus.FETCHING;
            fetchCapeAsync(uuid);
        }
        return null;
    }

    public static boolean hasElytraTexture(AbstractClientPlayerEntity player) {
        CapeRecord record = CAPES.get(player.getUuid());
        return record != null && record.status == CapeStatus.READY && record.hasElytraTexture;
    }

    private static void fetchCapeAsync(UUID uuid) {
        CompletableFuture.runAsync(() -> downloadCape(uuid), Util.getIoWorkerExecutor())
                .exceptionally(throwable -> {
                    Voidcapes.LOGGER.debug("Cape download failed for {}", uuid, throwable);
                    CAPES.computeIfPresent(uuid, (ignored, record) -> {
                        record.status = CapeStatus.FAILED;
                        return record;
                    });
                    return null;
                });
    }

    private static void downloadCape(UUID uuid) {
        byte[] data = requestCape(uuid);
        if (data == null || data.length == 0) {
            markFailed(uuid);
            return;
        }

        CapeImageDecoder.DecodedCape decoded;
        try {
            decoded = CapeImageDecoder.decode(data);
        } catch (IOException e) {
            Voidcapes.LOGGER.debug("Cape decode failed for {}", uuid, e);
            markFailed(uuid);
            return;
        }

        MinecraftClient client = MinecraftClient.getInstance();
        if (client == null) {
            discardDecodedCape(decoded);
            markFailed(uuid);
            return;
        }

        CapeImageDecoder.DecodedCape finalDecoded = decoded;
        client.execute(() -> registerDecodedCape(uuid, finalDecoded));
    }

    private static void registerDecodedCape(UUID uuid, CapeImageDecoder.DecodedCape decoded) {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client == null) {
            discardDecodedCape(decoded);
            markFailed(uuid);
            return;
        }

        TextureManager textureManager = client.getTextureManager();
        if (decoded instanceof CapeImageDecoder.StaticCape staticCape) {
            Identifier identifier = Identifier.of(Voidcapes.MOD_ID, "capes/" + uuid);
            textureManager.registerTexture(identifier, createTexture(identifier, staticCape.image()));
            updateRecord(uuid, identifier, null, staticCape.hasElytra());
            return;
        }

        if (decoded instanceof CapeImageDecoder.AnimatedCape animatedCape) {
            List<FrameTexture> frames = registerAnimatedFrames(textureManager, uuid, animatedCape.frames());
            if (frames.isEmpty()) {
                markFailed(uuid);
                return;
            }
            AnimatedCapeState state = new AnimatedCapeState(frames);
            updateRecord(uuid, state.currentTexture(), state, animatedCape.hasElytra());
        }
    }

    private static byte[] requestCape(UUID uuid) {
        String dashed = uuid.toString();
        String undashed = dashed.replace("-", "");
        String[] candidates = new String[] { undashed, dashed };
        for (String candidate : candidates) {
            byte[] result = sendCapeRequest(CAPE_ENDPOINT + candidate);
            if (result != null && result.length > 0) {
                return result;
            }
        }
        return null;
    }

    private static byte[] sendCapeRequest(String url) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();
        try {
            HttpResponse<byte[]> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == 200) {
                return response.body();
            }
            if (response.statusCode() != 404) {
                Voidcapes.LOGGER.debug("Unexpected response {} for {}", response.statusCode(), url);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Voidcapes.LOGGER.debug("Cape request interrupted for {}", url, e);
        } catch (IOException e) {
            Voidcapes.LOGGER.debug("Cape request failed for {}", url, e);
        }
        return null;
    }

    private static List<FrameTexture> registerAnimatedFrames(
            TextureManager textureManager,
            UUID uuid,
            List<CapeImageDecoder.CapeFrame> frames) {
        List<FrameTexture> textures = new ArrayList<>(frames.size());
        for (int index = 0; index < frames.size(); index++) {
            CapeImageDecoder.CapeFrame frame = frames.get(index);
            Identifier identifier = Identifier.of(Voidcapes.MOD_ID, "capes/" + uuid + "/" + index);
            textureManager.registerTexture(identifier, createTexture(identifier, frame.image()));
            textures.add(new FrameTexture(identifier, Math.max(1, frame.delayMs())));
        }
        return textures;
    }

    private static void updateRecord(UUID uuid, Identifier identifier, AnimatedCapeState animatedCape, boolean hasElytra) {
        CAPES.compute(uuid, (ignored, record) -> {
            if (record == null) {
                record = new CapeRecord();
            }
            record.status = CapeStatus.READY;
            record.textureId = identifier;
            record.animatedCape = animatedCape;
            record.hasElytraTexture = hasElytra;
            return record;
        });
    }

    private static void markFailed(UUID uuid) {
        CAPES.compute(uuid, (ignored, record) -> {
            if (record == null) {
                return null;
            }
            record.status = CapeStatus.FAILED;
            record.textureId = null;
            record.animatedCape = null;
            record.hasElytraTexture = false;
            return record;
        });
    }

    private static void discardDecodedCape(CapeImageDecoder.DecodedCape decoded) {
        if (decoded instanceof CapeImageDecoder.StaticCape staticCape) {
            staticCape.image().close();
        } else if (decoded instanceof CapeImageDecoder.AnimatedCape animatedCape) {
            animatedCape.frames().forEach(frame -> frame.image().close());
        }
    }

    private static NativeImageBackedTexture createTexture(Identifier identifier, NativeImage image) {
        return new NativeImageBackedTexture(identifier::toString, image);
    }

    public static void prefetchCape(AbstractClientPlayerEntity player) {
        requestFetch(player.getUuid(), FetchMode.PREFETCH);
    }

    public static void refreshCape(AbstractClientPlayerEntity player) {
        requestFetch(player.getUuid(), FetchMode.FORCE_REFRESH);
    }

    public static int refreshPlayers(Iterable<? extends AbstractClientPlayerEntity> players) {
        int count = 0;
        for (AbstractClientPlayerEntity player : players) {
            refreshCape(player);
            count++;
        }
        return count;
    }

    private static void requestFetch(UUID uuid, FetchMode mode) {
        boolean[] shouldFetch = new boolean[] { false };
        CAPES.compute(uuid, (ignored, record) -> {
            if (record == null) {
                record = new CapeRecord();
            }
            if (mode == FetchMode.FORCE_REFRESH) {
                record.status = CapeStatus.UNCHECKED;
                record.textureId = null;
                record.animatedCape = null;
                record.hasElytraTexture = false;
            }
            if (record.status == CapeStatus.UNCHECKED || record.status == CapeStatus.FAILED
                    || mode == FetchMode.FORCE_REFRESH) {
                if (record.status != CapeStatus.FETCHING) {
                    record.status = CapeStatus.FETCHING;
                    shouldFetch[0] = true;
                }
            }
            return record;
        });
        if (shouldFetch[0]) {
            fetchCapeAsync(uuid);
        }
    }

    private enum CapeStatus {
        UNCHECKED,
        FETCHING,
        READY,
        FAILED
    }

    private static final class CapeRecord {
        private volatile CapeStatus status = CapeStatus.UNCHECKED;
        private volatile Identifier textureId;
        private volatile AnimatedCapeState animatedCape;
        private volatile boolean hasElytraTexture;
    }

    private static final class AnimatedCapeState {
        private final List<FrameTexture> frames;
        private int frameIndex;
        private long nextFrameTime;

        private AnimatedCapeState(List<FrameTexture> frames) {
            this.frames = frames;
            long now = System.currentTimeMillis();
            this.frameIndex = 0;
            this.nextFrameTime = now + frames.get(0).delayMs();
        }

        private Identifier currentTexture() {
            if (frames.isEmpty()) {
                return null;
            }
            long now = System.currentTimeMillis();
            if (now >= nextFrameTime) {
                frameIndex = (frameIndex + 1) % frames.size();
                nextFrameTime = now + frames.get(frameIndex).delayMs();
            }
            return frames.get(frameIndex).identifier();
        }
    }

    private record FrameTexture(Identifier identifier, int delayMs) {
    }

    private enum FetchMode {
        PREFETCH,
        FORCE_REFRESH
    }
}
