package dev.pixo2000.client.cape;

import dev.pixo2000.Voidcapes;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.AbstractClientPlayerEntity;

public final class CapeRefreshManager {
    public static final int DEFAULT_REFRESH_INTERVAL_SECONDS = 300;
    private static final int MIN_REFRESH_INTERVAL_SECONDS = 5;

    private static long refreshIntervalMs = DEFAULT_REFRESH_INTERVAL_SECONDS * 1000L;
    private static long nextRefreshTimestamp = System.currentTimeMillis() + refreshIntervalMs;
    private static final Set<UUID> TRACKED_PLAYERS = new HashSet<>();
    private static boolean initialized;

    private CapeRefreshManager() {
    }

    public static void initialize() {
        if (initialized) {
            return;
        }
        initialized = true;
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            if (client.world == null) {
                TRACKED_PLAYERS.clear();
                return;
            }

            trackPlayers(client);

            long now = System.currentTimeMillis();
            if (now >= nextRefreshTimestamp) {
                int refreshed = CapeTextureService.refreshPlayers(client.world.getPlayers());
                if (refreshed > 0) {
                    Voidcapes.LOGGER.debug("Auto-refreshed {} cape(s)", refreshed);
                }
                nextRefreshTimestamp = now + refreshIntervalMs;
            }
        });
    }

    public static int refreshNow() {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client.world == null) {
            return 0;
        }
        nextRefreshTimestamp = System.currentTimeMillis() + refreshIntervalMs;
        return CapeTextureService.refreshPlayers(client.world.getPlayers());
    }

    public static void setRefreshIntervalSeconds(int seconds) {
        int sanitized = Math.max(MIN_REFRESH_INTERVAL_SECONDS, seconds);
        refreshIntervalMs = sanitized * 1000L;
        nextRefreshTimestamp = System.currentTimeMillis() + refreshIntervalMs;
    }

    public static int getRefreshIntervalSeconds() {
        return (int) (refreshIntervalMs / 1000L);
    }

    private static void trackPlayers(MinecraftClient client) {
        TRACKED_PLAYERS.removeIf(uuid -> client.world.getPlayerByUuid(uuid) == null);
        for (AbstractClientPlayerEntity player : client.world.getPlayers()) {
            if (TRACKED_PLAYERS.add(player.getUuid())) {
                CapeTextureService.prefetchCape(player);
            }
        }
    }
}
