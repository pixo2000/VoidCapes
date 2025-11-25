package dev.pixo2000.client.command;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import dev.pixo2000.client.config.CredentialsManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.argument;
import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.literal;

/**
 * Implements /caperemove to delete an assigned cape after confirmation.
 */
public final class CapeRemoveCommand {
    private static final String API_BASE_URL = "https://capes.voidcube.de/api";
    private static final ConcurrentHashMap<String, PendingCapeRemoval> PENDING = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "Voidcapes-CapeRemove");
        thread.setDaemon(true);
        return thread;
    });
    private static final Gson GSON = new Gson();

    private CapeRemoveCommand() {
    }

    public static void register(CommandDispatcher<FabricClientCommandSource> dispatcher) {
        dispatcher.register(literal("caperemove")
                .then(argument("totp", StringArgumentType.word())
                        .then(argument("player", StringArgumentType.word())
                                .executes(CapeRemoveCommand::execute))));
    }

    private static int execute(CommandContext<FabricClientCommandSource> context) {
        String totp = StringArgumentType.getString(context, "totp");
        String playerName = StringArgumentType.getString(context, "player");

        if (PENDING.containsKey(playerName.toLowerCase())) {
            context.getSource().sendError(Text.literal("[Voidcapes] Pending removal already scheduled for " + playerName));
            return 0;
        }

        CompletableFuture.supplyAsync(() -> checkPlayerCape(playerName)).thenAccept(result -> {
            if (result == null || result.error != null) {
                context.getSource().sendError(Text.literal("[Voidcapes] Failed to check cape: "
                        + (result == null ? "unknown" : result.error)));
                return;
            }
            if (!result.playerExists) {
                context.getSource().sendError(Text.literal("[Voidcapes] Player not found: " + playerName));
                return;
            }
            if (!result.hasCape) {
                context.getSource().sendError(Text.literal("[Voidcapes] Player " + playerName + " has no cape"));
                return;
            }
            scheduleConfirmation(playerName, totp, context.getSource());
        }).exceptionally(throwable -> {
            context.getSource().sendError(Text.literal("[Voidcapes] Failed to check cape: " + throwable.getMessage()));
            return null;
        });
        return 1;
    }

    private static void scheduleConfirmation(String playerName, String totp, FabricClientCommandSource source) {
        PendingCapeRemoval removal = new PendingCapeRemoval(playerName, totp, source);
        PENDING.put(playerName.toLowerCase(), removal);
        source.sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.YELLOW)
                .append(Text.literal(playerName).formatted(Formatting.GOLD))
                .append(Text.literal(" has a cape. Run /capeconfirm within 10s to remove it.")));
        SCHEDULER.schedule(() -> {
            if (PENDING.remove(playerName.toLowerCase()) != null) {
                source.sendError(Text.literal("[Voidcapes] Removal confirmation timed out for " + playerName));
            }
        }, 10, TimeUnit.SECONDS);
    }

    private static CapeCheckResult checkPlayerCape(String playerName) {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            String encodedName = URLEncoder.encode(playerName, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE_URL + "/check_cape/" + encodedName))
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", "Voidcapes/1.0")
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return new CapeCheckResult(false, false, "HTTP " + response.statusCode());
            }
            JsonObject json = GSON.fromJson(response.body(), JsonObject.class);
            boolean success = json.has("success") && json.get("success").getAsBoolean();
            if (!success) {
                String error = json.has("error") ? json.get("error").getAsString() : "Request failed";
                return new CapeCheckResult(false, false, error);
            }
            boolean playerExists = json.has("player_exists") && json.get("player_exists").getAsBoolean();
            boolean hasCape = json.has("has_cape") && json.get("has_cape").getAsBoolean();
            return new CapeCheckResult(playerExists, hasCape, null);
        } catch (Exception e) {
            return new CapeCheckResult(false, false, e.getMessage());
        }
    }

    private static CapeRemovalResult performRemoval(String playerName, String totp, String username, String password) {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
            String form = "player_name=" + URLEncoder.encode(playerName, StandardCharsets.UTF_8)
                    + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8)
                    + "&totp=" + URLEncoder.encode(totp, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE_URL + "/delete_cape"))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("User-Agent", "Voidcapes/1.0")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return new CapeRemovalResult(false, "HTTP " + response.statusCode() + ": " + response.body());
            }
            JsonObject json = GSON.fromJson(response.body(), JsonObject.class);
            boolean success = json.has("success") && json.get("success").getAsBoolean();
            if (!success) {
                String error = json.has("error") ? json.get("error").getAsString() : "Request failed";
                return new CapeRemovalResult(false, error);
            }
            return new CapeRemovalResult(true, null);
        } catch (Exception e) {
            return new CapeRemovalResult(false, e.getMessage());
        }
    }

    private static void removeCape(String playerName, String totp, FabricClientCommandSource source) {
        CompletableFuture.supplyAsync(() -> {
            CredentialsManager.CredentialsData credentials = CapeLoginCommand.getStoredCredentials();
            if (credentials == null) {
                return new CapeRemovalResult(false, "No stored credentials. Use /capelogin first.");
            }
            return performRemoval(playerName, totp, credentials.username(), credentials.password());
        }).thenAccept(result -> {
            if (result.success) {
                source.sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                        .append(Text.literal("Cape removed for " + playerName).formatted(Formatting.WHITE)));
            } else {
                source.sendError(Text.literal("[Voidcapes] Failed: " + result.error));
            }
        }).exceptionally(throwable -> {
            source.sendError(Text.literal("[Voidcapes] Failed: " + throwable.getMessage()));
            return null;
        });
    }

    public static void confirmPendingRemoval(String playerName) {
        PendingCapeRemoval pending = PENDING.remove(playerName.toLowerCase());
        if (pending != null) {
            removeCape(pending.playerName, pending.totp, pending.source);
        }
    }

    public static String getAnyPendingRemoval() {
        return PENDING.keySet().stream().findFirst().orElse(null);
    }

    public static PendingCapeRemoval getPendingRemoval(String playerName) {
        return PENDING.get(playerName.toLowerCase());
    }

    public static void shutdown() {
        if (!SCHEDULER.isShutdown()) {
            SCHEDULER.shutdown();
        }
    }

    private record CapeCheckResult(boolean playerExists, boolean hasCape, String error) {
    }

    private record CapeRemovalResult(boolean success, String error) {
    }

    public static final class PendingCapeRemoval {
        final String playerName;
        final String totp;
        final FabricClientCommandSource source;

        PendingCapeRemoval(String playerName, String totp, FabricClientCommandSource source) {
            this.playerName = playerName;
            this.totp = totp;
            this.source = source;
        }
    }
}
