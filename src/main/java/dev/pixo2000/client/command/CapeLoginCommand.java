package dev.pixo2000.client.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import dev.pixo2000.client.config.CredentialsManager;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.argument;
import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.literal;

/**
 * Handles /capelogin, /capecheck and /capeclear commands for storing provider credentials.
 */
public final class CapeLoginCommand {
    private static CredentialsManager credentialsManager;

    private CapeLoginCommand() {
    }

    public static void setCredentialsManager(CredentialsManager manager) {
        credentialsManager = manager;
    }

    public static void register(CommandDispatcher<FabricClientCommandSource> dispatcher) {
        dispatcher.register(literal("capelogin")
                .then(argument("username", StringArgumentType.word())
                        .then(argument("password", StringArgumentType.greedyString())
                                .executes(CapeLoginCommand::executeLogin))));

        dispatcher.register(literal("capecheck").executes(CapeLoginCommand::executeCheck));
        dispatcher.register(literal("capeclear").executes(CapeLoginCommand::executeClear));
    }

    private static int executeLogin(CommandContext<FabricClientCommandSource> context) {
        if (credentialsManager == null) {
            context.getSource().sendError(Text.literal("[Voidcapes] Credentials manager unavailable"));
            return 0;
        }

        String username = StringArgumentType.getString(context, "username");
        String password = StringArgumentType.getString(context, "password");
        try {
            credentialsManager.storeCredentials(username, password);
            context.getSource().sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                    .append(Text.literal("Saved credentials for " + username).formatted(Formatting.WHITE)));
            return 1;
        } catch (Exception e) {
            context.getSource().sendError(Text.literal("[Voidcapes] Failed to save credentials: " + e.getMessage()));
            return 0;
        }
    }

    private static int executeCheck(CommandContext<FabricClientCommandSource> context) {
        if (credentialsManager == null) {
            context.getSource().sendError(Text.literal("[Voidcapes] Credentials manager unavailable"));
            return 0;
        }

        try {
            if (!credentialsManager.hasCredentials()) {
                context.getSource().sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.YELLOW)
                        .append(Text.literal("No stored credentials found").formatted(Formatting.WHITE)));
                return 1;
            }

            CredentialsManager.CredentialsData data = credentialsManager.loadCredentials();
            if (data == null) {
                context.getSource().sendError(Text.literal("[Voidcapes] Could not decrypt credentials"));
                return 0;
            }

            long daysAgo = (System.currentTimeMillis() - data.timestamp()) / (1000L * 60 * 60 * 24);
            context.getSource().sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                    .append(Text.literal("Stored user: " + data.username()).formatted(Formatting.WHITE)));
            context.getSource().sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GRAY)
                    .append(Text.literal("Saved " + daysAgo + " day(s) ago").formatted(Formatting.WHITE)));
            return 1;
        } catch (Exception e) {
            context.getSource().sendError(Text.literal("[Voidcapes] Failed to read credentials: " + e.getMessage()));
            return 0;
        }
    }

    private static int executeClear(CommandContext<FabricClientCommandSource> context) {
        if (credentialsManager == null) {
            context.getSource().sendError(Text.literal("[Voidcapes] Credentials manager unavailable"));
            return 0;
        }

        try {
            credentialsManager.deleteCredentials();
            context.getSource().sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                    .append(Text.literal("Stored credentials cleared").formatted(Formatting.WHITE)));
            return 1;
        } catch (Exception e) {
            context.getSource().sendError(Text.literal("[Voidcapes] Failed to clear credentials: " + e.getMessage()));
            return 0;
        }
    }

    public static CredentialsManager.CredentialsData getStoredCredentials() {
        if (credentialsManager == null) {
            return null;
        }
        try {
            return credentialsManager.loadCredentials();
        } catch (Exception e) {
            return null;
        }
    }
}
