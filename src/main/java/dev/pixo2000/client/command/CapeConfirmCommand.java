package dev.pixo2000.client.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.context.CommandContext;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.literal;

/**
 * Confirms pending /capeset or /caperemove operations.
 */
public final class CapeConfirmCommand {
    private CapeConfirmCommand() {
    }

    public static void register(CommandDispatcher<FabricClientCommandSource> dispatcher) {
        dispatcher.register(literal("capeconfirm").executes(CapeConfirmCommand::execute));
    }

    private static int execute(CommandContext<FabricClientCommandSource> context) {
        FabricClientCommandSource source = context.getSource();

        String pendingSet = CapeSetCommand.getAnyPendingPlayer();
        if (pendingSet != null) {
            CapeSetCommand.PendingCapeRequest request = CapeSetCommand.getPendingRequest(pendingSet);
            if (request != null) {
                source.sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                        .append(Text.literal("Confirming cape replacement for " + request.playerName)
                                .formatted(Formatting.WHITE)));
                CapeSetCommand.confirmPendingRequest(pendingSet);
                return 1;
            }
        }

        String pendingRemoval = CapeRemoveCommand.getAnyPendingRemoval();
        if (pendingRemoval != null) {
            CapeRemoveCommand.PendingCapeRemoval removal = CapeRemoveCommand.getPendingRemoval(pendingRemoval);
            if (removal != null) {
                source.sendFeedback(Text.literal("[Voidcapes] ").formatted(Formatting.GREEN)
                        .append(Text.literal("Confirming cape removal for " + removal.playerName)
                                .formatted(Formatting.WHITE)));
                CapeRemoveCommand.confirmPendingRemoval(pendingRemoval);
                return 1;
            }
        }

        source.sendError(Text.literal("[Voidcapes] No pending cape requests"));
        return 0;
    }
}
