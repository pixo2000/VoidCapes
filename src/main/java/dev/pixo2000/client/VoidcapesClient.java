package dev.pixo2000.client;

import com.mojang.brigadier.arguments.IntegerArgumentType;
import dev.pixo2000.Voidcapes;
import dev.pixo2000.client.cape.CapeRefreshManager;
import dev.pixo2000.client.cape.CapeTextureService;
import dev.pixo2000.client.command.CapeConfirmCommand;
import dev.pixo2000.client.command.CapeLoginCommand;
import dev.pixo2000.client.command.CapeRemoveCommand;
import dev.pixo2000.client.command.CapeSetCommand;
import dev.pixo2000.client.config.CredentialsManager;
import java.nio.file.Path;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.api.EnvType;
import net.fabricmc.api.Environment;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.text.Text;

@Environment(EnvType.CLIENT)
public final class VoidcapesClient implements ClientModInitializer {
    @Override
    public void onInitializeClient() {
        CapeTextureService.initialize();
        CapeRefreshManager.initialize();
        initializeCredentials();
        registerCommands();
    }

    private static void initializeCredentials() {
        Path configDir = FabricLoader.getInstance().getConfigDir().resolve(Voidcapes.MOD_ID);
        CapeLoginCommand.setCredentialsManager(new CredentialsManager(configDir));
    }

    private static void registerCommands() {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            dispatcher.register(ClientCommandManager.literal("caperefresh")
                    .executes(ctx -> {
                        int refreshed = CapeRefreshManager.refreshNow();
                        ctx.getSource().sendFeedback(Text.literal(
                                "Refreshing capes for " + refreshed + " player(s)"));
                        return 1;
                    })
                    .then(ClientCommandManager.literal("interval")
                            .then(ClientCommandManager.argument("seconds", IntegerArgumentType.integer(5, 3600))
                                    .executes(ctx -> {
                                        int seconds = IntegerArgumentType.getInteger(ctx, "seconds");
                                        CapeRefreshManager.setRefreshIntervalSeconds(seconds);
                                        ctx.getSource().sendFeedback(Text.literal(
                                                "Cape refresh timer set to " + seconds + "s"));
                                        return 1;
                                    }))));

            CapeLoginCommand.register(dispatcher);
            CapeSetCommand.register(dispatcher);
            CapeRemoveCommand.register(dispatcher);
            CapeConfirmCommand.register(dispatcher);
        });
    }
}
