package dev.pixo2000.mixin.client;

import dev.pixo2000.client.cape.CapeTextureService;
import net.fabricmc.api.EnvType;
import net.fabricmc.api.Environment;
import net.minecraft.client.network.AbstractClientPlayerEntity;
import net.minecraft.client.util.SkinTextures;
import net.minecraft.util.Identifier;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Environment(EnvType.CLIENT)
@Mixin(AbstractClientPlayerEntity.class)
public abstract class AbstractClientPlayerEntityMixin {
    @Inject(method = "getSkinTextures", at = @At("RETURN"), cancellable = true)
    private void voidcapes$injectCapeTexture(CallbackInfoReturnable<SkinTextures> cir) {
        AbstractClientPlayerEntity self = (AbstractClientPlayerEntity) (Object) this;
        Identifier customCape = CapeTextureService.getCapeTexture(self);
        if (customCape == null) {
            return;
        }

        SkinTextures original = cir.getReturnValue();
        if (original == null) {
            return;
        }

        Identifier elytraTexture = CapeTextureService.hasElytraTexture(self)
            ? customCape
            : original.elytraTexture();
        SkinTextures updated = new SkinTextures(
                original.texture(),
                original.textureUrl(),
                customCape,
            elytraTexture,
                original.model(),
                original.secure()
        );
        cir.setReturnValue(updated);
    }
}
