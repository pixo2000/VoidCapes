package dev.pixo2000.client.cape;

import net.minecraft.util.AssetInfo;
import net.minecraft.util.Identifier;

record CapeTextureAsset(Identifier id) implements AssetInfo.TextureAsset {
    @Override
    public Identifier texturePath() {
        return id;
    }
}
