package net.litetex.capes.provider;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mojang.authlib.GameProfile;

import net.litetex.capes.provider.antifeature.AntiFeature;
import net.litetex.capes.provider.antifeature.AntiFeatures;
import net.minecraft.client.MinecraftClient;


public class CapeModCapeProvider implements CapeProvider
{
	private static final Logger LOG = LoggerFactory.getLogger(CapeModCapeProvider.class);

	public static final String ID = "capemod";

	@Override
	public String id()
	{
		return ID;
	}

	@Override
	public String name()
	{
		return "CapeMod";
	}

	@Override
	public String getBaseUrl(final GameProfile profile)
	{
		return "https://textures.capemod.com/cape/?uuid=" + profile.id().toString() + "";
	}

	@Override
	public boolean hasChangeCapeUrl()
	{
		return true;
	}

	@Override
	public String changeCapeUrl(final MinecraftClient client)
	{
			return "https://capemod.com/dashboard";

	}

	@Override
	public String homepageUrl()
	{
		return "https://capemod.com/";
	}
}
