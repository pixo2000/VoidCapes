# Voidcapes

Voidcapes is a Fabric 1.21.x client mod that fetches player capes from `https://voidcube.de/capes/<uuid>`.
It supports static and animated textures (stacked PNG or GIF), per-player caching, and refresh commands so
capes stay in sync while you are in game.

## Features

- Downloads capes for every player that comes into render distance (prefetch + refresh caching).
- Animated cape support with frame-based timing and optional elytra textures.
- Auto-refresh loop plus `/caperefresh` command with user-defined interval.
- Credential-backed commands (`/capelogin`, `/capeset`, `/caperemove`, `/capeconfirm`) that call the
  VoidCube management API so you can update capes without leaving Minecraft.

## Commands

| Command | Description |
| --- | --- |
| `/capelogin <username> <password>` | Encrypts and stores your API credentials under `.minecraft/config/voidcapes`. |
| `/capecheck` | Shows whether credentials are saved and when. |
| `/capeclear` | Deletes stored credentials and key files. |
| `/capeset <totp> <player> <url>` | Uploads a remote cape for `<player>`. Prompts for confirmation if they already have one. |
| `/caperemove <totp> <player>` | Removes the cape for `<player>` (confirmation required). |
| `/capeconfirm` | Confirms the most recent `/capeset` or `/caperemove` request within 10 seconds. |
| `/caperefresh` | Immediately refreshes all known players. |
| `/caperefresh interval <seconds>` | Changes the automatic refresh cadence (default 300 seconds, min 5). |

## 🎨 Getting a Free Cape

Want a custom cape? It's completely free! Simply message **"Xandarian"** on Discord to request your personalized cape.

## Building the Mod

Requirements: Java 21, Gradle Wrapper (`gradlew` bundle).

```powershell
# from the repository root
./gradlew.bat build
```

The compiled mod will be under `build/libs/voidcapes-<version>.jar`. Copy it into your Fabric client `mods/`
folder alongside Fabric Loader and Fabric API matching the same Minecraft version.

## Targeting Multiple Minecraft Versions

The project currently ships with Fabric 1.21.4 coordinates in `gradle.properties`:

```text
minecraft_version=1.21.4
yarn_mappings=1.21.4+build.8
fabric_version=0.119.4+1.21.4
```

### Building for Minecraft 1.21.4 (default)

1. Ensure the values above are present (they already are in the repo).
2. Run `./gradlew.bat clean build` to produce a 1.21.4-compatible jar.

### Building for Minecraft 1.21.10

1. Visit <https://fabricmc.net/develop> and note the **exact** versions for:
   - `minecraft_version` (set to `1.21.10`).
   - A matching Yarn mapping string, e.g. `1.21.10+build.<n>` once available.
   - Fabric API string `fabric_version=0.<series>+1.21.10` that matches the loader release you install.
2. Edit `gradle.properties` and replace the three values above with the 1.21.10 numbers.
3. (Optional) update `fabric_version`/`loader_version` if Fabric lists newer releases for 1.21.10.
4. Run `./gradlew.bat clean build` – the resulting jar will now target Minecraft 1.21.10.

> **Tip:** keep two branches or local copies if you routinely build for both versions; swapping the
> `gradle.properties` entries and running a clean build is enough to retarget the mod.

## Troubleshooting

- Delete `.gradle/` if Gradle complains about stale metadata after switching Minecraft versions.
- Ensure Fabric Loader and Fabric API installed in your client match the same MC version you built.
- Animated cape glitches usually mean the remote asset lacks a proper stacked PNG or GIF; check logs under
  `.minecraft/logs/latest.log` for decoding errors tagged with `dev.pixo2000.voidcapes`.

