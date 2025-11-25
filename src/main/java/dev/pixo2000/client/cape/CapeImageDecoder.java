package dev.pixo2000.client.cape;

import net.minecraft.client.texture.NativeImage;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.metadata.IIOMetadataNode;
import javax.imageio.stream.ImageInputStream;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Decodes cape textures and detects whether they contain animation frames.
 */
final class CapeImageDecoder {
    private static final int DEFAULT_FRAME_DELAY_MS = 100;

    private CapeImageDecoder() {
    }

    static DecodedCape decode(byte[] imageBytes) throws IOException {
        if (looksLikeGif(imageBytes)) {
            return decodeGif(imageBytes);
        }
        return decodeStackedPngOrStatic(imageBytes);
    }

    private static boolean looksLikeGif(byte[] data) {
        return data.length >= 3 && data[0] == 'G' && data[1] == 'I' && data[2] == 'F';
    }

    private static DecodedCape decodeStackedPngOrStatic(byte[] bytes) throws IOException {
        NativeImage source = NativeImage.read(new ByteArrayInputStream(bytes));
        boolean closeSource = true;
        try {
            int width = source.getWidth();
            int height = source.getHeight();
            int frameHeight = width / 2;
            boolean stacked = frameHeight > 0 && height > frameHeight && height % frameHeight == 0;
            if (stacked) {
                int frameCount = height / frameHeight;
                List<CapeFrame> frames = new ArrayList<>(frameCount);
                for (int frameIndex = 0; frameIndex < frameCount; frameIndex++) {
                    NativeImage frame = new NativeImage(width, frameHeight, true);
                    for (int x = 0; x < width; x++) {
                        for (int y = 0; y < frameHeight; y++) {
                            frame.setColorArgb(x, y, source.getColorArgb(x, y + (frameIndex * frameHeight)));
                        }
                    }
                    frames.add(new CapeFrame(frame, DEFAULT_FRAME_DELAY_MS));
                }
                return new AnimatedCape(frames, Math.floorDiv(width, frameHeight) == 2);
            }

            NativeImage normalized = normalizeCape(source);
            closeSource = false; // normalized now owns the pixels
            boolean hasElytra = Math.floorDiv(normalized.getWidth(), normalized.getHeight()) == 2;
            return new StaticCape(normalized, hasElytra);
        } finally {
            if (closeSource) {
                source.close();
            }
        }
    }

    private static NativeImage normalizeCape(NativeImage source) {
        int srcWidth = source.getWidth();
        int srcHeight = source.getHeight();
        int imageWidth = 64;
        int imageHeight = 32;
        while (imageWidth < srcWidth || imageHeight < srcHeight) {
            imageWidth *= 2;
            imageHeight *= 2;
        }
        NativeImage resized = new NativeImage(imageWidth, imageHeight, true);
        for (int x = 0; x < srcWidth; x++) {
            for (int y = 0; y < srcHeight; y++) {
                resized.setColorArgb(x, y, source.getColorArgb(x, y));
            }
        }
        source.close();
        return resized;
    }

    private static DecodedCape decodeGif(byte[] bytes) throws IOException {
        ImageReader reader = ImageIO.getImageReadersByFormatName("gif").next();
        try (ImageInputStream stream = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            reader.setInput(stream, false, false);
            int frameCount = Math.max(1, reader.getNumImages(true));
            MetadataInfo metadataInfo = resolveStreamMetadata(reader.getStreamMetadata());
            int canvasWidth = metadataInfo.logicalScreenWidth() > 0 ? metadataInfo.logicalScreenWidth() : reader.getWidth(0);
            int canvasHeight = metadataInfo.logicalScreenHeight() > 0 ? metadataInfo.logicalScreenHeight() : reader.getHeight(0);
            BufferedImage canvas = new BufferedImage(canvasWidth, canvasHeight, BufferedImage.TYPE_INT_ARGB);
            Rectangle canvasBounds = new Rectangle(0, 0, canvasWidth, canvasHeight);
            List<CapeFrame> frames = new ArrayList<>(frameCount);

            for (int frameIndex = 0; frameIndex < frameCount; frameIndex++) {
                IIOMetadata frameMetadata = reader.getImageMetadata(frameIndex);
                FrameInfo frameInfo = resolveFrameMetadata(frameMetadata);
                BufferedImage rawFrame = reader.read(frameIndex);

                Rectangle frameArea = new Rectangle(frameInfo.x(), frameInfo.y(), rawFrame.getWidth(), rawFrame.getHeight());
                Rectangle clippedArea = canvasBounds.intersection(frameArea);
                if (clippedArea.isEmpty()) {
                    clippedArea = canvasBounds;
                }

                BufferedImage backup = null;
                if ("restoreToPrevious".equals(frameInfo.disposal())) {
                    backup = copyArea(canvas, clippedArea);
                }

                Graphics2D graphics = canvas.createGraphics();
                graphics.drawImage(rawFrame, frameInfo.x(), frameInfo.y(), null);
                graphics.dispose();

                BufferedImage snapshot = deepCopy(canvas);
                frames.add(new CapeFrame(toNativeImage(snapshot), Math.max(1, frameInfo.delayMs())));

                if ("restoreToBackgroundColor".equals(frameInfo.disposal())) {
                    fillArea(canvas, clippedArea, metadataInfo.backgroundColor());
                } else if ("restoreToPrevious".equals(frameInfo.disposal()) && backup != null) {
                    Graphics2D g = canvas.createGraphics();
                    g.drawImage(backup, clippedArea.x, clippedArea.y, null);
                    g.dispose();
                }
            }

            boolean hasElytra = frames.stream()
                    .findFirst()
                    .map(frame -> Math.floorDiv(frame.image().getWidth(), frame.image().getHeight()) == 2)
                    .orElse(false);
            return new AnimatedCape(frames, hasElytra);
        } finally {
            reader.dispose();
        }
    }

    private static BufferedImage copyArea(BufferedImage source, Rectangle area) {
        BufferedImage copy = new BufferedImage(area.width, area.height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = copy.createGraphics();
        g.drawImage(source, -area.x, -area.y, null);
        g.dispose();
        return copy;
    }

    private static void fillArea(BufferedImage image, Rectangle area, Color backgroundColor) {
        Graphics2D g = image.createGraphics();
        if (backgroundColor == null) {
            g.setComposite(AlphaComposite.Clear);
        } else {
            g.setComposite(AlphaComposite.Src);
            g.setColor(backgroundColor);
        }
        g.fillRect(area.x, area.y, area.width, area.height);
        g.dispose();
    }

    private static BufferedImage deepCopy(BufferedImage source) {
        BufferedImage copy = new BufferedImage(source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = copy.createGraphics();
        g.drawImage(source, 0, 0, null);
        g.dispose();
        return copy;
    }

    private static NativeImage toNativeImage(BufferedImage image) {
        NativeImage nativeImage = new NativeImage(image.getWidth(), image.getHeight(), true);
        for (int x = 0; x < image.getWidth(); x++) {
            for (int y = 0; y < image.getHeight(); y++) {
                nativeImage.setColorArgb(x, y, image.getRGB(x, y));
            }
        }
        return nativeImage;
    }

    private static MetadataInfo resolveStreamMetadata(IIOMetadata metadata) throws IOException {
        if (metadata == null) {
            return new MetadataInfo(-1, -1, null);
        }
        String formatName = metadata.getNativeMetadataFormatName();
        IIOMetadataNode root = (IIOMetadataNode) metadata.getAsTree(formatName);

        int width = -1;
        int height = -1;
        Color backgroundColor = null;

        NodeList screenDescriptors = root.getElementsByTagName("LogicalScreenDescriptor");
        if (screenDescriptors.getLength() > 0) {
            IIOMetadataNode descriptor = (IIOMetadataNode) screenDescriptors.item(0);
            if (descriptor != null) {
                width = parseAttribute(descriptor, "logicalScreenWidth", -1);
                height = parseAttribute(descriptor, "logicalScreenHeight", -1);
            }
        }

        NodeList colorTables = root.getElementsByTagName("GlobalColorTable");
        if (colorTables.getLength() > 0) {
            IIOMetadataNode colorTable = (IIOMetadataNode) colorTables.item(0);
            if (colorTable != null) {
                String backgroundIndex = colorTable.getAttribute("backgroundColorIndex");
                Node entry = colorTable.getFirstChild();
                while (entry != null) {
                    if (entry instanceof IIOMetadataNode node && node.getAttribute("index").equals(backgroundIndex)) {
                        int red = parseAttribute(node, "red", 0);
                        int green = parseAttribute(node, "green", 0);
                        int blue = parseAttribute(node, "blue", 0);
                        backgroundColor = new Color(red, green, blue);
                        break;
                    }
                    entry = entry.getNextSibling();
                }
            }
        }

        return new MetadataInfo(width, height, backgroundColor);
    }

    private static FrameInfo resolveFrameMetadata(IIOMetadata metadata) throws IOException {
        IIOMetadataNode root = (IIOMetadataNode) metadata.getAsTree("javax_imageio_gif_image_1.0");
        Node descriptorNode = root.getElementsByTagName("ImageDescriptor").item(0);
        int x = 0;
        int y = 0;
        if (descriptorNode instanceof IIOMetadataNode descriptor) {
            x = parseAttribute(descriptor, "imageLeftPosition", 0);
            y = parseAttribute(descriptor, "imageTopPosition", 0);
        }

        IIOMetadataNode gce = (IIOMetadataNode) root.getElementsByTagName("GraphicControlExtension").item(0);
        int delay = gce != null ? parseAttribute(gce, "delayTime", 1) : 1;
        String disposal = gce != null ? gce.getAttribute("disposalMethod") : "none";
        return new FrameInfo(x, y, Math.max(1, delay) * 10, disposal);
    }

    private static int parseAttribute(IIOMetadataNode node, String attribute, int fallback) {
        try {
            String value = node.getAttribute(attribute);
            return value == null || value.isEmpty() ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    interface DecodedCape {
        boolean animated();

        boolean hasElytra();
    }

    record StaticCape(NativeImage image, boolean hasElytra) implements DecodedCape {
        @Override
        public boolean animated() {
            return false;
        }
    }

    record AnimatedCape(List<CapeFrame> frames, boolean hasElytra) implements DecodedCape {
        @Override
        public boolean animated() {
            return true;
        }
    }

    record CapeFrame(NativeImage image, int delayMs) {
    }

    private record MetadataInfo(int logicalScreenWidth, int logicalScreenHeight, Color backgroundColor) {
    }

    private record FrameInfo(int x, int y, int delayMs, String disposal) {
    }
}
