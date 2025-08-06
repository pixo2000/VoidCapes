#!/usr/bin/env python3
import sys
import os
from PIL import Image, ImageDraw
import argparse

class MinecraftCapeCreator:
    def __init__(self):
        self.scale = 6  # Max resolution (64 pixels becomes 384 pixels at scale 6)
        self.elytra_image = False  # Default to no elytra
        self.auto_color = True
        self.color = None
        self.mode = "zoom"  # "zoom" (default) or "fit"
        
    def set_elytra_enabled(self, enabled):
        """Enable or disable elytra generation"""
        self.elytra_image = enabled
        
    def set_mode(self, mode):
        """Set image processing mode: 'zoom' (crop to fill) or 'fit' (fit entirely with color fill)"""
        if mode in ["zoom", "fit"]:
            self.mode = mode
        else:
            raise ValueError("Mode must be 'zoom' or 'fit'")
        
    def set_scale(self, scale):
        """Set scale (1-6), where 6 is maximum resolution"""
        self.scale = max(1, min(scale, 6))
        self.actual_scale = 2 ** (self.scale - 1)
    
    def calculate_average_color(self, image):
        """Calculate average color from image for auto-color feature"""
        # Convert to RGB if not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Get pixel data
        pixels = list(image.getdata())
        
        # Sample every 5th pixel for performance (like the JS version)
        sampled_pixels = pixels[::5]
        
        if not sampled_pixels:
            return (128, 128, 128)  # Default gray
            
        # Calculate averages
        r_total = sum(pixel[0] for pixel in sampled_pixels)
        g_total = sum(pixel[1] for pixel in sampled_pixels)
        b_total = sum(pixel[2] for pixel in sampled_pixels)
        
        count = len(sampled_pixels)
        avg_r = r_total // count
        avg_g = g_total // count
        avg_b = b_total // count
        
        return (avg_r, avg_g, avg_b)

    def build_cape(self, input_image_path):
        """Build cape texture from input image"""
        # Set scale to maximum (6)
        self.set_scale(6)
        
        try:
            # Check if input is a GIF
            if input_image_path.lower().endswith('.gif'):
                print("Processing GIF file...")
                return self.build_cape_from_gif(input_image_path)
            else:
                input_img = Image.open(input_image_path)
                return self.build_cape_from_image(input_img)
                
        except Exception as e:
            print(f"Error processing image: {e}")
            return None
    
    def build_cape_from_gif(self, gif_path):
        """Build cape texture from GIF by processing each frame separately"""
        try:
            # Open the GIF
            gif = Image.open(gif_path)
            
            # Extract all frames
            frames = []
            frame_count = 0
            
            try:
                while True:
                    # Copy the current frame
                    frame = gif.copy()
                    # Convert to RGBA to ensure consistent format
                    if frame.mode != 'RGBA':
                        frame = frame.convert('RGBA')
                    frames.append(frame)
                    frame_count += 1
                    
                    # Move to next frame
                    gif.seek(gif.tell() + 1)
            except EOFError:
                # End of GIF reached
                pass
            
            if not frames:
                raise ValueError("No frames found in the GIF")
            
            print(f"Extracted {frame_count} frames from the GIF")
            
            # Process each frame as a separate cape
            cape_textures = []
            for i, frame in enumerate(frames):
                print(f"Processing frame {i + 1}/{len(frames)} as cape texture...")
                cape_texture = self.build_cape_from_image(frame)
                if cape_texture:
                    cape_textures.append(cape_texture)
                else:
                    print(f"Warning: Failed to process frame {i + 1}")
            
            if not cape_textures:
                raise ValueError("No cape textures could be created from GIF frames")
            
            # Stack all cape textures vertically
            cape_width = cape_textures[0].width
            cape_height = cape_textures[0].height
            total_height = cape_height * len(cape_textures)
            
            # Create final canvas
            final_canvas = Image.new('RGBA', (cape_width, total_height), (0, 0, 0, 0))
            
            # Paste each cape texture vertically
            current_y = 0
            for i, cape_texture in enumerate(cape_textures):
                final_canvas.paste(cape_texture, (0, current_y))
                current_y += cape_height
                print(f"Stacked cape texture {i + 1}/{len(cape_textures)}")
            
            print(f"Created final texture with {len(cape_textures)} cape textures stacked vertically")
            return final_canvas
            
        except Exception as e:
            print(f"Error processing GIF: {str(e)}")
            return None
    
    def build_cape_from_image(self, input_img):
        """Build a single cape texture from a PIL Image"""
        # Create the cape canvas (64x32 at max scale)
        canvas_width = 64 * self.actual_scale
        canvas_height = 32 * self.actual_scale
        cape_canvas = Image.new('RGBA', (canvas_width, canvas_height), (0, 0, 0, 0))
        
        # Convert to RGBA for consistency
        if input_img.mode != 'RGBA':
            input_img = input_img.convert('RGBA')
        
        # Calculate cape area dimensions (10x16 pixels at scale)
        cape_width = 10 * self.actual_scale
        cape_height = 16 * self.actual_scale
        
        # Calculate auto color if needed (from original image for fit mode)
        if self.auto_color:
            fill_color = self.calculate_average_color(input_img)
        else:
            fill_color = self.color or (128, 128, 128)
        
        # Process image based on selected mode
        if self.mode == "fit":
            cape_image = self.process_image_fit(input_img, cape_width, cape_height, fill_color)
        else:  # default "zoom" mode
            cape_image = self.process_image_center_zoom(input_img, cape_width, cape_height)
        
        # Paste the cape image onto the canvas at position (1, 1) scaled
        cape_canvas.paste(cape_image, (1 * self.actual_scale, 1 * self.actual_scale))
        
        # Create drawing context
        draw = ImageDraw.Draw(cape_canvas)
        
        # Helper function to draw filled rectangles
        def fill_rect(x, y, w, h):
            x1 = x * self.actual_scale
            y1 = y * self.actual_scale
            x2 = x1 + w * self.actual_scale
            y2 = y1 + h * self.actual_scale
            draw.rectangle([x1, y1, x2-1, y2-1], fill=fill_color)
        
        # Draw cape borders and back
        fill_rect(0, 1, 1, 16)   # Left border
        fill_rect(1, 0, 10, 1)   # Top border
        fill_rect(11, 1, 1, 16)  # Right border
        fill_rect(1, 17, 10, 1)  # Bottom border
        fill_rect(12, 1, 10, 16) # Back of cape
        
        # Draw elytra if enabled
        if self.elytra_image:
            # Paste the same image for elytra (36, 2, 10x20)
            elytra_width = 10 * self.actual_scale
            elytra_height = 20 * self.actual_scale
            
            # Process elytra image using the same mode as cape
            if self.mode == "fit":
                elytra_image = self.process_image_fit(input_img, elytra_width, elytra_height, fill_color)
            else:  # "zoom" mode
                # Use existing zoom logic for elytra
                elytra_img_ratio = input_img.width / input_img.height
                elytra_area_ratio = elytra_width / elytra_height
                
                if elytra_img_ratio > elytra_area_ratio:
                    # Fit to width
                    elytra_new_width = elytra_width
                    elytra_new_height = int(elytra_width / elytra_img_ratio)
                else:
                    # Fit to height
                    elytra_new_height = elytra_height
                    elytra_new_width = int(elytra_height * elytra_img_ratio)
                
                elytra_resized = input_img.resize((elytra_new_width, elytra_new_height), Image.Resampling.LANCZOS)
                
                # Center in elytra area
                elytra_x_offset = (elytra_width - elytra_new_width) // 2
                elytra_y_offset = (elytra_height - elytra_new_height) // 2
                
                elytra_image = Image.new('RGBA', (elytra_width, elytra_height), (0, 0, 0, 0))
                elytra_image.paste(elytra_resized, (elytra_x_offset, elytra_y_offset))
            
            cape_canvas.paste(elytra_image, (36 * self.actual_scale, 2 * self.actual_scale))
        # Note: When elytra is disabled, we don't draw anything in the elytra area
        # The right half will be cleared later
        
        # Draw elytra borders and details only if elytra is enabled
        if self.elytra_image:
            fill_rect(22, 11, 1, 11)  # Inside wing
            fill_rect(31, 0, 3, 1)    # Shoulder
            fill_rect(32, 1, 2, 1)    # Shoulder
            fill_rect(34, 0, 6, 1)    # Bottom
            fill_rect(34, 2, 1, 2)    # Outside wing
            fill_rect(35, 2, 1, 9)    # Outside wing
            
            # Helper function to clear rectangles (make transparent)
            def clear_rect(x, y, w, h):
                x1 = x * self.actual_scale
                y1 = y * self.actual_scale
                x2 = x1 + w * self.actual_scale
                y2 = y1 + h * self.actual_scale
                
                # Paste transparent over the area
                transparent_patch = Image.new('RGBA', (w * self.actual_scale, h * self.actual_scale), (0, 0, 0, 0))
                cape_canvas.paste(transparent_patch, (x1, y1))
            
            # Remove elytra parts (make transparent)
            clear_rect(36, 16, 1, 6)  # Bottom left
            clear_rect(37, 19, 1, 3)  # Bottom left
            clear_rect(38, 21, 1, 1)  # Bottom left
            clear_rect(42, 2, 1, 1)   # Top right
            clear_rect(43, 2, 1, 2)   # Top right
            clear_rect(44, 2, 1, 5)   # Top right
            clear_rect(45, 2, 1, 9)   # Top right
        
        # If elytra is disabled, remove the right half by making all colored pixels transparent
        if not self.elytra_image:
            self.clear_right_half_pixels(cape_canvas)
        
        return cape_canvas
    
    def clear_right_half_pixels(self, image):
        """Remove the right half by making all colored pixels transparent (alpha = 0)"""
        width, height = image.size
        right_half_start = width // 2  # Start of right half
        
        # Load pixel data for direct manipulation
        pixels = image.load()
        
        # Process each pixel in the right half
        for x in range(right_half_start, width):
            for y in range(height):
                # Get current pixel (R, G, B, A)
                pixel = pixels[x, y]
                # Set to fully transparent (keep RGB but set alpha to 0)
                pixels[x, y] = (pixel[0], pixel[1], pixel[2], 0)
    
    def process_image_center_zoom(self, input_img, cape_width, cape_height):
        """Process image in center-zoom mode: crop and zoom to fill the cape area perfectly"""
        img_ratio = input_img.width / input_img.height
        cape_ratio = cape_width / cape_height
        
        if img_ratio > cape_ratio:
            # Image is wider - crop from center horizontally and scale to fill height
            scale_factor = cape_height / input_img.height
            scaled_width = int(input_img.width * scale_factor)
            scaled_height = cape_height
            
            # Resize to fill height
            resized_img = input_img.resize((scaled_width, scaled_height), Image.Resampling.LANCZOS)
            
            # Crop from center horizontally
            crop_x = (scaled_width - cape_width) // 2
            cropped_img = resized_img.crop((crop_x, 0, crop_x + cape_width, cape_height))
        else:
            # Image is taller - crop from center vertically and scale to fill width
            scale_factor = cape_width / input_img.width
            scaled_width = cape_width
            scaled_height = int(input_img.height * scale_factor)
            
            # Resize to fill width
            resized_img = input_img.resize((scaled_width, scaled_height), Image.Resampling.LANCZOS)
            
            # Crop from center vertically
            crop_y = (scaled_height - cape_height) // 2
            cropped_img = resized_img.crop((0, crop_y, cape_width, crop_y + cape_height))
        
        return cropped_img
    
    def process_image_fit(self, input_img, cape_width, cape_height, fill_color):
        """Process image in fit mode: scale to fit entirely inside with color fill for empty areas"""
        img_ratio = input_img.width / input_img.height
        cape_ratio = cape_width / cape_height
        
        # Create background filled with the color
        background = Image.new('RGBA', (cape_width, cape_height), fill_color + (255,))  # Add alpha channel
        
        if img_ratio > cape_ratio:
            # Image is wider - fit to width, center vertically
            new_width = cape_width
            new_height = int(cape_width / img_ratio)
            
            # Resize image to fit
            resized_img = input_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Center vertically
            y_offset = (cape_height - new_height) // 2
            background.paste(resized_img, (0, y_offset), resized_img if resized_img.mode == 'RGBA' else None)
        else:
            # Image is taller or square - fit to height, center horizontally
            new_height = cape_height
            new_width = int(cape_height * img_ratio)
            
            # Resize image to fit
            resized_img = input_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Center horizontally
            x_offset = (cape_width - new_width) // 2
            background.paste(resized_img, (x_offset, 0), resized_img if resized_img.mode == 'RGBA' else None)
        
        return background

    def save_cape(self, cape_image, output_path):
        """Save the cape image"""
        if cape_image:
            cape_image.save(output_path, 'PNG')
            print(f"Cape saved as: {output_path}")
            return True
        return False

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Create Minecraft cape textures from images or GIFs")
    parser.add_argument("input", help="Input image file (.png, .jpg, .gif, etc.)")
    parser.add_argument("--elytra", action="store_true", help="Enable elytra generation (disabled by default)")
    parser.add_argument("--mode", choices=["zoom", "fit"], default="zoom", 
                       help="Image processing mode: 'zoom' (crop to fill, default) or 'fit' (fit entirely with color fill)")
    parser.add_argument("-o", "--output", help="Output filename (optional)")
    
    # If no arguments provided, fall back to simple usage
    if len(sys.argv) == 1:
        print("Usage: python capecreator.py <input_image> [--elytra] [--mode {zoom,fit}] [-o output_file]")
        print("Examples:")
        print("  python capecreator.py image.png")
        print("  python capecreator.py image.png --mode fit")
        print("  python capecreator.py animation.gif --elytra --mode fit")
        print("  python capecreator.py logo.jpg -o custom_cape.png --mode zoom")
        print("\nModes:")
        print("  zoom: Center-crop and zoom to fill the cape area perfectly (default)")
        print("  fit:  Fit the entire image inside with auto-color fill for empty areas")
        sys.exit(1)
    
    # Handle old-style single argument for backwards compatibility
    if len(sys.argv) == 2 and not sys.argv[1].startswith('-'):
        input_path = sys.argv[1]
        enable_elytra = False  # Default to no elytra
        mode = "zoom"  # Default mode
        output_path = None
    else:
        args = parser.parse_args()
        input_path = args.input
        enable_elytra = args.elytra  # Use the elytra flag directly
        mode = args.mode  # Get the selected mode
        output_path = args.output
    
    # Check if input file exists
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        sys.exit(1)
    
    # Generate output filename if not provided
    if output_path is None:
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        elytra_suffix = "_with_elytra" if enable_elytra else ""
        mode_suffix = f"_{mode}" if mode != "zoom" else ""
        output_path = f"{base_name}_cape{elytra_suffix}{mode_suffix}.png"
    
    # Create cape creator and process image
    creator = MinecraftCapeCreator()
    creator.set_elytra_enabled(enable_elytra)
    creator.set_mode(mode)
    
    # Show processing info
    file_type = "GIF" if input_path.lower().endswith('.gif') else "image"
    elytra_status = "with elytra" if enable_elytra else "without elytra"
    mode_description = "center-zoom (crop to fill)" if mode == "zoom" else "fit mode (fit entirely with color fill)"
    print(f"Processing {file_type} {elytra_status} using {mode_description}...")
    
    cape_image = creator.build_cape(input_path)
    
    if cape_image:
        creator.save_cape(cape_image, output_path)
        print(f"Successfully created cape texture at maximum resolution!")
        print(f"Canvas size: {cape_image.width}x{cape_image.height} pixels")
        if mode == "zoom":
            print("Note: Image is center-cropped and zoomed to fill the cape front perfectly")
        else:
            print("Note: Image is fitted entirely inside with auto-color fill for empty areas")
        if input_path.lower().endswith('.gif'):
            print("Note: Each GIF frame was processed as a separate cape texture and stacked vertically")
        if not enable_elytra:
            print("Note: Right half of texture is transparent (no elytra)")
    else:
        print("Failed to create cape texture.")
        sys.exit(1)

if __name__ == "__main__":
    main()
