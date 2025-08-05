from PIL import Image
import os
import sys

def gif_to_vertical_collage(gif_path, output_path=None):
    """
    Extract frames from a GIF and create a vertical collage PNG.
    
    Args:
        gif_path (str): Path to the input GIF file
        output_path (str): Path for the output PNG file (optional)
    
    Returns:
        str: Path to the created PNG file
    """
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
        
        # Get dimensions of the first frame
        frame_width, frame_height = frames[0].size
        
        # Calculate total height for the collage
        total_height = frame_height * len(frames)
        
        # Create a new image with the calculated dimensions
        collage = Image.new('RGBA', (frame_width, total_height), (255, 255, 255, 0))
        
        # Paste each frame vertically
        current_y = 0
        for i, frame in enumerate(frames):
            collage.paste(frame, (0, current_y))
            current_y += frame_height
            print(f"Pasted frame {i + 1}/{len(frames)}")
        
        # Generate output path if not provided
        if output_path is None:
            base_name = os.path.splitext(os.path.basename(gif_path))[0]
            output_dir = os.path.dirname(gif_path)
            output_path = os.path.join(output_dir, f"{base_name}_collage.png")
        
        # Save the collage as PNG
        collage.save(output_path, 'PNG')
        print(f"Collage saved as: {output_path}")
        
        return output_path
        
    except FileNotFoundError:
        print(f"Error: Could not find the file '{gif_path}'")
        return None
    except Exception as e:
        print(f"Error processing GIF: {str(e)}")
        return None

def main():
    """Main function to handle command line arguments or interactive input."""
    
    if len(sys.argv) > 1:
        # Use command line argument
        gif_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        # Interactive input
        gif_path = input("Enter the path to your GIF file: ").strip()
        
        # Remove quotes if present
        if gif_path.startswith('"') and gif_path.endswith('"'):
            gif_path = gif_path[1:-1]
        
        output_path = input("Enter output path (press Enter for auto-generated name): ").strip()
        if not output_path:
            output_path = None
        elif output_path.startswith('"') and output_path.endswith('"'):
            output_path = output_path[1:-1]
    
    # Check if input file exists
    if not os.path.exists(gif_path):
        print(f"Error: File '{gif_path}' does not exist")
        return
    
    # Check if it's a GIF file
    if not gif_path.lower().endswith('.gif'):
        print("Warning: File doesn't have .gif extension. Proceeding anyway...")
    
    # Process the GIF
    result = gif_to_vertical_collage(gif_path, output_path)
    
    if result:
        print(f"\nSuccess! Vertical collage created: {result}")
    else:
        print("\nFailed to create collage.")

if __name__ == "__main__":
    main()
