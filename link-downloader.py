import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import os
import re
from urllib.parse import urlparse
import threading

class CapeDownloaderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cape Downloader")
        self.root.geometry("600x400")
        self.root.resizable(True, True)
        
        # Variables
        self.download_folder = tk.StringVar(value=os.getcwd())
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Cape Downloader", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # URL input
        ttk.Label(main_frame, text="Cape URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Download folder selection
        ttk.Label(main_frame, text="Download to:").grid(row=2, column=0, sticky=tk.W, pady=5)
        folder_frame = ttk.Frame(main_frame)
        folder_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        folder_frame.columnconfigure(0, weight=1)
        
        self.folder_entry = ttk.Entry(folder_frame, textvariable=self.download_folder, state="readonly")
        self.folder_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(folder_frame, text="Browse", command=self.browse_folder)
        browse_btn.grid(row=0, column=1)
        
        # Download button
        self.download_btn = ttk.Button(main_frame, text="Download Cape", command=self.start_download)
        self.download_btn.grid(row=3, column=1, pady=20, sticky=tk.W)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status text
        self.status_text = tk.Text(main_frame, height=10, width=70)
        self.status_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.status_text.yview)
        scrollbar.grid(row=5, column=3, sticky=(tk.N, tk.S), pady=(10, 0))
        self.status_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure text widget grid
        main_frame.rowconfigure(5, weight=1)
        
        # Bind Enter key to download
        self.url_entry.bind('<Return>', lambda e: self.start_download())
        
        # Add example text
        example_text = """Supported URLs:
• skinmc.net: https://skinmc.net/cape/91129
• minecraftcapes.net: https://minecraftcapes.net/gallery/[hash]

The downloader will automatically convert these URLs to the correct download format."""
        
        self.log_message(example_text)
        
    def browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self.download_folder.get())
        if folder:
            self.download_folder.set(folder)
    
    def log_message(self, message):
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_log(self):
        self.status_text.delete(1.0, tk.END)
    
    def convert_url_to_download(self, url):
        """Convert various cape URLs to download URLs"""
        url = url.strip()
        
        # Handle skinmc.net URLs
        if "skinmc.net/cape/" in url:
            if not url.endswith("/download"):
                return url + "/download"
            return url
        
        # Handle minecraftcapes.net URLs
        elif "minecraftcapes.net/gallery/" in url:
            # Extract the hash from the URL
            match = re.search(r'minecraftcapes\.net/gallery/([a-f0-9]+)', url)
            if match:
                cape_hash = match.group(1)
                return f"https://api.minecraftcapes.net/api/gallery/{cape_hash}/download"
        
        # Return as-is if already a download URL or unknown format
        return url
    
    def get_filename_from_url(self, url, response=None):
        """Generate a filename for the downloaded cape"""
        # Try to get filename from Content-Disposition header
        if response and 'content-disposition' in response.headers:
            content_disp = response.headers['content-disposition']
            filename_match = re.search(r'filename[^;=\n]*=(([\'"]).*?\2|[^;\n]*)', content_disp)
            if filename_match:
                filename = filename_match.group(1).strip('"\'')
                if filename:
                    return filename
        
        # Generate filename based on URL
        parsed_url = urlparse(url)
        
        if "skinmc.net" in url:
            cape_id = re.search(r'/cape/(\d+)', url)
            if cape_id:
                return f"skinmc_cape_{cape_id.group(1)}.png"
        
        elif "minecraftcapes.net" in url or "api.minecraftcapes.net" in url:
            cape_hash = re.search(r'([a-f0-9]{64})', url)
            if cape_hash:
                return f"mcm_cape_{cape_hash.group(1)[:8]}.png"
        
        # Fallback
        return "cape.png"
    
    def download_cape(self, url):
        """Download the cape file"""
        try:
            download_url = self.convert_url_to_download(url)
            self.log_message(f"Original URL: {url}")
            self.log_message(f"Download URL: {download_url}")
            
            # Make the request
            self.log_message("Starting download...")
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Check if it's an image
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('image/'):
                self.log_message(f"Warning: Content type is {content_type}, expected image")
            
            # Get filename
            filename = self.get_filename_from_url(url, response)
            filepath = os.path.join(self.download_folder.get(), filename)
            
            # Save the file
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            file_size = os.path.getsize(filepath)
            self.log_message(f"✅ Successfully downloaded: {filename}")
            self.log_message(f"   File size: {file_size:,} bytes")
            self.log_message(f"   Saved to: {filepath}")
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.log_message(f"❌ Network error: {str(e)}")
            return False
        except Exception as e:
            self.log_message(f"❌ Error: {str(e)}")
            return False
    
    def download_worker(self, url):
        """Worker function for downloading in a separate thread"""
        try:
            self.download_btn.config(state="disabled")
            self.progress.start()
            
            success = self.download_cape(url)
            
            if success:
                messagebox.showinfo("Success", "Cape downloaded successfully!")
            else:
                messagebox.showerror("Error", "Failed to download cape. Check the log for details.")
                
        finally:
            self.progress.stop()
            self.download_btn.config(state="normal")
    
    def start_download(self):
        """Start the download process"""
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        if not os.path.exists(self.download_folder.get()):
            messagebox.showerror("Error", "Download folder does not exist")
            return
        
        # Clear previous log and start download
        self.clear_log()
        self.log_message("=" * 60)
        self.log_message("Starting cape download...")
        self.log_message("=" * 60)
        
        # Start download in a separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.download_worker, args=(url,))
        thread.daemon = True
        thread.start()

def main():
    root = tk.Tk()
    app = CapeDownloaderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()