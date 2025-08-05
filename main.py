from flask import Flask, render_template, send_file, request, redirect, flash, jsonify, session
import os
import requests
import json
from datetime import datetime, timedelta
import threading
import time
from werkzeug.utils import secure_filename
import re
from urllib.parse import urlparse
import tempfile
import shutil
from PIL import Image
import hashlib
import pyotp
import qrcode
import io
import base64
import sys

def load_config():
    """Load configuration from config.json file"""
    config_file = os.path.join(os.path.dirname(__file__), 'config.json')
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validate required sections
        if 'login_credentials' not in config:
            print("❌ Error: 'login_credentials' section missing from config.json")
            sys.exit(1)
        
        if 'totp_secrets' not in config:
            print("❌ Error: 'totp_secrets' section missing from config.json")
            sys.exit(1)
        
        # Validate that both sections have matching users
        login_users = set(config['login_credentials'].keys())
        totp_users = set(config['totp_secrets'].keys())
        
        if login_users != totp_users:
            print(f"❌ Error: Mismatch between login users ({login_users}) and TOTP users ({totp_users})")
            print("   Both sections must have the same usernames")
            sys.exit(1)
        
        if not login_users:
            print("❌ Error: No users configured in config.json")
            sys.exit(1)
        
        print(f"✅ Configuration loaded successfully for {len(login_users)} user(s): {', '.join(login_users)}")
        return config
        
    except FileNotFoundError:
        print(f"❌ Error: Configuration file not found: {config_file}")
        print("   Please create a config.json file with the following structure:")
        print("   {")
        print('       "login_credentials": {')
        print('           "admin": "your_password_here"')
        print("       },")
        print('       "totp_secrets": {')
        print('           "admin": "your_totp_secret_here"')
        print("       }")
        print("   }")
        sys.exit(1)
        
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in config file: {e}")
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        sys.exit(1)

# Load configuration from external file
config = load_config()
LOGIN_CREDENTIALS = config['login_credentials']
TOTP_SECRETS = config['totp_secrets']

app = Flask(__name__)
app.secret_key = 'minecraft_capes_secret_key_2025'  # For flash messages and sessions
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration
CAPES_DIR = "/var/www/html/capes"
PORT = 4563
ALLOWED_EXTENSIONS = {'png', 'gif'}
SESSION_TIMEOUT = 600  # 10 minutes in seconds

def check_auth():
    """Check if user is authenticated and session hasn't expired"""
    if not session.get('authenticated', False):
        return False
    
    # Check session timeout
    last_activity = session.get('last_activity', 0)
    current_time = time.time()
    
    if current_time - last_activity > SESSION_TIMEOUT:
        print(f"⏰ Session expired for user {session.get('username', 'unknown')}")
        session.clear()
        return False
    
    # Update last activity time
    session['last_activity'] = current_time
    return True

def get_totp_secret(username):
    """Get TOTP secret for user"""
    return TOTP_SECRETS.get(username, None)

def verify_totp(username, token):
    """Verify TOTP token for user"""
    secret = get_totp_secret(username)
    if not secret:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=2)  # Allow 2 windows for clock drift

def generate_qr_code(username):
    """Generate QR code for TOTP setup"""
    secret = get_totp_secret(username)
    if not secret:
        return None
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="VoidCapes"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()

def hash_password(password):
    """Simple password hashing for comparison"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.before_request
def require_login():
    """Require login for all routes except login and API endpoints"""
    # Skip authentication for API endpoints and login page
    if request.endpoint and (request.endpoint == 'login' or 
                            request.endpoint == 'api_check_cape' or 
                            request.endpoint == 'api_download_cape'):
        return
    
    if not check_auth():
        # Clear any remaining session data
        if session.get('authenticated'):
            print("🔒 Session expired, redirecting to login")
            flash('Your session has expired. Please log in again.', 'warning')
        return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Check credentials
        if username in LOGIN_CREDENTIALS and LOGIN_CREDENTIALS[username] == password:
            session['authenticated'] = True
            session['username'] = username
            session['last_activity'] = time.time()  # Set initial activity time
            print(f"👤 User {username} logged in successfully")
            flash(f'Welcome, {username}!', 'success')
            return redirect('/')
        else:
            print(f"❌ Failed login attempt for username: {username}")
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'unknown')
    print(f"👋 User {username} logged out")
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')

@app.route('/session_status')
def session_status():
    """Check session status for client-side timeout management"""
    if not check_auth():
        return jsonify({'authenticated': False})
    
    last_activity = session.get('last_activity', 0)
    current_time = time.time()
    time_remaining = SESSION_TIMEOUT - (current_time - last_activity)
    
    return jsonify({
        'authenticated': True,
        'time_remaining': max(0, time_remaining),
        'username': session.get('username')
    })

@app.route('/verify_totp', methods=['POST'])
def verify_totp_route():
    """Verify TOTP token for editing operations"""
    print("🔐 TOTP verification request received")
    
    if not check_auth():
        print("❌ User not authenticated")
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    token = request.form.get('totp_token', '').strip()
    username = session.get('username')
    
    print(f"👤 TOTP verification for user: {username}")
    print(f"🔢 TOTP token received: {token[:3]}*** (length: {len(token)})")
    
    if not token:
        print("❌ No TOTP token provided")
        return jsonify({'success': False, 'error': 'TOTP token required'})
    
    if verify_totp(username, token):
        # Set a temporary flag that TOTP was verified for this session
        session['totp_verified'] = True
        session['totp_verified_time'] = time.time()
        session.permanent = True  # Ensure session is saved immediately
        print(f"✅ TOTP verification successful at {session['totp_verified_time']}")
        return jsonify({'success': True})
    else:
        print("❌ TOTP verification failed")
        return jsonify({'success': False, 'error': 'Invalid TOTP token'})

@app.route('/setup_totp')
def setup_totp():
    """Show TOTP setup page with QR code"""
    if not check_auth():
        return redirect('/login')
    
    username = session.get('username')
    qr_code = generate_qr_code(username)
    secret = get_totp_secret(username)
    
    return render_template('totp_setup.html', qr_code=qr_code, secret=secret, username=username)

def require_totp_for_edit():
    """Check if TOTP verification is required for editing operations"""
    if not check_auth():
        print("❌ User not authenticated for TOTP check")
        return False
    
    # Check if TOTP was verified recently (within 5 minutes)
    totp_time = session.get('totp_verified_time', 0)
    current_time = time.time()
    time_since_verification = current_time - totp_time
    
    print(f"🕐 TOTP verification check: {time_since_verification:.1f} seconds ago")
    
    if time_since_verification < 300:  # 5 minutes
        print("✅ TOTP verification still valid")
        return True
    
    # Clear the verification flag if it's expired
    session.pop('totp_verified', None)
    session.pop('totp_verified_time', None)
    print("❌ TOTP verification expired, clearing session")
    return False

# Cache for player names to avoid excessive API calls
player_name_cache = {}
cache_lock = threading.Lock()

def get_player_name(uuid):
    """Get Minecraft player name from UUID using Mojang API with caching."""
    with cache_lock:
        # Check if we have a cached name
        if uuid in player_name_cache:
            cached_data = player_name_cache[uuid]
            # Cache for 1 hour
            if datetime.now() - cached_data['timestamp'] < timedelta(hours=1):
                return cached_data['name']
    
    try:
        # Clean UUID (remove dashes if present)
        clean_uuid = uuid.replace('-', '')
        
        # Mojang API endpoint
        url = f"https://sessionserver.mojang.com/session/minecraft/profile/{clean_uuid}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            player_name = data.get('name', f'Unknown ({uuid[:8]})')
            
            # Cache the result
            with cache_lock:
                player_name_cache[uuid] = {
                    'name': player_name,
                    'timestamp': datetime.now()
                }
            
            return player_name
        else:
            return f"Unknown ({uuid[:8]})"
            
    except Exception as e:
        print(f"Error fetching player name for {uuid}: {e}")
        return f"Unknown ({uuid[:8]})"

def get_uuid_from_playername(player_name):
    """Get UUID from Minecraft player name using Mojang API."""
    try:
        # Mojang API endpoint for username to UUID
        url = f"https://api.mojang.com/users/profiles/minecraft/{player_name}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            uuid = data.get('id')
            if uuid:
                # Format UUID with dashes for proper display
                formatted_uuid = f"{uuid[:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:]}"
                return formatted_uuid
            return None
        else:
            return None
            
    except Exception as e:
        print(f"Error fetching UUID for player {player_name}: {e}")
        return None

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def gif_to_vertical_collage(gif_path, output_path=None):
    """Convert GIF to vertical collage PNG (from giftocape.py)"""
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
        
        # Generate output path if not provided
        if output_path is None:
            base_name = os.path.splitext(os.path.basename(gif_path))[0]
            output_dir = os.path.dirname(gif_path)
            output_path = os.path.join(output_dir, f"{base_name}_collage.png")
        
        # Save the collage as PNG
        collage.save(output_path, 'PNG')
        print(f"Collage saved as: {output_path}")
        
        # Save frame metadata for animation
        metadata_path = output_path + '.meta'
        metadata = {
            'frame_count': frame_count,
            'frame_width': frame_width,
            'frame_height': frame_height,
            'is_animated': True
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        return output_path
        
    except Exception as e:
        print(f"Error processing GIF: {str(e)}")
        return None

def convert_url_to_download(url):
    """Convert various cape URLs to download URLs"""
    url = url.strip()
    print(f"Converting URL: {url}")
    
    # Handle skinmc.net URLs
    if "skinmc.net/cape/" in url:
        # Extract cape ID from URL like https://skinmc.net/cape/91129
        match = re.search(r'skinmc\.net/cape/(\d+)', url)
        if match:
            cape_id = match.group(1)
            result = f"https://skinmc.net/capes/{cape_id}/download"
            print(f"skinmc.net conversion: {url} -> {result}")
            return result
        elif not url.endswith("/download"):
            result = url + "/download"
            print(f"skinmc.net fallback: {url} -> {result}")
            return result
        return url
    
    # Handle minecraftcapes.net URLs
    elif "minecraftcapes.net/gallery/" in url:
        # Extract the hash from the URL
        match = re.search(r'minecraftcapes\.net/gallery/([a-f0-9]+)', url)
        if match:
            cape_hash = match.group(1)
            result = f"https://api.minecraftcapes.net/api/gallery/{cape_hash}/download"
            print(f"minecraftcapes.net conversion: {url} -> {result}")
            return result
    
    # Handle misterlauncher.org URLs (both old and new formats)
    elif "misterlauncher.org" in url and "/cape/" in url:
        # New format: https://misterlauncher.org/en/cape/c39c70d85ddba5e7f68d2ca92f0ff5180a9ef4ec/
        # Old format: https://misterlauncher.org/cape/39c7029d0f05102e15a04d1b93c332d336e3ee08/
        
        # Extract hash from both formats
        match = re.search(r'misterlauncher\.org/(?:en/)?cape/([a-f0-9]+)', url)
        if match:
            cape_hash = match.group(1)
            # Use the old format for download URL
            base_url = f"https://misterlauncher.org/cape/{cape_hash}"
            if not url.endswith("/download") and not url.endswith("/download/"):
                result = base_url + "/download/"
                print(f"misterlauncher.org conversion: {url} -> {result}")
                return result
            elif url.endswith("/download"):
                result = base_url + "/download/"
                print(f"misterlauncher.org adding trailing slash: {url} -> {result}")
                return result
        
        # Fallback for existing URLs
        if not url.endswith("/download") and not url.endswith("/download/"):
            # Remove trailing slash if present, then add /download/
            url = url.rstrip('/')
            result = url + "/download/"
            print(f"misterlauncher.org fallback conversion: {url} -> {result}")
            return result
        elif url.endswith("/download"):
            # Add trailing slash if missing
            result = url + "/"
            print(f"misterlauncher.org adding trailing slash: {url} -> {result}")
            return result
        print(f"misterlauncher.org already has /download/: {url}")
        return url
    
    # Return as-is if already a download URL or unknown format
    print(f"No conversion needed: {url}")
    return url

def download_cape_from_url(url, player_name):
    """Download a cape from URL and save it for a player"""
    try:
        download_url = convert_url_to_download(url)
        print(f"Original URL: {url}")
        print(f"Download URL: {download_url}")
        
        # Make the request
        response = requests.get(download_url, stream=True, timeout=30)
        
        # More detailed error handling
        if response.status_code == 404:
            return False, f"Cape not found at URL (404 error). Please check the URL is correct."
        elif response.status_code == 403:
            return False, f"Access denied (403 error). The cape might be private or the URL is incorrect."
        elif response.status_code == 500:
            return False, f"Server error (500 error). The cape site might be experiencing issues."
        elif response.status_code != 200:
            return False, f"HTTP error {response.status_code}: {response.reason}"
        
        response.raise_for_status()
        
        # Check if it's an image
        content_type = response.headers.get('content-type', '')
        print(f"Content type: {content_type}")
        
        if not content_type.startswith('image/'):
            # Provide more specific error messages based on content type
            if content_type.startswith('text/html'):
                if "skinmc.net" in url:
                    return False, f"Got HTML page instead of image from skinmc.net. The cape might not exist or the URL format might be incorrect. Try a direct cape URL like: https://skinmc.net/cape/12345"
                elif "minecraftcapes.net" in url:
                    return False, f"Got HTML page instead of image from minecraftcapes.net. Make sure you're using a gallery URL like: https://minecraftcapes.net/gallery/[hash]"
                elif "misterlauncher.org" in url:
                    return False, f"Got HTML page instead of image from misterlauncher.org. Make sure you're using a cape URL like: https://misterlauncher.org/cape/[hash]/ (the converted download URL should be: {download_url})"
                else:
                    return False, f"Downloaded content is a webpage (HTML) instead of an image. The URL might be pointing to a webpage rather than a direct image link."
            elif content_type.startswith('text/'):
                return False, f"Downloaded content is text ({content_type}) instead of an image. The URL might be incorrect or the server returned an error message."
            else:
                return False, f"Downloaded content is not an image (got {content_type}). URL might be incorrect or not pointing to an image file."
        
        # Check content length
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            return False, f"File too large ({int(content_length) / 1024 / 1024:.1f}MB). Maximum size is 10MB."
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    temp_file.write(chunk)
                    total_size += len(chunk)
                    # Safety check during download
                    if total_size > 10 * 1024 * 1024:  # 10MB limit
                        temp_file.close()
                        os.remove(temp_file.name)
                        return False, "File too large (>10MB). Download cancelled."
            temp_path = temp_file.name
        
        print(f"Downloaded {total_size} bytes")
        
        # Check if it's a GIF and convert if necessary
        if content_type == 'image/gif':
            print("Detected GIF, converting to cape format...")
            converted_path = gif_to_vertical_collage(temp_path)
            if converted_path and os.path.exists(converted_path):
                os.remove(temp_path)  # Remove original GIF
                temp_path = converted_path
                print("GIF conversion successful")
            else:
                os.remove(temp_path)
                return False, "Failed to convert GIF to cape format. The GIF might be corrupted or in an unsupported format."
        
        # Get UUID from player name
        uuid = get_uuid_from_playername(player_name)
        if not uuid:
            os.remove(temp_path)
            return False, f'Player "{player_name}" not found. Please check the spelling and make sure it\'s a valid Minecraft username.'
        
        # Create capes directory if it doesn't exist
        os.makedirs(CAPES_DIR, exist_ok=True)
        
        # Move the file to final location
        cape_path = os.path.join(CAPES_DIR, uuid)
        metadata_path = cape_path + '.meta'
        
        # Remove old metadata file if it exists (for cape replacement)
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        shutil.move(temp_path, cape_path)
        
        # Set correct Linux permissions: -rw-r--r-- (644)
        try:
            os.chmod(cape_path, 0o644)
        except OSError:
            pass  # Skip if on Windows or permission error
        
        # Also move metadata file if it exists (for GIF conversions)
        metadata_src = temp_path + '.meta'
        metadata_dst = cape_path + '.meta'
        if os.path.exists(metadata_src):
            shutil.move(metadata_src, metadata_dst)
            # Set permissions for metadata file too
            try:
                os.chmod(metadata_dst, 0o644)
            except OSError:
                pass
        
        # Clear cache for this UUID
        with cache_lock:
            if uuid in player_name_cache:
                del player_name_cache[uuid]
        
        return True, f'Cape downloaded successfully for player "{player_name}" ({total_size} bytes)'
        
    except requests.exceptions.Timeout:
        return False, "Download timed out. The server might be slow or unreachable."
    except requests.exceptions.ConnectionError:
        return False, "Connection error. Please check your internet connection and that the URL is accessible."
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}"
    except Exception as e:
        print(f"Unexpected error in download_cape_from_url: {e}")
        return False, f"Unexpected error: {str(e)}"

def get_cape_files():
    """Get list of cape files from the capes directory."""
    print(f"🔍 Checking for capes in directory: {CAPES_DIR}")
    
    if not os.path.exists(CAPES_DIR):
        print(f"❌ Capes directory does not exist: {CAPES_DIR}")
        return []
    
    try:
        files = os.listdir(CAPES_DIR)
        print(f"📁 Found {len(files)} files in capes directory: {files}")
    except Exception as e:
        print(f"❌ Error reading capes directory: {e}")
        return []
    
    capes = []
    for filename in files:
        # Skip metadata files
        if filename.endswith('.meta'):
            print(f"⏭️ Skipping metadata file: {filename}")
            continue
            
        file_path = os.path.join(CAPES_DIR, filename)
        if os.path.isfile(file_path):
            # The filename should be the UUID (without .png extension)
            uuid = filename
            print(f"🔍 Processing cape file: {filename} (UUID: {uuid})")
            
            try:
                player_name = get_player_name(uuid)
                print(f"👤 Player name for {uuid}: {player_name}")
                
                capes.append({
                    'uuid': uuid,
                    'player_name': player_name,
                    'filename': filename
                })
                print(f"✅ Added cape: {player_name} ({uuid})")
            except Exception as e:
                print(f"❌ Error processing cape {uuid}: {e}")
        else:
            print(f"⏭️ Skipping non-file: {filename}")
    
    print(f"📊 Total capes found: {len(capes)}")
    return sorted(capes, key=lambda x: x['player_name'].lower())

@app.route('/')
def index():
    """Main page showing all capes."""
    print("🏠 Index page requested")
    capes = get_cape_files()
    print(f"📊 Returning {len(capes)} capes to template")
    return render_template('index.html', capes=capes, total_count=len(capes))

@app.route('/cape/<uuid>')
def serve_cape(uuid):
    """Serve a cape image file."""
    cape_path = os.path.join(CAPES_DIR, uuid)
    
    if os.path.exists(cape_path):
        return send_file(cape_path, mimetype='image/png')
    else:
        return "Cape not found", 404

@app.route('/cape_meta/<uuid>')
def serve_cape_metadata(uuid):
    """Serve cape metadata for animated capes."""
    metadata_path = os.path.join(CAPES_DIR, uuid + '.meta')
    
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            return jsonify(metadata)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'is_animated': False})

@app.route('/refresh')
def refresh():
    """Refresh the cache and reload the page."""
    global player_name_cache
    with cache_lock:
        player_name_cache.clear()
    flash('Player name cache refreshed!', 'success')
    return redirect('/')

@app.route('/delete_cape/<uuid>', methods=['GET', 'POST'])
def delete_cape(uuid):
    """Delete a cape file."""
    print(f"🗑️ Delete cape request for UUID: {uuid}")
    print(f"📋 Request method: {request.method}")
    
    # Check TOTP verification for editing operations
    if not require_totp_for_edit():
        print("❌ TOTP verification required for delete")
        flash('TOTP verification required for editing operations.', 'error')
        return redirect('/')
    
    cape_path = os.path.join(CAPES_DIR, uuid)
    metadata_path = cape_path + '.meta'
    
    if os.path.exists(cape_path):
        try:
            os.remove(cape_path)
            # Also remove metadata file if it exists
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            # Clear cache for this UUID
            with cache_lock:
                if uuid in player_name_cache:
                    del player_name_cache[uuid]
            print(f"🗑️ Cape deleted successfully for UUID: {uuid}")
            flash('Cape deleted successfully!', 'success')
        except Exception as e:
            print(f"❌ Error deleting cape: {e}")
            flash(f'Error deleting cape: {str(e)}', 'error')
    else:
        flash('Cape not found!', 'error')
    
    return redirect('/')

@app.route('/duplicate_cape/<uuid>', methods=['GET', 'POST'])
def duplicate_cape(uuid):
    """Duplicate a cape for another player."""
    if request.method == 'POST':
        # Check TOTP verification for editing operations
        if not require_totp_for_edit():
            print("❌ TOTP verification required for duplicate")
            flash('TOTP verification required for editing operations.', 'error')
            return redirect('/')
        
        new_player_name = request.form.get('new_player_name', '').strip()
        if not new_player_name:
            flash('Please enter a player name for the duplicate.', 'error')
            return redirect('/')
        
        # Get UUID from new player name
        new_uuid = get_uuid_from_playername(new_player_name)
        if not new_uuid:
            flash(f'Player "{new_player_name}" not found. Please check the spelling.', 'error')
            return redirect('/')
        
        # Check if new player already has a cape
        new_cape_path = os.path.join(CAPES_DIR, new_uuid)
        if os.path.exists(new_cape_path):
            flash(f'Player "{new_player_name}" already has a cape!', 'warning')
            return redirect('/')
        
        # Copy the cape file
        original_cape_path = os.path.join(CAPES_DIR, uuid)
        if os.path.exists(original_cape_path):
            try:
                shutil.copy2(original_cape_path, new_cape_path)
                
                # Set correct Linux permissions: -rw-r--r-- (644)
                try:
                    os.chmod(new_cape_path, 0o644)
                except OSError:
                    pass  # Skip if on Windows or permission error
                
                # Also copy metadata file if it exists
                original_metadata = original_cape_path + '.meta'
                new_metadata = new_cape_path + '.meta'
                if os.path.exists(original_metadata):
                    shutil.copy2(original_metadata, new_metadata)
                    # Set permissions for metadata file too
                    try:
                        os.chmod(new_metadata, 0o644)
                    except OSError:
                        pass
                
                print(f"📋 Cape duplicated successfully from {uuid} to {new_uuid} ({new_player_name})")
                flash(f'Cape duplicated successfully for player "{new_player_name}"!', 'success')
            except Exception as e:
                print(f"❌ Error duplicating cape: {e}")
                flash(f'Error duplicating cape: {str(e)}', 'error')
        else:
            flash('Original cape not found!', 'error')
        
        return redirect('/')
    
    return redirect('/')

@app.route('/upload', methods=['GET', 'POST'])
def upload_cape():
    """Handle cape upload."""
    if request.method == 'POST':
        print("📤 Cape upload request received")
        
        # Check TOTP verification for editing operations
        if not require_totp_for_edit():
            print("❌ TOTP verification required for upload")
            # Check if this is an AJAX request
            if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded' and \
               request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'TOTP verification required', 'require_totp': True})
            else:
                flash('TOTP verification required for editing operations.', 'error')
                return redirect('/')
        
        # Check if player name is provided
        player_name = request.form.get('player_name', '').strip()
        print(f"👤 Upload request for player: {player_name}")
        
        if not player_name:
            print("❌ No player name provided")
            flash('Please enter a player name.', 'error')
            return redirect('/')
        
        # Check if file is provided
        if 'cape_file' not in request.files:
            print("❌ No file in request")
            flash('No file selected.', 'error')
            return redirect('/')
        
        file = request.files['cape_file']
        if file.filename == '':
            print("❌ Empty filename")
            flash('No file selected.', 'error')
            return redirect('/')
        
        print(f"📄 File details: {file.filename}, content type: {file.content_type}")
        
        if not allowed_file(file.filename):
            print("❌ File type not allowed")
            flash('Only PNG files are allowed.', 'error')
            return redirect('/')
        
        # Get UUID from player name
        uuid = get_uuid_from_playername(player_name)
        if not uuid:
            print(f"❌ Player {player_name} not found")
            flash(f'Player "{player_name}" not found. Please check the spelling.', 'error')
            return redirect('/')
        
        print(f"🆔 Player UUID: {uuid}")
        
        # Create capes directory if it doesn't exist
        os.makedirs(CAPES_DIR, exist_ok=True)
        
        # Save the file with UUID as filename (no extension)
        cape_path = os.path.join(CAPES_DIR, uuid)
        metadata_path = cape_path + '.meta'
        
        print(f"💾 Saving cape to: {cape_path}")
        
        try:
            # Remove old metadata file if it exists (for cape replacement)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
                print("🗑️ Removed old metadata file")
            
            file.save(cape_path)
            print("✅ Cape file saved successfully")
            
            # Set correct Linux permissions: -rw-r--r-- (644)
            try:
                os.chmod(cape_path, 0o644)
                print("🔒 File permissions set")
            except OSError:
                print("⚠️ Could not set file permissions (Windows/permission error)")
                pass  # Skip if on Windows or permission error
            
            # Clear cache for this UUID to refresh the name
            with cache_lock:
                if uuid in player_name_cache:
                    del player_name_cache[uuid]
                    print("🔄 Cleared player name cache")
            
            print(f"🎉 Cape uploaded successfully for {player_name}")
            flash(f'Cape uploaded successfully for player "{player_name}"!', 'success')
            
        except Exception as e:
            print(f"❌ Error saving cape: {e}")
            flash(f'Error saving cape: {str(e)}', 'error')
        
        return redirect('/')
    
    return redirect('/')

@app.route('/check_player/<player_name>')
def check_player(player_name):
    """Check if a player exists and if they already have a cape."""
    uuid = get_uuid_from_playername(player_name)
    if not uuid:
        return jsonify({'exists': False, 'message': f'Player "{player_name}" not found'})
    
    cape_exists = os.path.exists(os.path.join(CAPES_DIR, uuid))
    return jsonify({
        'exists': True, 
        'uuid': uuid,
        'has_cape': cape_exists,
        'message': f'Player found: {player_name} ({uuid})'
    })

@app.route('/check_cape_exists', methods=['POST'])
def check_cape_exists():
    """Check if a player already has a cape for the warning popup."""
    player_name = request.form.get('player_name', '').strip()
    
    if not player_name:
        return jsonify({'error': 'Player name required'})
    
    uuid = get_uuid_from_playername(player_name)
    if not uuid:
        return jsonify({'player_exists': False, 'error': f'Player "{player_name}" not found'})
    
    cape_exists = os.path.exists(os.path.join(CAPES_DIR, uuid))
    return jsonify({
        'player_exists': True,
        'cape_exists': cape_exists,
        'uuid': uuid,
        'player_name': player_name
    })

@app.route('/preview_url', methods=['POST'])
def preview_url():
    """Preview a cape from URL before downloading."""
    url = request.form.get('cape_url', '').strip()
    
    if not url:
        return jsonify({'success': False, 'error': 'Please enter a cape URL.'})
    
    try:
        download_url = convert_url_to_download(url)
        
        # Make a HEAD request first to check if it's an image
        head_response = requests.head(download_url, timeout=10)
        content_type = head_response.headers.get('content-type', '')
        
        if not content_type.startswith('image/'):
            return jsonify({
                'success': False, 
                'error': f'URL does not point to an image (got {content_type}). Please check the URL.'
            })
        
        # If it's an image, return the download URL for preview
        return jsonify({
            'success': True,
            'preview_url': download_url,
            'content_type': content_type,
            'original_url': url
        })
        
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Request timed out. The server might be slow or unreachable.'})
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'error': 'Connection error. Please check the URL and your internet connection.'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error checking URL: {str(e)}'})

@app.route('/download_from_url', methods=['POST'])
def download_from_url():
    """Download a cape from URL."""
    # Check TOTP verification for editing operations
    if not require_totp_for_edit():
        print("❌ TOTP verification required for URL download")
        flash('TOTP verification required for editing operations.', 'error')
        return redirect('/')
    
    url = request.form.get('cape_url', '').strip()
    player_name = request.form.get('player_name', '').strip()
    
    if not url:
        flash('Please enter a cape URL.', 'error')
        return redirect('/')
    
    if not player_name:
        flash('Please enter a player name.', 'error')
        return redirect('/')
    
    print(f"🌐 URL download request: {url} for player {player_name}")
    success, message = download_cape_from_url(url, player_name)
    
    if success:
        print(f"✅ URL download successful: {message}")
        flash(message, 'success')
    else:
        print(f"❌ URL download failed: {message}")
        flash(message, 'error')
    
    return redirect('/')

@app.route('/upload_gif', methods=['POST'])
def upload_gif():
    """Handle GIF upload and conversion."""
    # Check TOTP verification for editing operations
    if not require_totp_for_edit():
        print("❌ TOTP verification required for GIF upload")
        flash('TOTP verification required for editing operations.', 'error')
        return redirect('/')
    
    # Check if player name is provided
    player_name = request.form.get('player_name', '').strip()
    if not player_name:
        flash('Please enter a player name.', 'error')
        return redirect('/')
    
    # Check if file is provided
    if 'gif_file' not in request.files:
        flash('No file selected.', 'error')
        return redirect('/')
    
    file = request.files['gif_file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect('/')
    
    if not file.filename.lower().endswith('.gif'):
        flash('Only GIF files are allowed for this upload.', 'error')
        return redirect('/')
    
    # Get UUID from player name
    uuid = get_uuid_from_playername(player_name)
    if not uuid:
        flash(f'Player "{player_name}" not found. Please check the spelling.', 'error')
        return redirect('/')
    
    print(f"🎞️ GIF upload request for player: {player_name} (UUID: {uuid})")
    
    try:
        # Save GIF to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.gif') as temp_file:
            file.save(temp_file.name)
            gif_path = temp_file.name
        
        # Convert GIF to cape format
        converted_path = gif_to_vertical_collage(gif_path)
        
        if not converted_path or not os.path.exists(converted_path):
            os.remove(gif_path)
            flash('Failed to convert GIF to cape format.', 'error')
            return redirect('/')
        
        # Create capes directory if it doesn't exist
        os.makedirs(CAPES_DIR, exist_ok=True)
        
        # Move converted file to final location
        cape_path = os.path.join(CAPES_DIR, uuid)
        metadata_dst = cape_path + '.meta'
        
        # Remove old metadata file if it exists (for cape replacement)
        if os.path.exists(metadata_dst):
            os.remove(metadata_dst)
        
        shutil.move(converted_path, cape_path)
        
        # Set correct Linux permissions: -rw-r--r-- (644)
        try:
            os.chmod(cape_path, 0o644)
        except OSError:
            pass  # Skip if on Windows or permission error
        
        # Also move the metadata file if it exists
        metadata_src = converted_path + '.meta'
        if os.path.exists(metadata_src):
            shutil.move(metadata_src, metadata_dst)
            # Set permissions for metadata file too
            try:
                os.chmod(metadata_dst, 0o644)
            except OSError:
                pass
        
        # Clean up temporary files
        os.remove(gif_path)
        
        # Clear cache for this UUID
        with cache_lock:
            if uuid in player_name_cache:
                del player_name_cache[uuid]
        
        print(f"🎉 GIF cape uploaded successfully for {player_name}")
        flash(f'GIF cape uploaded and converted successfully for player "{player_name}"!', 'success')
        
    except Exception as e:
        print(f"❌ Error processing GIF: {e}")
        flash(f'Error processing GIF: {str(e)}', 'error')
    
    return redirect('/')

# API Endpoints

@app.route('/api/download_cape', methods=['POST'])
def api_download_cape():
    """API endpoint to download a cape from URL with authentication and TOTP."""
    print("🔌 API cape download request received")
    
    # Get form data
    url = request.form.get('url', '').strip()
    player_name = request.form.get('player_name', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    totp_token = request.form.get('totp', '').strip()
    
    # Validate required parameters
    if not all([url, player_name, username, password, totp_token]):
        print("❌ API request missing required parameters")
        return jsonify({
            'success': False, 
            'error': 'Missing required parameters: url, player_name, username, password, totp'
        }), 400
    
    # Verify credentials
    if username not in LOGIN_CREDENTIALS or LOGIN_CREDENTIALS[username] != password:
        print(f"❌ API authentication failed for username: {username}")
        return jsonify({
            'success': False, 
            'error': 'Invalid username or password'
        }), 401
    
    # Verify TOTP
    if not verify_totp(username, totp_token):
        print(f"❌ API TOTP verification failed for user: {username}")
        return jsonify({
            'success': False, 
            'error': 'Invalid TOTP token'
        }), 401
    
    print(f"✅ API authentication successful for user: {username}")
    print(f"🌐 API downloading cape from: {url}")
    print(f"👤 API target player: {player_name}")
    
    # Download cape (no confirmation needed for API)
    success, message = download_cape_from_url(url, player_name)
    
    if success:
        print(f"✅ API cape download successful: {message}")
        return jsonify({
            'success': True,
            'message': message,
            'player_name': player_name,
            'url': url
        })
    else:
        print(f"❌ API cape download failed: {message}")
        return jsonify({
            'success': False,
            'error': message
        }), 400

@app.route('/api/check_cape/<player_name>')
def api_check_cape(player_name):
    """API endpoint to check if a player has a cape (no authentication needed)."""
    print(f"🔌 API cape check request for player: {player_name}")
    
    if not player_name.strip():
        return jsonify({
            'success': False,
            'error': 'Player name is required'
        }), 400
    
    # Get UUID from player name
    uuid = get_uuid_from_playername(player_name)
    if not uuid:
        print(f"❌ Player {player_name} not found via Mojang API")
        return jsonify({
            'success': False,
            'player_exists': False,
            'error': f'Player "{player_name}" not found'
        })
    
    # Check if cape file exists
    cape_path = os.path.join(CAPES_DIR, uuid)
    cape_exists = os.path.exists(cape_path)
    
    print(f"✅ Player {player_name} found (UUID: {uuid}), has cape: {cape_exists}")
    
    return jsonify({
        'success': True,
        'player_exists': True,
        'player_name': player_name,
        'uuid': uuid,
        'has_cape': cape_exists,
        'cape_url': f'/cape/{uuid}' if cape_exists else None
    })

if __name__ == '__main__':
    # Create templates directory and template file
    os.makedirs('templates', exist_ok=True)
    
    # Ensure capes directory exists (create it if on Windows for testing)
    if os.name == 'nt':  # Windows
        # For Windows testing, use local directory
        CAPES_DIR = os.path.join(os.getcwd(), "capes")
    
    os.makedirs(CAPES_DIR, exist_ok=True)
    print(f"📁 Capes directory: {CAPES_DIR}")
    print(f"📁 Directory exists: {os.path.exists(CAPES_DIR)}")
    print(f"⏰ Session timeout: {SESSION_TIMEOUT} seconds ({SESSION_TIMEOUT/60} minutes)")
    print(f"👥 Configured users: {', '.join(LOGIN_CREDENTIALS.keys())}")
    print(f"🔐 TOTP enabled for: {', '.join(TOTP_SECRETS.keys())}")
    
    # Create the login template
    login_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoidCapes - Login</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ecf0f1;
            border-radius: 8px;
            font-size: 1em;
            box-sizing: border-box;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #74b9ff;
            box-shadow: 0 0 0 3px rgba(116, 185, 255, 0.1);
        }
        
        .login-btn {
            width: 100%;
            padding: 12px 24px;
            background: linear-gradient(135deg, #74b9ff, #0984e3);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 1em;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(116, 185, 255, 0.4);
        }
        
        .flash-messages {
            margin-bottom: 20px;
        }
        
        .flash-message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        
        .flash-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .flash-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .security-note {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🛡️ VoidCapes</h1>
        <p class="subtitle">Secure Cape Management</p>
        
        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="flash-message flash-{{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <button type="submit" class="login-btn">🔐 Login</button>
        </form>
        
        <div class="security-note">
            <strong>🔒 Secure Access Required</strong><br>
            Please enter your credentials to access the cape management system.
        </div>
    </div>
</body>
</html>'''
    
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write(login_template)
    
    # Create the TOTP setup template
    totp_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoidCapes - TOTP Setup</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
            text-align: center;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
            text-align: center;
        }
        
        .setup-section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .qr-code {
            text-align: center;
            margin: 20px 0;
        }
        
        .qr-code img {
            border: 2px solid #ecf0f1;
            border-radius: 10px;
            padding: 10px;
            background: white;
        }
        
        .secret-code {
            background: #2c3e50;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            text-align: center;
            margin: 15px 0;
        }
        
        .instructions {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .instructions ol {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        .instructions li {
            margin: 5px 0;
        }
        
        .back-btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #74b9ff, #0984e3);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
            transition: all 0.3s ease;
            text-align: center;
        }
        
        .back-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(116, 185, 255, 0.4);
        }
        
        .app-recommendations {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .app-list {
            list-style: none;
            padding: 0;
        }
        
        .app-list li {
            margin: 8px 0;
            padding: 5px 0;
        }
        
        .app-list li::before {
            content: "📱 ";
            margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📱 TOTP Setup</h1>
        <p class="subtitle">Two-Factor Authentication for {{ username }}</p>
        
        <div class="setup-section">
            <h3>🔐 Setup Your Authenticator App</h3>
            
            <div class="app-recommendations">
                <strong>Recommended Authenticator Apps:</strong>
                <ul class="app-list">
                    <li><strong>Google Authenticator</strong> - Available for iOS and Android</li>
                    <li><strong>Microsoft Authenticator</strong> - Available for iOS and Android</li>
                    <li><strong>Authy</strong> - Cross-platform with backup features</li>
                    <li><strong>1Password</strong> - If you use 1Password password manager</li>
                </ul>
            </div>
            
            <div class="instructions">
                <strong>Setup Instructions:</strong>
                <ol>
                    <li>Install an authenticator app on your phone</li>
                    <li>Open the app and scan the QR code below</li>
                    <li>Or manually enter the secret code if QR scanning doesn't work</li>
                    <li>Your app will now generate 6-digit codes every 30 seconds</li>
                    <li>Enter these codes when prompted for editing operations</li>
                </ol>
            </div>
            
            {% if qr_code %}
            <div class="qr-code">
                <h4>📷 Scan this QR Code:</h4>
                <img src="data:image/png;base64,{{ qr_code }}" alt="TOTP QR Code">
            </div>
            {% endif %}
            
            <div>
                <h4>🔑 Or enter this secret manually:</h4>
                <div class="secret-code">{{ secret }}</div>
                <small style="color: #7f8c8d;">
                    Keep this secret safe! Anyone with this code can generate TOTP tokens for your account.
                </small>
            </div>
        </div>
        
        <div style="text-align: center;">
            <a href="/" class="back-btn">⬅️ Back to Cape Management</a>
        </div>
    </div>
</body>
</html>'''
    
    with open('templates/totp_setup.html', 'w', encoding='utf-8') as f:
        f.write(totp_template)
    
    # Create the HTML template
    template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoidCapes</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            text-align: center;
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .subtitle {
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .header-buttons {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        .header-btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, #74b9ff, #0984e3);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.95em;
        }
        
        .header-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(116, 185, 255, 0.4);
        }
        
        .stats {
            text-align: center;
            margin-bottom: 30px;
            padding: 15px;
            background: linear-gradient(135deg, #74b9ff, #0984e3);
            color: white;
            border-radius: 10px;
            font-size: 1.1em;
        }
        
        .upload-section {
            background: linear-gradient(135deg, #a29bfe, #6c5ce7);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
            color: white;
        }
        
        .upload-compact {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .upload-compact h3 {
            margin: 0;
            font-size: 1.1em;
        }
        
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
        }
        
        .file-input-wrapper input[type=file] {
            position: absolute;
            left: -9999px;
        }
        
        .file-select-btn {
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }
        
        .file-select-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
        }
        
        .search-section {
            margin-bottom: 25px;
        }
        
        .search-bar {
            width: 100%;
            max-width: 400px;
            padding: 12px 16px;
            border: 2px solid #ecf0f1;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }
        
        .search-bar:focus {
            outline: none;
            border-color: #74b9ff;
            box-shadow: 0 0 0 3px rgba(116, 185, 255, 0.1);
        }
        
        .upload-step {
            display: none;
        }
        
        .upload-step.active {
            display: block;
        }
        
        .preview-section {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 30px;
            align-items: start;
        }
        
        .cape-preview {
            text-align: center;
        }
        
        .cape-preview img {
            max-width: 200px;
            height: auto;
            border-radius: 10px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            image-rendering: pixelated;
            background: rgba(255, 255, 255, 0.1);
        }
        
        .upload-details {
            flex: 1;
        }
        
        .upload-form {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 15px;
            align-items: end;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
        }
        
        .form-group label {
            margin-bottom: 5px;
            font-weight: bold;
            color: white;
        }
        
        .form-group input[type="text"], .form-group input[type="file"] {
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            background: rgba(255, 255, 255, 0.9);
        }
        
        .file-info {
            margin-top: 8px;
            padding: 8px 12px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            font-size: 0.9em;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .upload-btn, .back-btn {
            padding: 8px 16px;
            background: linear-gradient(135deg, #00b894, #00a085);
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.9em;
        }
        
        .back-btn {
            background: linear-gradient(135deg, #636e72, #2d3436);
        }
        
        .upload-btn:hover, .back-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 184, 148, 0.4);
        }
        
        .back-btn:hover {
            box-shadow: 0 6px 20px rgba(99, 110, 114, 0.4);
        }
        
        .overwrite-section {
            background: #ff7675;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            color: white;
        }
        
        .overwrite-checkbox {
            margin-top: 15px;
        }
        
        .overwrite-checkbox input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.2);
        }
        
        .flash-messages {
            margin-bottom: 20px;
        }
        
        .flash-message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        
        .flash-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .flash-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .flash-warning {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .capes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 25px;
            margin-top: 20px;
        }
        
        .cape-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .cape-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
            border-color: #74b9ff;
        }
        
        .cape-image {
            width: 100%;
            max-width: 200px;
            height: auto;
            border-radius: 10px;
            margin-bottom: 15px;
            image-rendering: pixelated;
            border: 3px solid #ecf0f1;
            transition: border-color 0.3s ease;
            object-fit: cover;
        }
        
        .cape-image.animated {
            animation: capeAnimation 2s steps(1) infinite;
        }
        
        @keyframes capeAnimation {
            0% { object-position: 0% 0%; }
            100% { object-position: 0% 100%; }
        }
        
        .cape-card:hover .cape-image {
            border-color: #74b9ff;
        }
        
        .player-name {
            font-size: 1.4em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .player-uuid {
            font-size: 0.9em;
            color: #7f8c8d;
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 5px 10px;
            border-radius: 5px;
            word-break: break-all;
            margin-bottom: 15px;
        }
        
        .cape-actions {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 15px;
        }
        
        .action-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            font-size: 0.9em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .delete-btn {
            background: linear-gradient(135deg, #ff7675, #e17055);
            color: white;
        }
        
        .delete-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(255, 118, 117, 0.4);
        }
        
        .duplicate-btn {
            background: linear-gradient(135deg, #fdcb6e, #e17055);
            color: white;
        }
        
        .duplicate-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(253, 203, 110, 0.4);
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }
        
        .modal-header {
            text-align: center;
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .modal-input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ecf0f1;
            border-radius: 8px;
            font-size: 1em;
            margin-bottom: 20px;
            box-sizing: border-box;
        }
        
        .modal-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
        }
        
        .modal-btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .modal-confirm {
            background: linear-gradient(135deg, #00b894, #00a085);
            color: white;
        }
        
        .modal-cancel {
            background: #bdc3c7;
            color: #2c3e50;
        }
        
        .no-capes {
            text-align: center;
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 50px;
            padding: 40px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        @media (max-width: 768px) {
            .preview-section {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .upload-form {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .capes-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 20px;
                margin: 10px;
            }
            
            h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>VoidCapes Overview</h1>
        <p class="subtitle">Browse and upload player capes</p>
        
        <!-- Header Buttons -->
        <div class="header-buttons">
            <button class="header-btn" onclick="showUrlDownloadModal()">🌐 Download from URL</button>
            <button class="header-btn" onclick="showGifUploadModal()">🎞️ Upload GIF Cape</button>
            <button class="header-btn" onclick="window.open('https://misterlauncher.org/capes/', '_blank')">🎨 HD Capes</button>
            <button class="header-btn" onclick="window.open('https://minecraftcapes.net/gallery/', '_blank')">🎞️ Animated Capes</button>
            <button class="header-btn" onclick="window.open('https://skinmc.net/capes', '_blank')">📋 Standard Capes</button>
            <a href="/setup_totp" class="header-btn" style="text-decoration: none;">📱 Setup TOTP</a>
            <a href="/logout" class="header-btn" style="text-decoration: none;">🚪 Logout</a>
        </div>
        
        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="flash-message flash-{{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        
        <!-- Upload Section -->
        <div class="upload-section">
            <div class="upload-compact">
                <h3>📤 Upload Cape:</h3>
                <div class="file-input-wrapper">
                    <input type="file" id="cape_file" accept=".png" onchange="previewFile()">
                    <label for="cape_file" class="file-select-btn">Choose PNG File</label>
                </div>
                <span id="file-status">No file selected</span>
            </div>
            
            <!-- Step 2: Preview and Player Selection -->
            <div id="step2" class="upload-step">
                <h3 style="margin-top: 15px; margin-bottom: 10px;">🎨 Preview & Assign Player</h3>
                <div class="preview-section">
                    <div class="cape-preview">
                        <img id="cape-preview-img" src="" alt="Cape Preview">
                        <div class="file-info">
                            <div id="file-details"></div>
                        </div>
                    </div>
                    <div class="upload-details">
                        <form action="/upload" method="post" enctype="multipart/form-data" class="upload-form" onsubmit="return checkForOverwrite(this, 'regular');">
                            <input type="file" id="cape_file_hidden" name="cape_file" style="display: none;">
                            <div class="form-group">
                                <label for="player_name">Assign to Player:</label>
                                <input type="text" id="player_name" name="player_name" required 
                                       placeholder="Enter Minecraft username">
                            </div>
                            <div style="display: flex; gap: 10px;">
                                <button type="button" class="back-btn" onclick="goBackToFileSelection()">⬅️ Back</button>
                                <button type="submit" class="upload-btn">✅ Upload</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Search Section -->
        <div class="search-section">
            <input type="text" id="search-bar" class="search-bar" placeholder="🔍 Search players by name or UUID..." 
                   onkeyup="filterCapes()">
        </div>
        
        <div class="stats">
            📊 Total Capes: {{ total_count }}
        </div>
        
        {% if capes %}
            <div class="capes-grid">
                {% for cape in capes %}
                <div class="cape-card">
                    <img src="/cape/{{ cape.uuid }}" alt="Cape for {{ cape.player_name }}" class="cape-image" 
                         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div style="display:none; padding: 40px; background: #f8f9fa; border-radius: 10px; color: #7f8c8d;">
                        🚫 Image not found
                    </div>
                    <div class="player-name">{{ cape.player_name }}</div>
                    <div class="player-uuid">({{ cape.uuid }})</div>
                    
                    <div class="cape-actions">
                        <button class="action-btn duplicate-btn" onclick="showTotpModal('duplicate', '{{ cape.uuid }}', '{{ cape.player_name }}')">
                            📋 Duplicate
                        </button>
                        <button class="action-btn delete-btn" onclick="showTotpModal('delete', '{{ cape.uuid }}', '{{ cape.player_name }}')">
                            🗑️ Delete
                        </button>
                    </div>
                </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="no-capes">
                <h2>🔍 No capes found</h2>
                <p>Upload your first cape using the form above!</p>
                <p>Cape files are saved in <code>/var/www/html/capes</code></p>
            </div>
        {% endif %}
    </div>
    
    <!-- Duplicate Cape Modal -->
    <div id="duplicateModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>📋 Duplicate Cape</h3>
                <p>Enter the player name who should receive a copy of this cape:</p>
            </div>
            <form id="duplicateForm" method="post">
                <input type="text" id="newPlayerName" name="new_player_name" class="modal-input" 
                       placeholder="Enter Minecraft username" required>
                <div class="modal-buttons">
                    <button type="submit" class="modal-btn modal-confirm">✅ Duplicate Cape</button>
                    <button type="button" class="modal-btn modal-cancel" onclick="closeDuplicateModal()">❌ Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- URL Download Modal -->
    <div id="urlDownloadModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>🌐 Download Cape from URL</h3>
                <p>Download a cape from skinmc.net, minecraftcapes.net, misterlauncher.org, or other cape sites:</p>
            </div>
            
            <!-- Step 1: URL Input -->
            <div id="urlStep1">
                <input type="url" id="capeUrl" class="modal-input" 
                       placeholder="https://skinmc.net/cape/12345" required>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-confirm" onclick="previewCapeUrl()">👁️ Preview Cape</button>
                    <button type="button" class="modal-btn modal-cancel" onclick="closeUrlDownloadModal()">❌ Cancel</button>
                </div>
                <div id="urlPreviewError" style="color: #e74c3c; margin-top: 10px; display: none;"></div>
            </div>
            
            <!-- Step 2: Preview and Player Selection -->
            <div id="urlStep2" style="display: none;">
                <div class="preview-section" style="margin-bottom: 20px;">
                    <div class="cape-preview">
                        <img id="urlCapePreview" src="" alt="Cape Preview" style="max-width: 200px; height: auto; border-radius: 10px; border: 3px solid #ecf0f1; image-rendering: pixelated;">
                        <div style="margin-top: 10px; font-size: 0.9em; color: #7f8c8d;">
                            <div id="urlPreviewInfo"></div>
                        </div>
                    </div>
                    <div style="flex: 1; margin-left: 20px;">
                        <form action="/download_from_url" method="post" onsubmit="return checkForOverwrite(this, 'url');">
                            <input type="hidden" id="hiddenCapeUrl" name="cape_url">
                            <input type="text" id="urlPlayerName" name="player_name" class="modal-input" 
                                   placeholder="Enter Minecraft username" required>
                            <div class="modal-buttons">
                                <button type="button" class="modal-btn modal-cancel" onclick="goBackToUrlInput()">⬅️ Back</button>
                                <button type="submit" class="modal-btn modal-confirm">⬇️ Download Cape</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- GIF Upload Modal -->
    <div id="gifUploadModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>🎞️ Upload GIF Cape</h3>
                <p>Upload a GIF file that will be converted to cape format:</p>
            </div>
            <form action="/upload_gif" method="post" enctype="multipart/form-data" onsubmit="return checkForOverwrite(this, 'gif');">
                <input type="file" id="gifFile" name="gif_file" class="modal-input" 
                       accept=".gif" required>
                <input type="text" id="gifPlayerName" name="player_name" class="modal-input" 
                       placeholder="Enter Minecraft username" required>
                <div class="modal-buttons">
                    <button type="submit" class="modal-btn modal-confirm">🎨 Convert & Upload</button>
                    <button type="button" class="modal-btn modal-cancel" onclick="closeGifUploadModal()">❌ Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Overwrite Warning Modal -->
    <div id="overwriteWarningModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>⚠️ Cape Already Exists</h3>
                <p id="overwriteWarningText">This will overwrite the player's current cape.</p>
            </div>
            <div class="modal-buttons">
                <button type="button" class="modal-btn modal-confirm" id="confirmOverwrite">✅ OK, Overwrite</button>
                <button type="button" class="modal-btn modal-cancel" onclick="closeOverwriteWarning()">❌ Cancel</button>
            </div>
        </div>
    </div>
    
    <!-- TOTP Verification Modal -->
    <div id="totpModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>🔐 Security Verification</h3>
                <p>Please enter your TOTP code to confirm this action:</p>
            </div>
            <input type="text" id="totpToken" class="modal-input" 
                   placeholder="Enter 6-digit TOTP code" maxlength="6" pattern="[0-9]{6}">
            <div class="modal-buttons">
                <button type="button" class="modal-btn modal-confirm" onclick="verifyTOTP()">✅ Verify & Continue</button>
                <button type="button" class="modal-btn modal-cancel" onclick="closeTOTPModal()">❌ Cancel</button>
            </div>
            <div id="totpError" style="color: #e74c3c; margin-top: 10px; display: none; text-align: center;"></div>
        </div>
    </div>
</body>
<script>
let currentDuplicateUuid = '';
let selectedFile = null;
let pendingUpload = null; // Store pending upload details
let pendingTOTPAction = null; // Store pending action after TOTP verification

function previewFile() {
    const fileInput = document.getElementById('cape_file');
    const file = fileInput.files[0];
    const fileStatus = document.getElementById('file-status');
    
    if (file && file.type === 'image/png') {
        selectedFile = file;
        fileStatus.textContent = file.name;
        
        // Show preview
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('cape-preview-img').src = e.target.result;
            document.getElementById('file-details').innerHTML = 
                `📄 <strong>${file.name}</strong><br>📏 Size: ${(file.size / 1024).toFixed(1)} KB`;
        };
        reader.readAsDataURL(file);
        
        // Copy file to hidden input for form submission
        const hiddenInput = document.getElementById('cape_file_hidden');
        const dt = new DataTransfer();
        dt.items.add(file);
        hiddenInput.files = dt.files;
        
        // Show step 2
        document.getElementById('step2').style.display = 'block';
        
        // Focus on player name input and scroll to it
        document.getElementById('player_name').focus();
        document.getElementById('step2').scrollIntoView({ behavior: 'smooth' });
    } else {
        alert('Please select a PNG file.');
        fileInput.value = '';
        fileStatus.textContent = 'No file selected';
    }
}

function checkForOverwrite(form, uploadType = 'regular') {
    const playerNameInput = form.querySelector('input[name="player_name"]');
    const playerName = playerNameInput.value.trim();
    
    console.log('Checking for overwrite:', playerName, uploadType);
    
    if (!playerName) {
        alert('Please enter a player name.');
        return false;
    }
    
    // Store the form for potential TOTP verification
    pendingTOTPAction = { form: form, type: uploadType };
    console.log('Set pendingTOTPAction:', pendingTOTPAction);
    
    // Check if player has existing cape
    fetch('/check_cape_exists', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'player_name=' + encodeURIComponent(playerName)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Cape exists check result:', data);
        
        if (!data.player_exists) {
            alert(data.error || 'Player not found');
            return;
        }
        
        if (data.cape_exists) {
            console.log('Cape exists, showing overwrite warning');
            // Show overwrite warning first
            showOverwriteWarning(data.player_name, form, uploadType);
        } else {
            console.log('Cape does not exist, proceeding to TOTP verification');
            // No cape exists, proceed to TOTP verification
            showTOTPModal();
        }
    })
    .catch(error => {
        console.error('Error checking cape:', error);
        // Show TOTP modal anyway
        showTOTPModal();
    });
    
    return false; // Prevent default form submission
}

function showTotpModal(action, uuid, playerName) {
    console.log('showTotpModal called with action:', action, 'UUID:', uuid, 'Player:', playerName);
    
    // Store the pending action details
    pendingTOTPAction = { 
        action: action, 
        uuid: uuid, 
        playerName: playerName 
    };
    
    console.log('pendingTOTPAction set to:', pendingTOTPAction);
    
    // Update modal text based on action
    const modalHeader = document.querySelector('#totpModal .modal-header p');
    if (action === 'delete') {
        modalHeader.textContent = `Please enter your TOTP code to delete ${playerName}'s cape:`;
    } else if (action === 'duplicate') {
        modalHeader.textContent = `Please enter your TOTP code to duplicate ${playerName}'s cape:`;
    } else {
        modalHeader.textContent = 'Please enter your TOTP code to confirm this action:';
    }
    
    // Show the modal
    console.log('Showing TOTP modal');
    document.getElementById('totpModal').style.display = 'block';
    document.getElementById('totpToken').focus();
    document.getElementById('totpError').style.display = 'none';
}

function showTOTPModal() {
    console.log('Showing TOTP modal');
    document.getElementById('totpModal').style.display = 'block';
    document.getElementById('totpToken').focus();
    document.getElementById('totpError').style.display = 'none';
}

function closeTOTPModal() {
    console.log('Closing TOTP modal');
    document.getElementById('totpModal').style.display = 'none';
    document.getElementById('totpToken').value = '';
    document.getElementById('totpError').style.display = 'none';
    // Note: Don't clear pendingTOTPAction here - it will be cleared after action execution
}

function verifyTOTP() {
    const token = document.getElementById('totpToken').value.trim();
    const errorDiv = document.getElementById('totpError');
    
    if (!token || token.length !== 6) {
        errorDiv.textContent = 'Please enter a 6-digit TOTP code.';
        errorDiv.style.display = 'block';
        return;
    }
    
    fetch('/verify_totp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'totp_token=' + encodeURIComponent(token)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeTOTPModal();
            
            // Small delay to ensure session is saved
            setTimeout(() => {
                // Execute the pending action
                console.log('Checking pendingTOTPAction:', pendingTOTPAction);
                if (pendingTOTPAction) {
                    console.log('Executing action after TOTP verification:', pendingTOTPAction);
                    console.log('Action type:', pendingTOTPAction.action);
                    console.log('UUID:', pendingTOTPAction.uuid);
                    console.log('Player name:', pendingTOTPAction.playerName);
                    
                    if (pendingTOTPAction.form) {
                        // For form submissions (upload)
                        console.log('Submitting form after TOTP verification');
                        closeOverwriteWarning();
                        pendingTOTPAction.form.submit();
                    } else if (pendingTOTPAction.action === 'delete') {
                        // For delete action - use fetch to maintain session properly
                        console.log('Executing delete action via fetch for UUID:', pendingTOTPAction.uuid);
                        fetch(`/delete_cape/${pendingTOTPAction.uuid}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            credentials: 'same-origin' // Ensure cookies/session are sent
                        })
                        .then(response => {
                            console.log('Delete response status:', response.status);
                            if (response.ok) {
                                console.log('Delete successful, reloading page');
                                // Reload the page to show updated cape list
                                window.location.reload();
                            } else {
                                console.error('Delete failed with status:', response.status);
                                alert('Error deleting cape. Please try again.');
                            }
                        })
                        .catch(error => {
                            console.error('Delete error:', error);
                            alert('Error deleting cape. Please try again.');
                        });
                    } else if (pendingTOTPAction.action === 'duplicate') {
                        // For duplicate action - show the duplicate modal
                        console.log('Showing duplicate modal for UUID:', pendingTOTPAction.uuid, 'Player:', pendingTOTPAction.playerName);
                        
                        // Debug: Check if elements exist
                        const duplicateModal = document.getElementById('duplicateModal');
                        const duplicateForm = document.getElementById('duplicateForm');
                        const newPlayerName = document.getElementById('newPlayerName');
                        
                        console.log('duplicateModal element:', duplicateModal);
                        console.log('duplicateForm element:', duplicateForm);
                        console.log('newPlayerName element:', newPlayerName);
                        
                        if (duplicateModal && duplicateForm && newPlayerName) {
                            showDuplicateModal(pendingTOTPAction.uuid, pendingTOTPAction.playerName);
                        } else {
                            console.error('Missing duplicate modal elements');
                            alert('Error: Duplicate modal elements not found');
                        }
                    } else {
                        console.log('Unknown action type:', pendingTOTPAction.action);
                    }
                    
                    pendingTOTPAction = null;
                } else {
                    console.log('No pendingTOTPAction found after TOTP verification');
                }
            }, 100); // 100ms delay to ensure session is saved
        } else {
            errorDiv.textContent = data.error || 'Invalid TOTP code';
            errorDiv.style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error verifying TOTP:', error);
        errorDiv.textContent = 'Error verifying TOTP code';
        errorDiv.style.display = 'block';
    });
}

function showOverwriteWarning(playerName, form, uploadType) {
    console.log('Showing overwrite warning for:', playerName);
    const warningText = document.getElementById('overwriteWarningText');
    warningText.textContent = `This will overwrite ${playerName}'s current cape.`;
    
    // Store the form for later submission
    pendingUpload = { form: form, type: uploadType };
    console.log('Set pendingUpload:', pendingUpload);
    
    document.getElementById('overwriteWarningModal').style.display = 'block';
}

function closeOverwriteWarning() {
    console.log('Closing overwrite warning');
    document.getElementById('overwriteWarningModal').style.display = 'none';
    pendingUpload = null;
}

function confirmOverwrite() {
    if (pendingUpload) {
        console.log('Overwrite confirmed, proceeding to TOTP verification');
        // Store the pending upload for TOTP verification
        pendingTOTPAction = { form: pendingUpload.form, type: pendingUpload.type };
        closeOverwriteWarning();
        showTOTPModal();
    }
}

function goBackToFileSelection() {
    document.getElementById('step2').style.display = 'none';
    
    // Clear the file input
    document.getElementById('cape_file').value = '';
    document.getElementById('cape_file_hidden').value = '';
    document.getElementById('player_name').value = '';
    document.getElementById('file-status').textContent = 'No file selected';
    selectedFile = null;
}

function filterCapes() {
    const searchInput = document.getElementById('search-bar');
    const searchTerm = searchInput.value.toLowerCase();
    const capeCards = document.querySelectorAll('.cape-card');
    
    capeCards.forEach(card => {
        const playerName = card.querySelector('.player-name').textContent.toLowerCase();
        const playerUuid = card.querySelector('.player-uuid').textContent.toLowerCase();
        const searchText = playerName + ' ' + playerUuid;
        
        if (searchText.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Hide step 2 initially
    const step2 = document.getElementById('step2');
    if (step2) {
        step2.style.display = 'none';
    }
    
    // Setup animated capes
    setupAnimatedCapes();
});

function setupAnimatedCapes() {
    const capeImages = document.querySelectorAll('.cape-image');
    
    capeImages.forEach(img => {
        // Extract UUID from the image src
        const src = img.src;
        const uuidMatch = src.match(/\/cape\/([^\/]+)$/);
        if (uuidMatch) {
            const uuid = uuidMatch[1];
            
            // Fetch metadata for this cape
            fetch(`/cape_meta/${uuid}`)
                .then(response => response.json())
                .then(metadata => {
                    if (metadata.is_animated && metadata.frame_count > 1) {
                        setupCapeAnimation(img, metadata);
                    }
                })
                .catch(error => {
                    console.log('No metadata for cape:', uuid);
                });
        }
    });
}

function setupCapeAnimation(img, metadata) {
    const frameHeight = metadata.frame_height;
    const frameCount = metadata.frame_count;
    
    // Set the image height to show only one frame
    img.style.height = frameHeight + 'px';
    img.style.objectFit = 'none';
    img.style.objectPosition = '0 0';
    
    let currentFrame = 0;
    
    // Animate through frames
    setInterval(() => {
        currentFrame = (currentFrame + 1) % frameCount;
        const yPosition = -(currentFrame * frameHeight);
        img.style.objectPosition = `0 ${yPosition}px`;
    }, 200); // Change frame every 200ms
}

function showDuplicateModal(uuid, playerName) {
    console.log('showDuplicateModal called with UUID:', uuid, 'Player:', playerName);
    currentDuplicateUuid = uuid;
    document.getElementById('duplicateForm').action = `/duplicate_cape/${uuid}`;
    document.getElementById('newPlayerName').placeholder = `Copy ${playerName}'s cape to...`;
    console.log('Setting duplicate modal display to block');
    document.getElementById('duplicateModal').style.display = 'block';
    document.getElementById('newPlayerName').focus();
    console.log('Duplicate modal should now be visible');
}

function closeDuplicateModal() {
    document.getElementById('duplicateModal').style.display = 'none';
    document.getElementById('newPlayerName').value = '';
}

function showUrlDownloadModal() {
    document.getElementById('urlDownloadModal').style.display = 'block';
    document.getElementById('urlStep1').style.display = 'block';
    document.getElementById('urlStep2').style.display = 'none';
    document.getElementById('capeUrl').focus();
}

function closeUrlDownloadModal() {
    document.getElementById('urlDownloadModal').style.display = 'none';
    document.getElementById('capeUrl').value = '';
    document.getElementById('urlPlayerName').value = '';
    document.getElementById('urlStep1').style.display = 'block';
    document.getElementById('urlStep2').style.display = 'none';
    document.getElementById('urlPreviewError').style.display = 'none';
}

function previewCapeUrl() {
    const url = document.getElementById('capeUrl').value.trim();
    const errorDiv = document.getElementById('urlPreviewError');
    
    if (!url) {
        errorDiv.textContent = 'Please enter a cape URL.';
        errorDiv.style.display = 'block';
        return;
    }
    
    errorDiv.style.display = 'none';
    
    // Show loading state
    const previewBtn = document.querySelector('#urlStep1 .modal-confirm');
    const originalText = previewBtn.textContent;
    previewBtn.textContent = '⏳ Loading...';
    previewBtn.disabled = true;
    
    // Make request to preview endpoint
    fetch('/preview_url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cape_url=' + encodeURIComponent(url)
    })
    .then(response => response.json())
    .then(data => {
        previewBtn.textContent = originalText;
        previewBtn.disabled = false;
        
        if (data.success) {
            // Show preview
            document.getElementById('urlCapePreview').src = data.preview_url;
            document.getElementById('urlPreviewInfo').innerHTML = 
                `📄 <strong>Cape Preview</strong><br>🔗 Source: ${data.original_url}<br>📷 Type: ${data.content_type}`;
            document.getElementById('hiddenCapeUrl').value = data.original_url;
            
            // Switch to step 2
            document.getElementById('urlStep1').style.display = 'none';
            document.getElementById('urlStep2').style.display = 'block';
            document.getElementById('urlPlayerName').focus();
        } else {
            errorDiv.textContent = data.error;
            errorDiv.style.display = 'block';
        }
    })
    .catch(error => {
        previewBtn.textContent = originalText;
        previewBtn.disabled = false;
        errorDiv.textContent = 'Error loading preview: ' + error.message;
        errorDiv.style.display = 'block';
    });
}

function goBackToUrlInput() {
    document.getElementById('urlStep1').style.display = 'block';
    document.getElementById('urlStep2').style.display = 'none';
    document.getElementById('urlPlayerName').value = '';
}

function showGifUploadModal() {
    document.getElementById('gifUploadModal').style.display = 'block';
    document.getElementById('gifFile').focus();
}

function closeGifUploadModal() {
    document.getElementById('gifUploadModal').style.display = 'none';
    document.getElementById('gifFile').value = '';
    document.getElementById('gifPlayerName').value = '';
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Hide step 2 initially
    const step2 = document.getElementById('step2');
    if (step2) {
        step2.style.display = 'none';
    }
    
    // Setup animated capes
    setupAnimatedCapes();
    
    // Add event listener for confirm overwrite button
    const confirmBtn = document.getElementById('confirmOverwrite');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', confirmOverwrite);
    }
});

// Session timeout management
let sessionTimeout;
let warningTimeout;
let sessionCheckInterval;
const SESSION_DURATION = 10 * 60 * 1000; // 10 minutes in milliseconds
const WARNING_TIME = 2 * 60 * 1000; // Show warning 2 minutes before expiration

function checkSessionStatus() {
    fetch('/session_status')
        .then(response => response.json())
        .then(data => {
            if (!data.authenticated) {
                clearTimeout(sessionTimeout);
                clearTimeout(warningTimeout);
                clearInterval(sessionCheckInterval);
                alert('Session expired. You will be redirected to the login page.');
                window.location.href = '/login';
                return;
            }
            
            const timeRemaining = data.time_remaining * 1000; // Convert to milliseconds
            
            // Clear existing timeouts
            clearTimeout(sessionTimeout);
            clearTimeout(warningTimeout);
            
            if (timeRemaining <= WARNING_TIME && timeRemaining > 0) {
                // Show warning immediately if we're already in warning period
                if (confirm('Your session will expire soon. Click OK to stay logged in.')) {
                    // Make a request to keep session alive
                    fetch('/refresh', {method: 'GET'})
                        .then(() => {
                            console.log('Session refreshed');
                            // Check status again after refresh
                            setTimeout(checkSessionStatus, 1000);
                        })
                        .catch(() => window.location.href = '/login');
                }
            } else if (timeRemaining > WARNING_TIME) {
                // Set warning for remaining time minus warning period
                warningTimeout = setTimeout(() => {
                    if (confirm('Your session will expire in 2 minutes. Click OK to stay logged in.')) {
                        fetch('/refresh', {method: 'GET'})
                            .then(() => {
                                console.log('Session refreshed');
                                setTimeout(checkSessionStatus, 1000);
                            })
                            .catch(() => window.location.href = '/login');
                    }
                }, timeRemaining - WARNING_TIME);
            }
        })
        .catch(error => {
            console.error('Session check failed:', error);
            // If we can't check session, assume it's expired
            window.location.href = '/login';
        });
}

// Check session status every 30 seconds
function startSessionMonitoring() {
    checkSessionStatus(); // Initial check
    sessionCheckInterval = setInterval(checkSessionStatus, 30000); // Check every 30 seconds
}

// Start session monitoring on page load
document.addEventListener('DOMContentLoaded', startSessionMonitoring);

// Close modal when clicking outside of it
window.onclick = function(event) {
    const duplicateModal = document.getElementById('duplicateModal');
    const urlModal = document.getElementById('urlDownloadModal');
    const gifModal = document.getElementById('gifUploadModal');
    const overwriteModal = document.getElementById('overwriteWarningModal');
    const totpModal = document.getElementById('totpModal');
    
    if (event.target === duplicateModal) {
        closeDuplicateModal();
    } else if (event.target === urlModal) {
        closeUrlDownloadModal();
    } else if (event.target === gifModal) {
        closeGifUploadModal();
    } else if (event.target === overwriteModal) {
        closeOverwriteWarning();
    } else if (event.target === totpModal) {
        closeTOTPModal();
    }
}
</script>
</html>'''
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(template_content)
    
    print(f"🚀 Starting Minecraft Capes web server on port {PORT}")
    print(f"📁 Looking for capes in: {CAPES_DIR}")
    print(f"🌐 Access the website at: http://localhost:{PORT}")
    
    app.run(host='0.0.0.0', port=PORT, debug=True)