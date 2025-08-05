# VoidCapes - Minecraft Cape Management System

A web-based cape management system for Minecraft servers with TOTP authentication.

## Configuration

### Setting up credentials

1. Copy the example configuration file:

   ```bash
   cp config.example.json config.json
   ```

2. Edit `config.json` to set your login credentials and TOTP secrets:

   ```json
   {
       "login_credentials": {
           "admin": "your_secure_password_here",
           "user2": "another_password"
       },
       "totp_secrets": {
           "admin": "your_totp_secret_here",
           "user2": "another_totp_secret"
       }
   }
   ```

### Generating TOTP Secrets

To generate a new TOTP secret, run:

```python
python -c "import pyotp; print(pyotp.random_base32())"
```

### Security Notes

- **Never commit `config.json` to version control** - it contains sensitive credentials
- Use strong, unique passwords for each user
- Generate unique TOTP secrets for each user
- Both `login_credentials` and `totp_secrets` sections must have matching usernames
- Keep the config file secure with appropriate file permissions

### Configuration Structure

The `config.json` file must contain:

- `login_credentials`: Object with username/password pairs for web login
- `totp_secrets`: Object with username/TOTP secret pairs for two-factor authentication

Both sections must have the same usernames, but can have multiple users.

## Installation

1. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Set up your configuration file (see Configuration section above)

3. Run the application:

   ```bash
   python main.py
   ```

4. Access the web interface at `http://localhost:4563`

## Features

- Web-based cape upload and management
- Two-factor authentication (TOTP)
- Cape duplication between players
- URL-based cape downloading from popular cape sites
- GIF to cape conversion
- Session management with timeout
- Player name validation via Mojang API

## API Endpoints

The system provides API endpoints for automated cape management:

- `GET /api/check_cape/<player_name>` - Check if a player has a cape
- `POST /api/download_cape` - Download cape from URL (requires authentication and TOTP)