"""CLI utility to test SMTP email configuration and connectivity."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.config import Config
from backend.auth.email_service import send_email

def main():
    recipient = sys.argv[1] if len(sys.argv) > 1 else Config.MAIL_USERNAME

    print("=" * 60)
    print("Web Checker Email Diagnostics")
    print("=" * 60)
    print(f"MAIL_SERVER:         {Config.MAIL_SERVER}")
    print(f"MAIL_PORT:           {Config.MAIL_PORT}")
    print(f"MAIL_USE_TLS:        {Config.MAIL_USE_TLS}")
    print(f"MAIL_USE_SSL:        {getattr(Config, 'MAIL_USE_SSL', False)}")
    print(f"MAIL_USERNAME:       {Config.MAIL_USERNAME}")
    print(f"MAIL_PASSWORD set?   {'Yes (' + ('*' * len(Config.MAIL_PASSWORD)) + ')' if Config.MAIL_PASSWORD else 'No'}")
    print(f"MAIL_DEFAULT_SENDER: {Config.MAIL_DEFAULT_SENDER}")
    print(f"FRONTEND_URL:        {Config.FRONTEND_URL}")
    print(f"Sending test to:     {recipient}")
    print("=" * 60)

    if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD or Config.MAIL_PASSWORD == "your-gmail-app-password-here":
        print("\n[!] WARNING: Gmail App Password is not yet configured in .env.")
        print("To generate one:")
        print("  1. Ensure 2-Step Verification is ON in your Google Account.")
        print("  2. Visit https://myaccount.google.com/apppasswords")
        print("  3. Create an App Password for 'Web Checker' (16 letters).")
        print("  4. Set MAIL_PASSWORD=<your-16-char-app-password> in your .env file.\n")
        return 1

    print("Attempting to send test email...")
    html = """
    <div style="font-family: sans-serif; padding: 20px; background: #09090b; color: #f4f4f5; border-radius: 8px;">
        <h2 style="color: #2dd4bf;">Web Checker Email Test</h2>
        <p>This is a test email confirming that Gmail SMTP is properly connected and functioning.</p>
    </div>
    """
    text = "Web Checker Email Test - Your Gmail SMTP is successfully connected!"
    
    success = send_email(recipient, "Web Checker - SMTP Connection Test", html, text)
    if success:
        print("\n[+] SUCCESS! Test email sent successfully to", recipient)
        return 0
    else:
        print("\n[-] FAILED to send test email. Check the error logs above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
