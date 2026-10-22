"""Email service for sending transactional emails."""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from backend.config import Config

logger = logging.getLogger(__name__)


def send_email(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """
    Send an email via SMTP.
    
    Args:
        to: Recipient email address
        subject: Email subject
        html_body: HTML content
        text_body: Plain text content (optional, auto-generated from HTML if not provided)
    
    Returns:
        True if sent successfully, False otherwise
    """
    if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
        logger.warning("Email not configured (MAIL_USERNAME/MAIL_PASSWORD missing). Skipping send.")
        return False

    try:
        sender = Config.MAIL_DEFAULT_SENDER
        if not sender or "@webchecker.local" in sender:
            sender = f"Web Checker <{Config.MAIL_USERNAME}>"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        if getattr(Config, "MAIL_USE_SSL", False) or Config.MAIL_PORT == 465:
            with smtplib.SMTP_SSL(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=15) as server:
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=15) as server:
                if Config.MAIL_USE_TLS:
                    server.starttls()
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.send_message(msg)

        logger.info(f"Email sent successfully to {to}: {subject}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(
            f"SMTP Authentication error sending email to {to}: {e}. "
            f"If using Gmail, verify you are using a 16-character App Password (not your Gmail login password). "
            f"Generate one at https://myaccount.google.com/apppasswords"
        )
        return False
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}", exc_info=True)
        return False


def send_password_reset_email(to: str, reset_token: str, username: Optional[str] = None) -> bool:
    """Send password reset email with reset token, direct link, and account username."""
    reset_link = f"{Config.FRONTEND_URL}/reset-password?token={reset_token}"
    
    subject = "Reset your Web Checker password"
    username_notice = f"""
    <div style="margin: 0 0 16px; padding: 10px 14px; background: #1f1f23; border: 1px solid #27272a; border-radius: 6px; font-size: 13px; color: #d4d4d8;">
        Account Username: <strong style="color: #2dd4bf; font-family: monospace;">{username}</strong>
    </div>
    """ if username else ""
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #18181b; max-width: 600px; margin: 0 auto; padding: 24px; background-color: #09090b;">
        <div style="background: #121215; border-radius: 14px; padding: 32px; border: 1px solid #27272a;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; border-radius: 10px; background: linear-gradient(135deg, #0d9488, #14b8a6); color: white; font-weight: 600; font-size: 20px;">
                    W
                </div>
                <h1 style="margin: 16px 0 0; font-size: 24px; font-weight: 700; color: #f4f4f5;">Web Checker</h1>
            </div>
            
            <h2 style="margin: 0 0 16px; font-size: 20px; font-weight: 600; color: #f4f4f5;">Reset your password</h2>
            {username_notice}
            <p style="margin: 0 0 20px; color: #a1a1aa; font-size: 15px;">
                You requested a password reset for your Web Checker account. You can click the button below or enter the reset token directly on the reset page:
            </p>

            <div style="margin: 20px 0; padding: 16px; background: #18181b; border: 1px dashed #3f3f46; border-radius: 8px; text-align: center;">
                <span style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #71717a; display: block; margin-bottom: 6px; font-family: monospace;">Password Reset Token</span>
                <code style="display: block; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 16px; color: #2dd4bf; word-break: break-all; font-weight: 600;">{reset_token}</code>
            </div>
            
            <div style="text-align: center; margin: 28px 0;">
                <a href="{reset_link}" style="display: inline-block; padding: 14px 28px; background: #ffffff; color: #000000; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    Reset Password
                </a>
            </div>
            
            <p style="margin: 24px 0 0; color: #71717a; font-size: 13px;">
                Or copy this direct link into your browser:<br>
                <a href="{reset_link}" style="color: #14b8a6; word-break: break-all;">{reset_link}</a>
            </p>
            
            <hr style="border: none; border-top: 1px solid #27272a; margin: 24px 0;">
            
            <p style="margin: 0; color: #71717a; font-size: 13px;">
                This link and token expire in 2 hours. If you did not request this, you can safely ignore this email.
            </p>
        </div>
        
        <p style="text-align: center; margin-top: 16px; color: #71717a; font-size: 12px;">
            Web Checker — Security audit platform
        </p>
    </body>
    </html>
    """
    
    username_text = f"Username: {username}\n\n" if username else ""
    text_body = f"""
    Reset your Web Checker password
    
    You requested a password reset for your Web Checker account.
    {username_text}
    Your Reset Token is:
    {reset_token}
    
    You can reset your password directly at:
    {reset_link}
    
    This link and token expire in 2 hours. If you didn't request this, you can safely ignore this email.
    
    Web Checker — Security audit platform
    """
    
    return send_email(to, subject, html_body, text_body)


def send_verification_email(to: str, verification_token: str, username: Optional[str] = None) -> bool:
    """Send email verification link, token, and account username."""
    verify_link = f"{Config.FRONTEND_URL}/verify-email?token={verification_token}"
    
    subject = "Verify your Web Checker email address"
    username_notice = f"""
    <div style="margin: 0 0 16px; padding: 10px 14px; background: #1f1f23; border: 1px solid #27272a; border-radius: 6px; font-size: 13px; color: #d4d4d8;">
        Account Username: <strong style="color: #2dd4bf; font-family: monospace;">{username}</strong>
    </div>
    """ if username else ""
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #18181b; max-width: 600px; margin: 0 auto; padding: 24px; background-color: #09090b;">
        <div style="background: #121215; border-radius: 14px; padding: 32px; border: 1px solid #27272a;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; border-radius: 10px; background: linear-gradient(135deg, #0d9488, #14b8a6); color: white; font-weight: 600; font-size: 20px;">
                    W
                </div>
                <h1 style="margin: 16px 0 0; font-size: 24px; font-weight: 700; color: #f4f4f5;">Web Checker</h1>
            </div>
            
            <h2 style="margin: 0 0 16px; font-size: 20px; font-weight: 600; color: #f4f4f5;">Verify your email address</h2>
            {username_notice}
            <p style="margin: 0 0 20px; color: #a1a1aa; font-size: 15px;">
                Thank you for creating an account on Web Checker. Please confirm your email address by clicking the button below or entering your verification token:
            </p>

            <div style="margin: 20px 0; padding: 16px; background: #18181b; border: 1px dashed #3f3f46; border-radius: 8px; text-align: center;">
                <span style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #71717a; display: block; margin-bottom: 6px; font-family: monospace;">Verification Token</span>
                <code style="display: block; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 16px; color: #2dd4bf; word-break: break-all; font-weight: 600;">{verification_token}</code>
            </div>
            
            <div style="text-align: center; margin: 28px 0;">
                <a href="{verify_link}" style="display: inline-block; padding: 14px 28px; background: #ffffff; color: #000000; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    Verify Email Address
                </a>
            </div>
            
            <p style="margin: 24px 0 0; color: #71717a; font-size: 13px;">
                Or copy this direct link into your browser:<br>
                <a href="{verify_link}" style="color: #14b8a6; word-break: break-all;">{verify_link}</a>
            </p>
            
            <hr style="border: none; border-top: 1px solid #27272a; margin: 24px 0;">
            
            <p style="margin: 0; color: #71717a; font-size: 13px;">
                This link and token expire in 24 hours. If you did not create this account, no action is needed.
            </p>
        </div>
        
        <p style="text-align: center; margin-top: 16px; color: #71717a; font-size: 12px;">
            Web Checker — Security audit platform
        </p>
    </body>
    </html>
    """
    
    username_text = f"Username: {username}\n\n" if username else ""
    text_body = f"""
    Verify your Web Checker email address
    
    Thank you for registering. Please verify your email address.
    {username_text}
    Your Verification Token is:
    {verification_token}
    
    Click this link to verify your email:
    {verify_link}
    
    This link and token expire in 24 hours.
    
    Web Checker — Security audit platform
    """
    
    return send_email(to, subject, html_body, text_body)


def send_username_reminder_email(to: str, username: str) -> bool:
    """Send an email reminding the user of their registered username."""
    login_link = f"{Config.FRONTEND_URL}/login"
    
    subject = "Your Web Checker username reminder"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #18181b; max-width: 600px; margin: 0 auto; padding: 24px; background-color: #09090b;">
        <div style="background: #121215; border-radius: 14px; padding: 32px; border: 1px solid #27272a;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; border-radius: 10px; background: linear-gradient(135deg, #0d9488, #14b8a6); color: white; font-weight: 600; font-size: 20px;">
                    W
                </div>
                <h1 style="margin: 16px 0 0; font-size: 24px; font-weight: 700; color: #f4f4f5;">Web Checker</h1>
            </div>
            
            <h2 style="margin: 0 0 16px; font-size: 20px; font-weight: 600; color: #f4f4f5;">Username Reminder</h2>
            
            <p style="margin: 0 0 20px; color: #a1a1aa; font-size: 15px;">
                You requested a reminder of your Web Checker account username associated with this email address:
            </p>

            <div style="margin: 20px 0; padding: 18px; background: #18181b; border: 1px dashed #3f3f46; border-radius: 8px; text-align: center;">
                <span style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #71717a; display: block; margin-bottom: 6px; font-family: monospace;">Your Account Username</span>
                <code style="display: block; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 18px; color: #2dd4bf; word-break: break-all; font-weight: 700;">{username}</code>
            </div>

            <p style="margin: 20px 0; color: #a1a1aa; font-size: 14px;">
                <em>Note: You can also log into Web Checker directly using your email address and password!</em>
            </p>
            
            <div style="text-align: center; margin: 28px 0;">
                <a href="{login_link}" style="display: inline-block; padding: 14px 28px; background: #ffffff; color: #000000; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    Go to Sign In
                </a>
            </div>
            
            <hr style="border: none; border-top: 1px solid #27272a; margin: 24px 0;">
            
            <p style="margin: 0; color: #71717a; font-size: 13px;">
                If you did not request this reminder, you can safely ignore this email.
            </p>
        </div>
        
        <p style="text-align: center; margin-top: 16px; color: #71717a; font-size: 12px;">
            Web Checker — Security audit platform
        </p>
    </body>
    </html>
    """
    
    text_body = f"""
    Your Web Checker username reminder
    
    Your account username is:
    {username}
    
    You can also log into Web Checker directly using your email address and password!
    
    Sign in here:
    {login_link}
    
    Web Checker — Security audit platform
    """
    
    return send_email(to, subject, html_body, text_body)
