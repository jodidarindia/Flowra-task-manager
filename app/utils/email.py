import smtplib
import socket
from email.message import EmailMessage
from email.utils import formataddr
from flask import current_app


def send_email(to_email, subject, html_body):
    """Send an HTML email via SMTP.

    Reads SMTP settings from the app config (env vars):
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM_EMAIL, SMTP_FROM_NAME

    Returns True on success, False (with a printed reason) on failure.
    """
    host = current_app.config.get("SMTP_HOST")
    port = current_app.config.get("SMTP_PORT", 587)
    user = current_app.config.get("SMTP_USER")
    password = current_app.config.get("SMTP_PASSWORD")
    from_email = current_app.config.get("SMTP_FROM_EMAIL")
    from_name = current_app.config.get("SMTP_FROM_NAME") or "Flowra Task"

    if not host or not user or not password or not from_email:
        print("Email skipped: SMTP credentials not configured (SMTP_HOST/SMTP_USER/SMTP_PASSWORD/SMTP_FROM_EMAIL missing).")
        return False

    if not to_email:
        print("Email skipped: no recipient address.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_email
    msg.set_content("Please view this email in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    try:
        if int(port) == 465:
            server = smtplib.SMTP_SSL(host, int(port), timeout=20)
        else:
            server = smtplib.SMTP(host, int(port), timeout=20)
            server.starttls()
        server.login(user, password)
        server.send_message(msg)
        server.quit()
        print("Email sent to", to_email)
        return True
    except socket.timeout:
        print("Email error: SMTP connection timed out.")
        return False
    except Exception as e:
        print("Email error:", e)
        try:
            server.quit()
        except Exception:
            pass
        return False


def send_account_credentials_email(to_email, username, password, role=None, company=None, status="active"):
    """Send the auto-generated credentials for a newly created account."""
    role_label = {
        "super_admin": "Super Admin",
        "admin": "Admin",
        "manager": "Manager",
        "employee": "Employee"
    }.get(role, role or "User")

    company_line = f"<strong>{company}</strong>" if company else "<em>(not set)</em>"
    status_label = "Active" if status == "active" else status.capitalize()

    html_body = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="margin-top:0;color:#1d4ed8;">Welcome to Flowra Task</h2>
        <p>Your account has been created. Here are your sign-in details:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0;">
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Full Name</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{username}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Email Address</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{to_email}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Username</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{username}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Role</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{role_label}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Status</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{status_label}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Company</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{company_line}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Password</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;font-family:monospace;font-size:14px;">{password}</td>
            </tr>
        </table>
        <p>For security, please change your password after your first sign-in.</p>
        <p style="margin-bottom:0;color:#64748b;font-size:12px;">This is an automated message - please do not reply.</p>
    </div>
    """

    return send_email(
        to_email,
        "Your Flowra Task account credentials",
        html_body
    )