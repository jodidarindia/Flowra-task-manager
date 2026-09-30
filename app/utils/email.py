import json
import urllib.request
import urllib.error
from urllib.parse import quote
from flask import current_app

_last_error = None

SUPPORT_PHONE_DISPLAY = "8120470018"
SUPPORT_PHONE_WA = "918120470018"
SITE_URL = "https://www.flowralive.in"
SUPPORT_EMAIL = "support@flowralive.in"


def get_last_email_error():
    """Return the reason the most recent send attempt failed (or None)."""
    return _last_error


def _branded_footer():
    """Build the standard FLOWRA email footer with a clickable WhatsApp link."""
    wa_text = quote("Hi FLOWRA, I need help with my Flowra Task account.")
    wa_link = "https://wa.me/{}?text={}".format(SUPPORT_PHONE_WA, wa_text)

    return """
    <div style="margin-top:24px;padding-top:16px;border-top:1px solid #e5e7eb;text-align:center;color:#64748b;font-size:12px;line-height:1.6;">
        <p style="margin:0 0 6px;font-weight:bold;color:#1d4ed8;font-size:13px;">FLOWRA</p>
        <p style="margin:0 0 6px;">A product by <strong>JODIDAR INDIA</strong></p>
        <p style="margin:0 0 10px;">
            <a href="{site}" style="color:#1d4ed8;text-decoration:underline;">www.flowralive.in</a>
        </p>
        <p style="margin:0 0 10px;">
            <a href="mailto:{mail}" style="color:#1d4ed8;text-decoration:underline;">{mail}</a>
            &nbsp;&middot;&nbsp;
            <a href="{wa}" style="color:#25D366;text-decoration:underline;font-weight:bold;">WhatsApp</a>
        </p>
        <p style="margin:0 0 10px;">Need help? Chat with us on WhatsApp at <strong>{phone}</strong></p>
        <p style="margin:0 0 6px;color:#94a3b8;">Tally* is the trademark of its respective owner.</p>
        <p style="margin:0;color:#94a3b8;">This email was sent because you have an active FLOWRA account.</p>
    </div>
    """.format(
        site=SITE_URL,
        mail=SUPPORT_EMAIL,
        wa=wa_link,
        phone=SUPPORT_PHONE_DISPLAY,
    )


def send_email(to_email, subject, html_body):
    """Send an HTML email via the Resend REST API.

    Reads settings from the app config (env vars):
      RESEND_API_KEY, MAIL_FROM_EMAIL, MAIL_FROM_NAME

    Returns True on success, False (with a printed reason) on failure.
    """
    global _last_error
    _last_error = None

    api_key = current_app.config.get("RESEND_API_KEY")
    from_email = current_app.config.get("MAIL_FROM_EMAIL")
    from_name = current_app.config.get("MAIL_FROM_NAME") or "Flowra Task"

    if not api_key or not from_email:
        _last_error = "RESEND_API_KEY/MAIL_FROM_EMAIL is missing in .env"
        print("Email skipped:", _last_error)
        return False

    if not to_email:
        _last_error = "no recipient email address on the account"
        print("Email skipped:", _last_error)
        return False

    payload = {
        "from": f"{from_name} <{from_email}>",
        "to": [to_email],
        "subject": subject,
        "html": html_body,
    }

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "FlowraTask/1.0 ({})".format(from_email),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8")
            print("Resend email sent to", to_email, "| response:", body)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        _last_error = "Resend returned HTTP {}".format(e.code)
        try:
            parsed = json.loads(body)
            if parsed.get("message"):
                _last_error += " - " + parsed["message"]
        except Exception:
            if body.strip():
                _last_error += " - " + body.strip()[:160]
        print("Resend HTTP error", e.code, "|", body)
        return False
    except Exception as e:
        _last_error = "{}: {}".format(type(e).__name__, e)
        print("Resend email error:", e)
        return False


def _rupee(value):
    try:
        return "₹{:,}".format(int(value or 0))
    except (TypeError, ValueError):
        return "₹0"


def _plan_and_billing_section(plan):
    """Render the plan/billing table shown only to company admins."""
    if not plan:
        return ""

    slots = plan.get("plan_slots") or 0
    per_user = plan.get("per_employee_charge") or 0
    total = plan.get("total_amount")
    if total is None:
        total = slots * per_user

    gstin = plan.get("gstin") or ""
    address = plan.get("address") or ""

    rows = [
        ("User Limit (Total Users)", "<strong>{}</strong>".format(slots)),
        ("Per User Charge", "<strong>{}</strong>".format(_rupee(per_user))),
        ("Total Amount", "<strong>{}</strong>".format(_rupee(total))),
    ]
    if gstin:
        rows.append(("Company GSTIN", gstin))
    if address:
        rows.append(("Company Address", address))

    body = "".join(
        '<tr>'
        '<td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">{}</td>'
        '<td style="padding:8px 10px;border:1px solid #e5e7eb;">{}</td>'
        '</tr>'.format(label, value)
        for label, value in rows
    )

    return """
    <h3 style="color:#1d4ed8;margin:24px 0 8px;font-size:15px;">Your Plan &amp; Billing</h3>
    <p style="margin:0 0 8px;color:#475569;font-size:13px;">
        You can add up to <strong>{slots}</strong> users (managers + employees) in your company
        at <strong>{per_user}</strong> per user. Your total plan value is <strong>{total}</strong>.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:8px 0 16px;">
        {body}
    </table>
    <p style="margin:0 0 4px;color:#475569;font-size:13px;">
        <strong>Note:</strong> User Limit counts managers and employees. The Company
        Admin account itself are not counted.
    </p>
    <p style="margin:0 0 4px;color:#475569;font-size:13px;">
        <strong>Note:</strong> Billing is raised separately from the Payments page by Jodidar India.
    </p>
    """.format(slots=slots, per_user=_rupee(per_user), total=_rupee(total), body=body)


def send_account_deleted_email(to_email, username, role=None, company=None,
                               deleted_by=None, reason=None, extra_note=None):
    """Notify a user that their Flowra account has been deleted."""
    role_label = {
        "super_admin": "Super Admin",
        "admin": "Admin",
        "manager": "Manager",
        "employee": "Employee"
    }.get(role, role or "User")

    company_line = f"<strong>{company}</strong>" if company else "<em>(not set)</em>"
    by_line = f"<strong>{deleted_by}</strong>" if deleted_by else "an administrator"

    reason_html = ""
    if reason:
        reason_html = (
            '<tr>'
            '<td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Reason</td>'
            '<td style="padding:8px 10px;border:1px solid #e5e7eb;">{}</td>'
            '</tr>'.format(reason)
        )

    note_html = ""
    if extra_note:
        note_html = (
            '<div style="margin:12px 0;padding:10px 12px;background:#fff7ed;border:1px solid #fed7aa;'
            'border-radius:8px;color:#9a3412;font-size:13px;">{}</div>'.format(extra_note)
        )

    html_body = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="margin-top:0;color:#b91c1c;">Flowra Task account deleted</h2>
        <p>Hello {username},</p>
        <p>
            Your Flowra Task account has been <strong>deleted</strong> and you can no longer sign in.
            All data linked to this account has been removed as well.
        </p>
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
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Role</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{role_label}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Company</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{company_line}</td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Status</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;color:#b91c1c;"><strong>Deleted</strong></td>
            </tr>
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Deleted by</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">{by_line}</td>
            </tr>
            {reason_html}
        </table>
        {note_html}
        <p style="color:#475569;font-size:13px;">
            If you believe this was a mistake, please contact us and we will help you get access back.
        </p>
        {_branded_footer()}
    </div>
    """

    return send_email(
        to_email,
        "Your Flowra Task account has been deleted",
        html_body
    )


def send_account_credentials_email(to_email, username, password, role=None, company=None,
                                    status="active", plan=None):
    """Send the auto-generated credentials for a newly created account.

    plan: optional dict with plan_slots, per_employee_charge, total_amount,
          gstin and address - included only for company admins.
    """
    role_label = {
        "super_admin": "Super Admin",
        "admin": "Admin",
        "manager": "Manager",
        "employee": "Employee"
    }.get(role, role or "User")

    company_line = f"<strong>{company}</strong>" if company else "<em>(not set)</em>"
    status_label = "Active" if status == "active" else status.capitalize()

    plan_html = _plan_and_billing_section(plan) if role == "admin" else ""

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
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Username (to sign in)</td>
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
            <tr>
                <td style="padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:bold;">Sign in at</td>
                <td style="padding:8px 10px;border:1px solid #e5e7eb;">
                    <a href="{SITE_URL}" style="color:#1d4ed8;text-decoration:underline;">{SITE_URL}</a>
                </td>
            </tr>
        </table>
        {plan_html}
        <p>For security, please change your password after your first sign-in.</p>
        <p style="margin-bottom:0;color:#64748b;font-size:12px;">This is an automated message - please do not reply.</p>
        {_branded_footer()}
    </div>
    """

    return send_email(
        to_email,
        "Your Flowra Task account credentials",
        html_body
    )