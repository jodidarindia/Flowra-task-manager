from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from flask import current_app


def send_whatsapp_message(to_number, message, template_sid=None, template_variables=None):
    """Send a WhatsApp message.

    Production mode: if TWILIO_WHATSAPP_TEMPLATE_SID is configured (or template_sid
    is passed), the message is sent using the Twilio Content Templates API, which is
    required for registered WhatsApp senders (real/production numbers).

    Sandbox / trial mode: falls back to a plain `body`, which is allowed for the
    Twilio WhatsApp Sandbox.

    `to_number` may be passed as "919876543210", "+919876543210" or
    "+91 98765 43210" - the whatsapp: prefix is applied automatically.
    """
    account_sid = current_app.config.get("TWILIO_ACCOUNT_SID")
    auth_token = current_app.config.get("TWILIO_AUTH_TOKEN")
    twilio_number = current_app.config.get("TWILIO_WHATSAPP_NUMBER")

    if not account_sid or not auth_token or not twilio_number:
        print("WhatsApp skipped: Twilio credentials not configured (TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_WHATSAPP_NUMBER missing).")
        return False

    clean_number = to_number.replace(" ", "").replace("-", "")
    if not clean_number.startswith("+"):
        clean_number = "+" + clean_number

    client = Client(account_sid, auth_token)

    msg_kwargs = {
        "from_": f"whatsapp:{twilio_number}",
        "to": f"whatsapp:{clean_number}",
    }

    use_template = template_sid or current_app.config.get("TWILIO_WHATSAPP_TEMPLATE_SID")
    if use_template:
        msg_kwargs["content_sid"] = use_template
        vars_ = template_variables or {}
        if vars_:
            msg_kwargs["content_variables"] = vars_
    else:
        msg_kwargs["body"] = message

    try:
        msg = client.messages.create(**msg_kwargs)
        print("WhatsApp Sent SID:", msg.sid)
        print("WhatsApp Status:", msg.status)
        return True
    except TwilioRestException as e:
        print("Twilio error code:", e.code)
        print("Twilio error message:", e.msg)
        print("Twilio HTTP status:", e.status)
        return False
    except Exception as e:
        print("Error sending WhatsApp message:", e)
        return False