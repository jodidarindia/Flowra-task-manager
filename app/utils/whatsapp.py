from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from flask import current_app


def send_whatsapp_message(to_number, message):
    try:
        account_sid = current_app.config["TWILIO_ACCOUNT_SID"]
        auth_token = current_app.config["TWILIO_AUTH_TOKEN"]
        twilio_number = current_app.config["TWILIO_WHATSAPP_NUMBER"]

        print("TWILIO_ACCOUNT_SID:", account_sid)
        print("TWILIO_AUTH_TOKEN exists:", bool(auth_token))
        print("TWILIO_WHATSAPP_NUMBER:", twilio_number)
        print("TO NUMBER:", to_number)

        client = Client(account_sid, auth_token)

        msg = client.messages.create(
            body=message,
            from_=f"whatsapp:{twilio_number}",
            to=f"whatsapp:{to_number}"
        )

        print("Message Sent SID:", msg.sid)
        print("Message Status:", msg.status)

    except TwilioRestException as e:
        print("Twilio error code:", e.code)
        print("Twilio error message:", e.msg)
        print("Twilio HTTP status:", e.status)
    except Exception as e:
        print("Error sending WhatsApp message:", e)