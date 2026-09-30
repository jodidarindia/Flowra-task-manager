import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")

    MONGO_URI = os.environ.get("MONGO_URI")

    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_WHATSAPP_NUMBER = os.environ.get("TWILIO_WHATSAPP_NUMBER")
    TWILIO_WHATSAPP_TEMPLATE_SID = os.environ.get("TWILIO_WHATSAPP_TEMPLATE_SID")

    RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
    MAIL_FROM_EMAIL = os.environ.get("MAIL_FROM_EMAIL")
    MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "Flowra Task")