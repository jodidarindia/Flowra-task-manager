from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class MongoUser(UserMixin):
    def __init__(self, data):
        self.data = data or {}

    def get_id(self):
        return str(self.data.get("_id"))

    def __getattr__(self, name):
        return self.data.get(name)

    def check_password(self, password):
        return check_password_hash(
            self.data.get("password_hash", ""),
            password
        )

    @property
    def id(self):
        return str(self.data.get("_id"))

    @property
    def username(self):
        return self.data.get("username")

    @property
    def email(self):
        return self.data.get("email")

    @property
    def role(self):
        return self.data.get("role")

    @property
    def phone(self):
        return self.data.get("phone")

    @property
    def points(self):
        return self.data.get("points", 0)

    @property
    def department_id(self):
        return self.data.get("department_id")

    @property
    def supervisor_id(self):
        return self.data.get("supervisor_id")

    @property
    def is_logged_in(self):
        return self.data.get("is_logged_in", False)

    @property
    def active_session_token(self):
        return self.data.get("active_session_token")

    @property
    def last_seen(self):
        return self.data.get("last_seen")


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)