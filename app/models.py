from flask_login import UserMixin
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid


class RecurringTask(db.Model):
    __tablename__ = "recurring_task"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))
    employee = db.relationship("User")

    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

    frequency = db.Column(db.String(20))
    last_generated = db.Column(db.Date)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("department.id"))
    department = db.relationship("Department")
    password_hash = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    points = db.Column(db.Integer, default=0)
    role = db.Column(db.String(20), default="employee")
    supervisor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Login control
    is_logged_in = db.Column(db.Boolean, default=False, nullable=False)
    active_session_token = db.Column(db.String(255), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    # Tasks the user created
    tasks_created = db.relationship(
        "Task",
        foreign_keys="Task.created_by",
        back_populates="creator",
        lazy=True
    )

    # Tasks assigned to the user
    tasks_assigned = db.relationship(
        "Task",
        foreign_keys="Task.assigned_to",
        back_populates="assignee",
        lazy=True
    )

    # Subordinates (for manager)
    subordinates = db.relationship(
        "User",
        backref=db.backref("supervisor", remote_side=[id]),
        lazy=True
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LoginRequest(db.Model):
    __tablename__ = "login_request"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    device_info = db.Column(db.String(255))
    ip_address = db.Column(db.String(100))
    token = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="login_requests")


class Task(db.Model):
    __tablename__ = "task"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(10))
    status = db.Column(db.String(30), default="Pending")
    reward_points = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, nullable=True)
    remarks = db.Column(db.Text)
    due_date = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean, default=False)
    attachment = db.Column(db.String(255))
    proof_file = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reminder_active = db.Column(db.Boolean, default=False)
    reminder_interval = db.Column(db.Integer)
    reminder_end_time = db.Column(db.DateTime, nullable=True)
    estimated_time = db.Column(db.Integer, nullable=True)

    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))

    creator = db.relationship(
        "User",
        foreign_keys=[created_by],
        back_populates="tasks_created"
    )
    assignee = db.relationship(
        "User",
        foreign_keys=[assigned_to],
        back_populates="tasks_assigned"
    )

    work_status = db.Column(db.String(20), default="not_started")
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    total_time_spent = db.Column(db.Integer, default=0)
    is_timer_running = db.Column(db.Boolean, default=False)

    attachments = db.relationship(
        "TaskAttachment",
        backref="task",
        lazy=True,
        cascade="all, delete-orphan"
    )
    subtasks = db.relationship(
        "SubTask",
        backref="task",
        lazy=True,
        cascade="all, delete-orphan"
    )


class TaskAttachment(db.Model):
    __tablename__ = "task_attachment"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class SubTask(db.Model):
    __tablename__ = "sub_task"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Reminder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.String(200), nullable=False)
    remind_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=True)

    is_daily = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    user = db.relationship("User", backref="reminders")


class Department(db.Model):
    __tablename__ = "department"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Announcement(db.Model):
    __tablename__ = "announcement"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    creator = db.relationship("User", backref="announcements")

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
        return check_password_hash(self.data.get("password_hash", ""), password)


def hash_password(password):
    return generate_password_hash(password)
