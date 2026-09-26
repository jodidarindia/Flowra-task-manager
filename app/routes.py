from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, session, current_app, send_from_directory,
    send_file, make_response, g
)
from flask import abort
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from app.extensions import mongo
from app.models import MongoUser, hash_password
from app.utils.whatsapp import send_whatsapp_message
from app.utils.phone import normalize_phone
from bson import ObjectId
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
from io import BytesIO
import pandas as pd
import os
import re
import uuid
import io
import csv
import json
import secrets

bp = Blueprint("main", __name__)

from zoneinfo import ZoneInfo
from datetime import datetime
from flask import session, flash, redirect, url_for
from flask_login import current_user, logout_user

def to_ist(dt):
    if not dt:
        return None

    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except Exception:
            return None

    return dt.replace(
        tzinfo=ZoneInfo("UTC")
    ).astimezone(
        ZoneInfo("Asia/Kolkata")
    )


DEFAULT_SYSTEM_SETTINGS = {
    "app_name": "Flowra Task",
    "support_contact": "it-helpdesk@flowra.io",
    "timezone": "Asia/Kolkata",
    "date_format": "DD MMM YYYY",
    "default_role": "employee",
    "auto_deactivate_days": 90,
    "notify_new_task": True,
    "notify_status_change": True,
    "notify_reminder_due": True,
    "notify_task_overdue": True,
    "notify_announcement": True,
    "announcement_priority": "normal",
    "announcement_expiry_days": 14,
    "session_timeout_hours": 8,
    "min_password_length": 8,
    "lock_after_attempts": 5,
    "per_employee_charge": 100,
}


def get_system_settings():
    doc = mongo.db.system_settings.find_one({"_id": "global"})
    if not doc:
        doc = dict(DEFAULT_SYSTEM_SETTINGS)
        doc["_id"] = "global"
        mongo.db.system_settings.insert_one(doc)
    return doc


def device_label(user_agent):
    ua = user_agent or ""
    low = ua.lower()

    if not ua.strip() or "python-requests" in low or "werkzeug" in low:
        return "Web Â· this browser"

    browser = "Browser"
    if "edg/" in low or "edge/" in low:
        browser = "Edge"
    elif "opr/" in low or "opera" in low:
        browser = "Opera"
    elif "chrome/" in low:
        browser = "Chrome"
    elif "firefox/" in low:
        browser = "Firefox"
    elif "safari/" in low:
        browser = "Safari"

    platform = "device"
    if "windows" in low:
        platform = "Windows"
    elif "android" in low:
        platform = "Android"
    elif "iphone" in low or "ipad" in low:
        platform = "iOS"
    elif "mac os" in low or "macintosh" in low:
        platform = "macOS"
    elif "linux" in low:
        platform = "Linux"

    return "Web Â· {} on {}".format(browser, platform)


def log_activity(event_type, module, description, user_id=None, username=None, device=None, meta=None):

    if user_id is None and current_user.is_authenticated:
        user_id = str(current_user.get_id())

    if username is None and current_user.is_authenticated:
        username = current_user.username

    username = username or "System"
    name_parts = (username or "").split()
    initials = "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "S"

    doc = {
        "user_id": user_id,
        "username": username,
        "initials": initials[:2],
        "event_type": event_type,
        "module": module,
        "description": description,
        "device": device or "Web Â· this browser",
        "created_at": datetime.utcnow(),
    }

    if meta:
        doc.update(meta)

    mongo.db.activity_log.insert_one(doc)


def log_task_activity(task_id, action, description=None, username=None):

    if task_id is None:
        return

    if username is None and current_user.is_authenticated:
        username = current_user.username

    username = username or "System"
    name_parts = (username or "").split()
    initials = "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "S"

    mongo.db.task_activity.insert_one({
        "task_id": task_id,
        "action": action,
        "description": description or "",
        "username": username,
        "initials": initials[:2],
        "created_at": datetime.utcnow(),
    })


def parse_date_arg(value):
    if not value:
        return None

    for fmt in ("%d-%m-%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue

    return None


def reconcile_lock_notifications():

    lock_after_attempts = get_system_settings().get("lock_after_attempts", 5)

    for n in mongo.db.notifications.find({"type": "account_locked"}):
        user_doc = None
        if n.get("ref_user_id"):
            try:
                user_doc = mongo.db.users.find_one({"_id": ObjectId(n["ref_user_id"])})
            except Exception:
                user_doc = None

        live_locked = bool(user_doc) and user_doc.get("failed_attempts", 0) >= lock_after_attempts

        if n.get("resolved") is not (not live_locked):
            mongo.db.notifications.update_one(
                {"_id": n["_id"]},
                {"$set": {"resolved": (not live_locked)}}
            )

    for u in mongo.db.users.find({"failed_attempts": {"$gte": lock_after_attempts}}):
        open_notif = mongo.db.notifications.count_documents({
            "type": "account_locked",
            "ref_user_id": str(u["_id"]),
            "resolved": {"$ne": True}
        })

        if not open_notif:
            mongo.db.notifications.insert_one({
                "type": "account_locked",
                "message": "{}'s account locked after {} failed login attempts".format(
                    u.get("username"), u.get("failed_attempts")
                ),
                "target_role": "super_admin",
                "ref_user_id": str(u["_id"]),
                "ref_username": u.get("username"),
                "read": False,
                "resolved": False,
                "created_at": u.get("last_seen") or datetime.utcnow()
            })


def build_activity_query(current_user_obj, args):

    query = {}

    if current_user_obj.role == "super_admin":
        pass

    elif current_user_obj.role == "admin":
        company = current_user_obj.company or ""
        scoped_ids = [str(u["_id"]) for u in
                      mongo.db.users.find({"company": company})]
        scoped_ids.append(str(current_user_obj.get_id()))
        query["user_id"] = {"$in": scoped_ids}

    elif current_user_obj.role == "manager":
        scoped_ids = [str(e["_id"]) for e in
                      mongo.db.users.find({"supervisor_id": str(current_user_obj.get_id())})]
        scoped_ids.append(str(current_user_obj.get_id()))
        query["user_id"] = {"$in": scoped_ids}

    else:
        query["user_id"] = str(current_user_obj.get_id())

    filter_user = args.get("user", "").strip()
    if filter_user:
        query["user_id"] = filter_user

    filter_action = args.get("action", "").strip()
    if filter_action:
        query["event_type"] = filter_action

    filter_module = args.get("module", "").strip()
    if filter_module:
        query["module"] = filter_module

    q = args.get("q", "").strip()
    if q:
        query["description"] = {"$regex": re.escape(q), "$options": "i"}

    from_dt = parse_date_arg(args.get("from", ""))
    to_dt = parse_date_arg(args.get("to", ""))

    if from_dt or to_dt:
        range_query = {}
        if from_dt:
            range_query["$gte"] = from_dt.replace(hour=0, minute=0, second=0)
        if to_dt:
            range_query["$lte"] = to_dt.replace(hour=23, minute=59, second=59)
        query["created_at"] = range_query

    return query


@bp.before_app_request
def keep_session_alive():
    g.unread_notifications = 0

    if current_user.is_authenticated:

        saved_token = session.get("session_token")
        current_token = getattr(current_user, "active_session_token", None)

        if current_token and saved_token != current_token:
            logout_user()
            session.clear()
            return redirect(url_for("main.login"))

        if current_user.role == "super_admin":
            reconcile_lock_notifications()
            g.unread_notifications = mongo.db.notifications.count_documents({
                "target_role": "super_admin",
                "read": False
            })
@bp.route("/")
def home():
    return render_template("home.html")


# ---------------- LOGIN ----------------
@bp.route("/login", methods=["GET", "POST"])
def login():

    existing_admin = mongo.db.users.find_one({"role": {"$in": ["admin", "super_admin"]}})

    if not existing_admin:
        mongo.db.users.insert_one({
            "username": "admin",
            "email": "admin@example.com",
            "role": "super_admin",
            "password_hash": hash_password("admin123"),
            "phone": "",
            "points": 0,
            "is_logged_in": False,
            "active_session_token": None,
            "last_seen": None,
            "created_at": datetime.utcnow()
        })

        print("Default super admin created: admin / admin123")

    if request.method == "POST":

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password")

        user_doc = mongo.db.users.find_one({"username": username})

        if user_doc is None:
            user_doc = mongo.db.users.find_one({"email": {
                "$regex": "^{}$".format(re.escape(username)), "$options": "i"
            }})

        if user_doc is None:
            user_doc = mongo.db.users.find_one({
                "username": {"$regex": "^{}$".format(re.escape(username)), "$options": "i"}
            })

        if user_doc and check_password_hash(user_doc.get("password_hash", ""), password):

            if user_doc.get("status") == "inactive":
                return jsonify({
                    "status": "error",
                    "message": "This account is inactive. Please contact your administrator."
                })

            lock_after_attempts = get_system_settings().get("lock_after_attempts", 5)

            if user_doc.get("failed_attempts", 0) >= lock_after_attempts:
                return jsonify({
                    "status": "error",
                    "message": "Account locked due to too many failed attempts. Please contact your administrator."
                })

            mongo.db.login_requests.delete_many({
                "user_id": str(user_doc["_id"])
            })

            log_activity(
                event_type="login",
                module="Auth",
                description="{} signed in".format(user_doc.get("username")),
                user_id=str(user_doc["_id"]),
                username=user_doc.get("username"),
                device=device_label(request.headers.get("User-Agent"))
            )

            session_token = str(uuid.uuid4())

            mongo.db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {
                    "is_logged_in": True,
                    "active_session_token": session_token,
                    "last_seen": datetime.utcnow(),
                    "failed_attempts": 0
                }}
            )

            updated_user = mongo.db.users.find_one({"_id": user_doc["_id"]})

            login_user(MongoUser(updated_user))

            session["last_activity"] = datetime.utcnow().isoformat()
            session["session_token"] = session_token

            role = updated_user.get("role")

            if role in ("super_admin", "admin"):
                return jsonify({
                    "status": "success",
                    "redirect": url_for("main.admin_panel")
                })

            elif role == "manager":
                return jsonify({
                    "status": "success",
                    "redirect": url_for("main.manager_panel")
                })

            else:
                return jsonify({
                    "status": "success",
                    "redirect": url_for("main.employee_panel")
                })

        if user_doc:

            new_failed = user_doc.get("failed_attempts", 0) + 1

            mongo.db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {"failed_attempts": new_failed}}
            )

            lock_after_attempts = get_system_settings().get("lock_after_attempts", 5)

            if new_failed == lock_after_attempts:

                log_activity(
                    event_type="account_locked",
                    module="Auth",
                    description="{}'s account locked after {} failed login attempts".format(
                        user_doc.get("username"), new_failed
                    ),
                    user_id=str(user_doc["_id"]),
                    username=user_doc.get("username"),
                    device=device_label(request.headers.get("User-Agent"))
                )

                mongo.db.notifications.insert_one({
                    "type": "account_locked",
                    "message": "{}'s account locked after {} failed login attempts".format(
                        user_doc.get("username"), new_failed
                    ),
                    "target_role": "super_admin",
                    "ref_user_id": str(user_doc["_id"]),
                    "ref_username": user_doc.get("username"),
                    "read": False,
                    "resolved": False,
                    "created_at": datetime.utcnow()
                })

        return jsonify({
            "status": "error",
            "message": "Invalid username or password"
        })

    return render_template("login.html")


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        username = (request.form.get("username") or "").strip()
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not username or not new_password:
            flash("Username and new password are required", "danger")
            return redirect(url_for("main.forgot_password"))

        if new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("main.forgot_password"))

        min_password_length = get_system_settings().get("min_password_length", 8)

        if len(new_password) < min_password_length:
            flash("Password must be at least {} characters".format(min_password_length), "danger")
            return redirect(url_for("main.forgot_password"))

        user_doc = mongo.db.users.find_one({
            "username": {"$regex": "^{}$".format(re.escape(username)), "$options": "i"}
        })

        if not user_doc:
            flash("No account found with that username", "danger")
            return redirect(url_for("main.forgot_password"))

        mongo.db.users.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {
                "password_hash": hash_password(new_password),
                "is_logged_in": False,
                "active_session_token": None
            }}
        )

        flash("Password updated successfully. You can now login.", "success")
        return redirect(url_for("main.login"))

    return render_template("forgot_password.html")


@bp.route("/check-login-status/<token>")
def check_login_status(token):

    req = mongo.db.login_requests.find_one({
        "token": token
    })

    if not req:
        return jsonify({
            "status": "Denied",
            "message": "Request not found"
        })

    return jsonify({
        "status": req.get("status", "Pending")
    })


@bp.route("/notifications/unlock/<user_id>", methods=["POST"])
@login_required
def unlock_account(user_id):

    if current_user.role != "super_admin":
        return jsonify({"success": False, "message": "Unauthorized access"}), 403

    user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if not user_doc:
        return jsonify({"success": False, "message": "User not found"}), 404

    mongo.db.users.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "failed_attempts": 0,
            "is_logged_in": False,
            "active_session_token": None
        }}
    )

    mongo.db.notifications.update_many(
        {"type": "account_locked", "ref_user_id": str(user_doc["_id"])},
        {"$set": {"resolved": True}}
    )

    log_activity(
        event_type="account_unlocked",
        module="Auth",
        description="{} unlocked {}'s account".format(
            current_user.username, user_doc.get("username")
        ),
        user_id=str(current_user.get_id()),
        username=current_user.username,
        device=device_label(request.headers.get("User-Agent"))
    )

    return jsonify({"success": True, "username": user_doc.get("username")})


@bp.route("/notifications/reset-password/<user_id>", methods=["POST"])
@login_required
def reset_user_password(user_id):

    if current_user.role != "super_admin":
        return jsonify({"success": False, "message": "Unauthorized access"}), 403

    user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if not user_doc:
        return jsonify({"success": False, "message": "User not found"}), 404

    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    new_password = "".join(secrets.choice(alphabet) for _ in range(10))

    mongo.db.users.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "password_hash": hash_password(new_password),
            "failed_attempts": 0,
            "is_logged_in": False,
            "active_session_token": None
        }}
    )

    mongo.db.notifications.update_many(
        {"type": "account_locked", "ref_user_id": str(user_doc["_id"])},
        {"$set": {"resolved": True}}
    )

    log_activity(
        event_type="password_reset",
        module="Auth",
        description="{} generated a new password for {}".format(
            current_user.username, user_doc.get("username")
        ),
        user_id=str(current_user.get_id()),
        username=current_user.username,
        device=device_label(request.headers.get("User-Agent"))
    )

    return jsonify({
        "success": True,
        "username": user_doc.get("username"),
        "new_password": new_password
    })


@bp.route("/complete-login/<token>")
def complete_login(token):

    req = mongo.db.login_requests.find_one({
        "token": token,
        "status": "Approved"
    })

    if not req:
        flash("Access denied or request expired.", "danger")
        return redirect(url_for("main.login"))

    user_doc = mongo.db.users.find_one({
        "_id": ObjectId(req.get("user_id"))
    })

    if not user_doc:
        flash("User not found.", "danger")
        return redirect(url_for("main.login"))

    session_token = str(uuid.uuid4())

    mongo.db.users.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "is_logged_in": True,
            "active_session_token": session_token,
            "last_seen": datetime.utcnow()
        }}
    )

    mongo.db.login_requests.update_one(
        {"_id": req["_id"]},
        {"$set": {
            "status": "Completed"
        }}
    )

    updated_user = mongo.db.users.find_one({
        "_id": user_doc["_id"]
    })

    login_user(MongoUser(updated_user))

    session["last_activity"] = datetime.utcnow().isoformat()
    session["session_token"] = session_token

    role = updated_user.get("role")

    if role in ("super_admin", "admin"):
        return redirect(url_for("main.admin_panel"))

    elif role == "manager":
        return redirect(url_for("main.manager_panel"))

    else:
        return redirect(url_for("main.employee_panel"))


@bp.route("/approve-login/<req_id>", methods=["POST"])
@login_required
def approve_login(req_id):

    req = mongo.db.login_requests.find_one({
        "_id": ObjectId(req_id)
    })

    if not req:
        return jsonify({
            "success": False,
            "message": "Request not found"
        }), 404

    session_token = str(uuid.uuid4())

    mongo.db.login_requests.update_one(
        {"_id": ObjectId(req_id)},
        {"$set": {
            "status": "Approved"
        }}
    )

    mongo.db.users.update_one(
        {"_id": ObjectId(req.get("user_id"))},
        {"$set": {
            "is_logged_in": True,
            "active_session_token": session_token,
            "last_seen": datetime.utcnow()
        }}
    )

    return jsonify({
        "success": True
    })


@bp.route("/deny-login/<req_id>", methods=["POST"])
@login_required
def deny_login(req_id):

    req = mongo.db.login_requests.find_one({
        "_id": ObjectId(req_id)
    })

    if not req:
        return jsonify({
            "success": False,
            "message": "Request not found"
        }), 404

    mongo.db.login_requests.update_one(
        {"_id": ObjectId(req_id)},
        {"$set": {
            "status": "Denied"
        }}
    )

    mongo.db.users.update_one(
        {"_id": ObjectId(req.get("user_id"))},
        {"$set": {
            "is_logged_in": False,
            "active_session_token": None
        }}
    )

    return jsonify({
        "success": True
    })

@bp.route("/pending-logins")
@login_required
def pending_logins():

    current_device = request.headers.get("User-Agent")

    requests_data = mongo.db.login_requests.find({
        "user_id": str(current_user.get_id()),
        "status": "Pending"
    })

    filtered_requests = []

    for r in requests_data:

        if r.get("device_info") != current_device:

            filtered_requests.append({
                "id": str(r.get("_id")),
                "device": r.get("device_info", "Unknown device")
            })

    return jsonify(filtered_requests)

# ---------------- DASHBOARD ----------------
@bp.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "super_admin":
        return redirect(url_for("main.admin_panel"))
    elif current_user.role == "admin":
        return redirect(url_for("main.admin_panel"))
    elif current_user.role == "manager":
        return redirect(url_for("main.manager_panel"))
    return redirect(url_for("main.employee_panel"))


@bp.route("/reminders_page")
@login_required
def reminders_page():
    return render_template("reminders.html")


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():

    if request.method == "POST":

        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password and new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("main.settings"))

        min_password_length = get_system_settings().get("min_password_length", 8)

        if new_password and len(new_password) < min_password_length:
            flash("Password must be at least {} characters".format(min_password_length), "danger")
            return redirect(url_for("main.settings"))

        updates = {}
        if new_password:
            updates["password_hash"] = hash_password(new_password)

        if updates:
            mongo.db.users.update_one(
                {"_id": ObjectId(current_user.get_id())},
                {"$set": updates}
            )
            flash("Settings updated successfully.", "success")
            return redirect(url_for("main.settings"))

        flash("No changes to save", "warning")
        return redirect(url_for("main.settings"))

    user = mongo.db.users.find_one({"_id": ObjectId(current_user.get_id())})
    return render_template("settings.html", user=user)


def _to_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@bp.route("/system-settings", methods=["GET", "POST"])
@login_required
def system_settings():

    if current_user.role != "super_admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("main.settings"))

    if request.method == "POST":

        action = request.form.get("action")

        if action == "reset":
            settings_data = dict(DEFAULT_SYSTEM_SETTINGS)
        else:

            def _bool(v):
                return v in ("on", "true", "1", "yes")

            settings_data = {
                "app_name": (request.form.get("app_name") or "Flowra Task").strip(),
                "support_contact": (request.form.get("support_contact") or "").strip(),
                "timezone": request.form.get("timezone") or "Asia/Kolkata",
                "date_format": request.form.get("date_format") or "DD MMM YYYY",
                "default_role": request.form.get("default_role") or "employee",
                "auto_deactivate_days": _to_int(request.form.get("auto_deactivate_days"), 90),
                "notify_new_task": _bool(request.form.get("notify_new_task")),
                "notify_status_change": _bool(request.form.get("notify_status_change")),
                "notify_reminder_due": _bool(request.form.get("notify_reminder_due")),
                "notify_task_overdue": _bool(request.form.get("notify_task_overdue")),
                "notify_announcement": _bool(request.form.get("notify_announcement")),
                "announcement_priority": request.form.get("announcement_priority") or "normal",
                "announcement_expiry_days": _to_int(request.form.get("announcement_expiry_days"), 14),
                "session_timeout_hours": _to_int(request.form.get("session_timeout_hours"), 8),
                "min_password_length": _to_int(request.form.get("min_password_length"), 8),
                "lock_after_attempts": _to_int(request.form.get("lock_after_attempts"), 5),
                "per_employee_charge": _to_int(request.form.get("per_employee_charge"), 100),
            }

        mongo.db.system_settings.update_one(
            {"_id": "global"},
            {"$set": settings_data},
            upsert=True
        )

        mongo.db.system_activity.insert_one({
            "username": current_user.username,
            "action": "System settings reset to defaults" if action == "reset" else "System settings updated",
            "created_at": datetime.utcnow()
        })

        if action == "reset":
            flash("System settings reset to defaults successfully.", "success")
        else:
            flash("System settings saved successfully. Changes apply system-wide.", "success")

        return redirect(url_for("main.system_settings"))

    settings_doc = get_system_settings()

    return render_template("system_settings.html", settings=settings_doc)


@bp.route("/api/search")
@login_required
def api_search():

    q = (request.args.get("q") or "").strip()

    if not q:
        return jsonify({"tasks": [], "people": [], "departments": []})

    rx = re.compile(re.escape(q), re.IGNORECASE)

    role = current_user.role
    uid = str(current_user.get_id())

    user_map = {}
    for u in mongo.db.users.find():
        user_map[str(u["_id"])] = u

    dept_map = {}
    for d in mongo.db.departments.find():
        dept_map[str(d["_id"])] = d

    def dept_name(uid_):
        u = user_map.get(uid_)
        if not u:
            return ""
        d = dept_map.get(u.get("department_id"))
        return d.get("name") if d else ""

    if role in ("super_admin",):
        task_pool = list(mongo.db.tasks.find({"is_deleted": {"$ne": True}}))
        user_pool = list(mongo.db.users.find())
        dept_pool = list(mongo.db.departments.find())
    elif role == "admin":
        company = mongo.db.users.find_one({"_id": ObjectId(uid)}).get("company") if uid else None
        user_pool = list(mongo.db.users.find({"company": company}))
        task_pool = [t for t in mongo.db.tasks.find({"is_deleted": {"$ne": True}})
                     if str(t.get("assigned_to") or "") in {str(u["_id"]) for u in user_pool}]
        dept_pool = list(mongo.db.departments.find({"company": company}))
    elif role == "manager":
        manager = mongo.db.users.find_one({"_id": ObjectId(uid)})
        manager_dept_id = (manager or {}).get("department_id")
        emp_docs = list(mongo.db.users.find({
            "role": "employee",
            **({"department_id": manager_dept_id} if manager_dept_id else {"supervisor_id": uid})
        }))
        emp_id_set = {str(e["_id"]) for e in emp_docs}
        task_pool = [t for t in mongo.db.tasks.find({"is_deleted": {"$ne": True}})
                     if str(t.get("assigned_to") or "") in emp_id_set]
        user_pool = emp_docs
        if manager_dept_id:
            dept_pool = list(mongo.db.departments.find({"_id": ObjectId(manager_dept_id)}))
        else:
            dept_pool = []
    else:
        task_pool = list(mongo.db.tasks.find({
            "assigned_to": uid,
            "is_deleted": {"$ne": True}
        }))
        user_pool = [u for u in mongo.db.users.find() if str(u["_id"]) == uid]
        dept_pool = []

    results = {"tasks": [], "people": [], "departments": []}

    for u in user_pool:
        if not rx.search(u.get("username") or ""):
            continue
        results["people"].append({
            "id": str(u["_id"]),
            "username": u.get("username", "-"),
            "role": u.get("role", "-"),
            "department": dept_name(str(u["_id"])),
        })
        if len(results["people"]) >= 6:
            break

    for t in task_pool:
        assignee = user_map.get(t.get("assigned_to"))
        aname = assignee.get("username") if assignee else ""
        title = t.get("title") or ""
        if not (rx.search(title) or rx.search(aname)):
            continue
        results["tasks"].append({
            "id": str(t["_id"]),
            "title": title,
            "employee": aname,
            "department": dept_name(t.get("assigned_to")),
            "status": t.get("status", "-"),
        })
        if len(results["tasks"]) >= 6:
            break

    for d in dept_pool:
        if not rx.search(d.get("name") or ""):
            continue
        results["departments"].append({
            "id": str(d["_id"]),
            "name": d.get("name", "-"),
        })
        if len(results["departments"]) >= 6:
            break

    return jsonify(results)


@bp.route("/my-reminders")
@login_required
def my_reminders():

    reminders = list(
        mongo.db.reminders.find({
            "user_id": str(current_user.get_id())
        }).sort("remind_at", -1)
    )

    for r in reminders:
        r["id"] = str(r["_id"])

    return render_template(
        "my_reminders.html",
        reminders=reminders
    )


@bp.route("/stop-reminder-page/<id>", methods=["POST"])
@login_required
def stop_reminder_page(id):

    reminder = mongo.db.reminders.find_one({
        "_id": ObjectId(id)
    })

    if not reminder:
        flash("Reminder not found", "danger")
        return redirect(url_for("main.my_reminders"))

    if reminder.get("user_id") != str(current_user.get_id()):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.my_reminders"))

    mongo.db.reminders.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"active": False}}
    )

    flash("Reminder stopped successfully!", "success")
    return redirect(url_for("main.my_reminders"))


# ---------------- CREATE TASK ----------------

@bp.route("/create_task", methods=["GET", "POST"])
@login_required
def create_task():

    if current_user.role not in ["super_admin", "admin", "manager"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":

        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority")
        assigned_to_id = request.form.get("assigned_to")
        category = request.form.get("category")
        notes = request.form.get("notes")

        print("=" * 50)
        print("FORM DATA =", request.form)
        print("ASSIGNED_TO_ID =", assigned_to_id)
        print("=" * 50)
        due_date_str = request.form.get("due_date")
        start_date_str = request.form.get("start_date")
        reward_points = int(request.form.get("reward_points", 5))
        estimated_time = request.form.get("estimated_time")

        print("Reward points from form:", reward_points)

        if not title:
            flash("Title is required", "danger")
            return redirect(request.url)

        due_date = None

        if due_date_str:
            parsed = None
            for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(due_date_str, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                flash("Invalid date format", "danger")
                return redirect(request.url)
            due_date = parsed

        start_date = None

        if start_date_str:
            parsed = None
            for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(start_date_str, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                flash("Invalid date format", "danger")
                return redirect(request.url)
            start_date = parsed

        if not description:
            description = "General task created"

        assigned_to = assigned_to_id if assigned_to_id else None

        if current_user.role == "manager" and assigned_to:
            manager_dept_id = current_user.department_id
            target = mongo.db.users.find_one({"_id": ObjectId(assigned_to)})
            allowed = False
            if target and target.get("role") == "employee":
                if manager_dept_id and target.get("department_id") == manager_dept_id:
                    allowed = True
                elif not manager_dept_id and target.get("supervisor_id") == str(current_user.get_id()):
                    allowed = True
            if not allowed:
                flash("You can only assign tasks to employees in your department.", "danger")
                return redirect(request.url)

        task_data = {
            "title": title,
            "description": description,
            "priority": priority,
            "due_date": due_date,
            "start_date": start_date,
            "category": category,
            "notes": notes,
            "assigned_to": assigned_to,
            "created_by": str(current_user.get_id()),
            "reward_points": reward_points,
            "estimated_time": estimated_time,
            "status": "Pending",
            "is_deleted": False,
            "created_at": datetime.utcnow(),
            "attachment": None
        }

        # Single attachment
        attachment = request.files.get("attachment")

        if attachment and attachment.filename != "":

            filename = secure_filename(attachment.filename)

            upload_path = current_app.config["UPLOAD_FOLDER"]

            os.makedirs(upload_path, exist_ok=True)

            attachment.save(
                os.path.join(upload_path, filename)
            )

            task_data["attachment"] = filename

        # Insert task
        task_result = mongo.db.tasks.insert_one(task_data)

        task_id = str(task_result.inserted_id)

        ua = request.headers.get("User-Agent")

        log_activity(
            event_type="task_created",
            module="Tasks",
            description='Created "{}"'.format(title),
            device=device_label(ua)
        )

        log_task_activity(
            task_id,
            "Task created",
            'Created "{}"'.format(title)
        )

        if assigned_to:

            assignee = mongo.db.users.find_one({
                "_id": ObjectId(assigned_to)
            })

            assignee_name = assignee.get("username") if assignee else "an employee"

            log_activity(
                event_type="task_assigned",
                module="Tasks",
                description='Assigned "{}" to {}'.format(title, assignee_name),
                device=device_label(ua)
            )

        # Multiple attachments
        files = request.files.getlist("attachments")

        upload_path = current_app.config["UPLOAD_FOLDER"]

        for file in files:

            if file and file.filename != "":

                filename = secure_filename(file.filename)

                file_path = os.path.join(upload_path, filename)

                file.save(file_path)

                mongo.db.task_attachments.insert_one({
                    "task_id": task_id,
                    "filename": filename,
                    "uploaded_at": datetime.utcnow()
                })

        print("Task saved. Task ID:", task_id)

        # Auto reminder
        if due_date and assigned_to:

            reminder_time = due_date - timedelta(hours=1)

            mongo.db.reminders.insert_one({
                "reason": f"New Task Assigned: {title}",
                "remind_at": reminder_time,
                "end_at": due_date,
                "user_id": assigned_to,
                "task_id": task_id,
                "active": True,
                "created_at": datetime.utcnow()
            })

        # WhatsApp notification
        if assigned_to:

            employee = mongo.db.users.find_one({
                "_id": ObjectId(assigned_to)
            })

            if employee and employee.get("phone"):

                message = f"""
Hello {employee.get('username')},

You have been assigned a new task.

Task: {title}
Due Date: {due_date}
Reward Points: {reward_points}

Please check your dashboard.
"""

                template_sid = current_app.config.get("TWILIO_WHATSAPP_TEMPLATE_SID")
                if template_sid:
                    send_whatsapp_message(
                        employee.get("phone"),
                        message,
                        template_sid=template_sid,
                        template_variables=json.dumps({
                            "1": str(employee.get('username')),
                            "2": str(title),
                            "3": str(due_date),
                            "4": str(reward_points),
                            "5": str(task_id)
                        })
                    )
                else:
                    send_whatsapp_message(employee.get("phone"), message)

        flash("Task created successfully!", "success")

        if current_user.role == "manager":
            return redirect(url_for("main.manager_panel"))

        return redirect(url_for("main.admin_panel"))

    # Manager employee filter (only own department)
    if current_user.role == "manager":

        manager_dept_id = current_user.department_id

        if manager_dept_id:
            employees = list(
                mongo.db.users.find({
                    "role": "employee",
                    "department_id": manager_dept_id
                })
            )
        else:
            employees = list(
                mongo.db.users.find({
                    "role": "employee",
                    "supervisor_id": str(current_user.get_id())
                })
            )

    elif current_user.role == "admin":

        employees = list(
            mongo.db.users.find({
                "role": {"$in": ["employee", "manager"]},
                "company": current_user.company
            })
        )

    else:

        employees = list(
            mongo.db.users.find({
                "role": {"$in": ["employee", "manager"]}
            })
        )

    dept_map = {}
    for d in mongo.db.departments.find():
        dept_map[str(d["_id"])] = d

    now_utc = datetime.utcnow()
    assignees = []

    for emp in employees:
        emp_id = str(emp["_id"])
        dept = dept_map.get(emp.get("department_id") or "")
        open_tasks = mongo.db.tasks.count_documents({
            "assigned_to": emp_id,
            "status": {"$ne": "Approved"},
            "is_deleted": {"$ne": True}
        })
        overdue_tasks = mongo.db.tasks.count_documents({
            "assigned_to": emp_id,
            "status": {"$ne": "Approved"},
            "due_date": {"$lt": now_utc},
            "is_deleted": {"$ne": True}
        })
        assignees.append({
            "id": emp_id,
            "name": emp.get("username", "-"),
            "role": emp.get("role", "-"),
            "department": dept.get("name") if dept else "",
            "department_id": emp.get("department_id") or "",
            "email": emp.get("email", ""),
            "phone": emp.get("phone", ""),
            "open_tasks": open_tasks,
            "overdue_tasks": overdue_tasks,
        })

    if current_user.role == "manager":
        manager_dept_id = current_user.department_id
        if manager_dept_id:
            departments = list(mongo.db.departments.find({
                "status": {"$ne": "inactive"},
                "_id": ObjectId(manager_dept_id)
            }).sort("name", 1))
        else:
            departments = []
    else:
        departments = list(mongo.db.departments.find({
            "status": {"$ne": "inactive"},
            **({"company": current_user.company} if current_user.role == "admin" else {})
        }).sort("name", 1))

    for d in departments:
        d["id"] = str(d["_id"])

    return render_template(
        "create_task.html",
        users=assignees,
        departments=departments
    )



def task_display_status(task):

    if task.get("status") == "Approved":
        return "Completed"

    if (
        task.get("status") == "Submitted"
        or task.get("work_status") == "Started"
    ):
        return "In Progress"

    return "Pending"


@bp.route("/my-tasks")
@login_required
def my_tasks():

    if current_user.role == "super_admin":
        return redirect(url_for("main.task_history"))

    selected = request.args.get("filter", "all")
    uid = str(current_user.get_id())

    now_utc = datetime.utcnow()

    if current_user.role == "employee":
        query = {"assigned_to": uid, "is_deleted": {"$ne": True}}
    else:
        query = {"created_by": uid, "is_deleted": {"$ne": True}}

    tasks = list(mongo.db.tasks.find(query).sort("created_at", -1))

    user_map = {}
    for u in mongo.db.users.find():
        user_map[str(u["_id"])] = u

    dept_map = {}
    for d in mongo.db.departments.find():
        dept_map[str(d["_id"])] = d

    view_rows = []
    counts = {"all": 0, "pending": 0, "in_progress": 0, "completed": 0, "overdue": 0}

    for t in tasks:
        t["id"] = str(t["_id"])

        assignee = user_map.get(t.get("assigned_to") or "")
        assignee_name = assignee.get("username") if assignee else "Unassigned"
        assignee_role = assignee.get("role", "").capitalize() if assignee else ""

        creator = user_map.get(t.get("created_by") or "")
        creator_name = creator.get("username") if creator else "-"
        creator_role = creator.get("role", "").capitalize() if creator else ""

        dept = dept_map.get(assignee.get("department_id") or "") if assignee else None
        dept_name = dept.get("name") if dept else ""

        start_date = to_ist(t.get("start_date"))
        due_date = to_ist(t.get("due_date"))

        is_overdue = bool(
            t.get("status") != "Approved"
            and due_date
            and t.get("due_date") < now_utc
        )

        display = task_display_status(t)

        counts["all"] += 1
        counts[{
            "Completed": "completed",
            "In Progress": "in_progress",
        }.get(display, "pending")] += 1
        if is_overdue:
            counts["overdue"] += 1

        if selected == "pending" and display != "Pending":
            continue
        if selected == "in_progress" and display != "In Progress":
            continue
        if selected == "completed" and display != "Completed":
            continue
        if selected == "overdue" and not is_overdue:
            continue

        name_parts = assignee_name.split()
        initials = "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "?" 
        cname_parts = creator_name.split()
        cinitials = "".join(p[0].upper() for p in cname_parts[:2]) if cname_parts else "?"

        view_rows.append({
            "id": t["id"],
            "title": t.get("title", ""),
            "category": t.get("category") or "Internal",
            "priority": t.get("priority", "-"),
            "status": display,
            "actual_status": t.get("status", "-"),
            "is_overdue": is_overdue,
            "start_date": start_date.strftime("%d %b %Y") if start_date else "â€”",
            "due_date": due_date.strftime("%d %b %Y") if due_date else "â€”",
            "assignee_name": assignee_name,
            "assignee_role": assignee_role,
            "assignee_initials": initials,
            "creator_name": creator_name,
            "creator_role": creator_role,
            "creator_initials": cinitials,
            "department": dept_name or "â€”",
            "reward_points": t.get("reward_points", 0),
        })

    return render_template(
        "my_tasks.html",
        rows=view_rows,
        counts=counts,
        selected=selected,
        is_manager=current_user.role == "manager",
        is_admin=current_user.role == "admin",
        is_employee=current_user.role == "employee",
    )


@bp.route("/task/<task_id>/view")
@login_required
def task_details(task_id):

    if current_user.role not in ("admin", "manager"):
        if current_user.role == "super_admin":
            return redirect(url_for("main.task_history"))
        return redirect(url_for("main.employee_panel"))

    try:
        task = mongo.db.tasks.find_one({
            "_id": ObjectId(task_id),
            "is_deleted": {"$ne": True}
        })
    except Exception:
        task = None

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.my_tasks"))

    user_map = {}
    for u in mongo.db.users.find():
        user_map[str(u["_id"])] = u

    dept_map = {}
    for d in mongo.db.departments.find():
        dept_map[str(d["_id"])] = d

    assignee = user_map.get(task.get("assigned_to") or "")
    creator = user_map.get(task.get("created_by") or "")

    def person(user):
        if not user:
            return {"name": "-", "role": "", "initials": "?", "email": "", "phone": ""}
        name = user.get("username") or "-"
        parts = name.split()
        initials = "".join(p[0].upper() for p in parts[:2]) if parts else "?"
        return {
            "name": name,
            "role": user.get("role", "").capitalize(),
            "initials": initials,
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
        }

    dept = dept_map.get(assignee.get("department_id") or "") if assignee else None

    attachments = list(mongo.db.task_attachments.find({
        "task_id": task_id
    }).sort("uploaded_at", -1))

    comments = list(mongo.db.task_comments.find({
        "task_id": task_id
    }).sort("created_at", -1))

    task_comments = list(mongo.db.task_comments.find({
        "task_id": task_id
    }))

    activity_count = (
        mongo.db.task_activity.count_documents({"task_id": task_id})
        + len(task_comments)
    )

    reminders = list(mongo.db.reminders.find({
        "task_id": task_id
    }).sort("remind_at", 1))

    def fmt(v):
        if not v:
            return "â€”"
        ist = to_ist(v)
        return ist.strftime("%d %b %Y") if ist else "â€”"

    def fmt_dt(v):
        if not v:
            return "â€”"
        ist = to_ist(v)
        return ist.strftime("%d %b %Y at %I:%M %p") if ist else "â€”"

    return render_template(
        "task_details.html",
        task=task,
        task_id=task_id,
        task_code="T{:03d}".format(int(str(task["_id"])[-4:], 16) % 1000),
        title=task.get("title", ""),
        description=task.get("description", ""),
        notes=task.get("notes", ""),
        notes_by=creator.get("username") if creator and task.get("notes") else None,
        category=task.get("category") or "Internal",
        priority=task.get("priority", "Low"),
        display_status=task_display_status(task),
        actual_status=task.get("status", "-"),
        start_date=fmt(task.get("start_date")),
        due_date=fmt(task.get("due_date")),
        completed_at=fmt(task.get("completed_at")),
        estimated_time=task.get("estimated_time") or "â€”",
        assignee=person(assignee),
        creator=person(creator),
        department=dept.get("name") if dept else "â€”",
        attachments=attachments,
        comments=comments,
        activity_count=activity_count,
        reminders=reminders,
        fmt_dt=fmt_dt,
        is_manager=current_user.role == "manager",
    )


@bp.route("/task/<task_id>/comment", methods=["POST"])
@login_required
def add_task_comment(task_id):

    if current_user.role not in ("admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.my_tasks"))

    body = (request.form.get("body") or "").strip()

    if body:
        username = current_user.username
        parts = username.split()
        initials = "".join(p[0].upper() for p in parts[:2]) if parts else "?"

        mongo.db.task_comments.insert_one({
            "task_id": task_id,
            "user_id": str(current_user.get_id()),
            "username": username,
            "initials": initials,
            "body": body,
            "created_at": datetime.utcnow(),
        })

    return redirect(url_for("main.task_details", task_id=task_id))


@bp.route("/task/<task_id>/upload", methods=["POST"])
@login_required
def upload_task_attachment(task_id):

    if current_user.role not in ("admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.my_tasks"))

    files = request.files.getlist("attachment")

    upload_path = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_path, exist_ok=True)

    saved = 0

    for file in files:
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join(upload_path, filename))
            mongo.db.task_attachments.insert_one({
                "task_id": task_id,
                "filename": filename,
                "uploaded_at": datetime.utcnow(),
            })
            saved += 1

    flash(f"{saved} file(s) uploaded", "success" if saved else "info")
    return redirect(url_for("main.task_details", task_id=task_id))


@bp.route("/task/<task_id>/reminder", methods=["POST"])
@login_required
def add_task_reminder(task_id):

    if current_user.role not in ("admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.my_tasks"))

    remind_at_str = request.form.get("remind_at")
    remind_at = None

    if remind_at_str:
        try:
            remind_at = datetime.strptime(remind_at_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            remind_at = None

    if remind_at:
        task = mongo.db.tasks.find_one({"_id": ObjectId(task_id)})
        reason = "Reminder: {}".format(task.get("title", "task")) if task else "Reminder"

        mongo.db.reminders.insert_one({
            "reason": reason,
            "remind_at": remind_at,
            "end_at": task.get("due_date") if task else None,
            "user_id": task.get("assigned_to") if task else None,
            "task_id": task_id,
            "active": True,
            "created_at": datetime.utcnow(),
        })
        flash("Reminder added", "success")
    else:
        flash("Pick a valid reminder time", "danger")

    return redirect(url_for("main.task_details", task_id=task_id))


@bp.route("/task/<task_id>/mark-complete", methods=["POST"])
@login_required
def task_mark_complete(task_id):

    if current_user.role not in ("admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.my_tasks"))

    approve_task(task_id)

    log_task_activity(
        task_id,
        "Marked complete",
        "Task marked as complete"
    )

    return redirect(url_for("main.task_details", task_id=task_id))



@bp.route("/task/<task_id>/subtask", methods=["POST"])
@login_required
def create_subtask(task_id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(task_id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    # ---------------- PERMISSION LOGIC ----------------

    if current_user.role in ("super_admin", "admin"):
        pass

    elif current_user.role == "manager":

        employee = mongo.db.users.find_one({
            "_id": ObjectId(task.get("assigned_to"))
        }) if task.get("assigned_to") else None

        if not employee or employee.get("supervisor_id") != str(current_user.get_id()):
            flash("You cannot add subtask to this task", "danger")
            return redirect(request.referrer or url_for("main.dashboard"))

    elif current_user.role == "employee":

        if task.get("assigned_to") != str(current_user.get_id()):
            flash("You can only add subtask to your own task", "danger")
            return redirect(request.referrer or url_for("main.dashboard"))

    title = request.form.get("title")

    if not title:
        flash("Sub task title required", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    mongo.db.sub_tasks.insert_one({
        "task_id": task_id,
        "title": title,
        "status": "Pending",
        "created_by": str(current_user.get_id()),
        "created_at": datetime.utcnow()
    })

    flash("Sub Task Added", "success")

    return redirect(request.referrer or url_for("main.dashboard"))


@bp.route("/task/toggle/<task_id>")
@login_required
def toggle_task(task_id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(task_id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.dashboard"))

    current_status = task.get("status", "Pending")

    if current_status == "Completed":
        new_status = "Pending"
    else:
        new_status = "Completed"

    mongo.db.tasks.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "status": new_status,
            "updated_at": datetime.utcnow()
        }}
    )

    return redirect(url_for("main.create_task"))

@bp.route("/task/work-toggle/<task_id>")
@login_required
def toggle_work(task_id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(task_id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    current_status = task.get("work_status", "Not Started")

    if current_status == "Not Started":
        new_status = "Started"

    elif current_status == "Started":
        new_status = "Stopped"

    elif current_status == "Stopped":
        new_status = "Started"

    else:
        new_status = "Not Started"

    mongo.db.tasks.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "work_status": new_status,
            "updated_at": datetime.utcnow()
        }}
    )

    return redirect(request.referrer or url_for("main.dashboard"))



@bp.route("/edit-user/<id>", methods=["GET", "POST"])
@login_required
def edit_user(id):

    user = mongo.db.users.find_one({
        "_id": ObjectId(id)
    })

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("main.dashboard"))

    is_self = current_user.get_id() == id
    is_admin_like = current_user.role in ("super_admin", "admin")
    is_manager_like = current_user.role == "manager"
    allowed = is_admin_like or is_self or (
        is_manager_like and user.get("role") == "employee" and user.get("supervisor_id") == current_user.get_id()
    )

    if not allowed:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    user_query = {"role": "manager"}
    if current_user.role == "admin":
        user_query["company"] = current_user.company
    elif current_user.role == "manager":
        user_query["company"] = current_user.company
        user_query["supervisor_id"] = current_user.get_id()
        if current_user.department_id:
            user_query["department_id"] = current_user.department_id

    managers = list(
        mongo.db.users.find(user_query)
    )
    for mgr in managers:
        mgr["id"] = str(mgr["_id"])

    if current_user.role == "manager":
        manager_dept_id = current_user.department_id
        if manager_dept_id:
            departments = list(mongo.db.departments.find({
                "status": {"$ne": "inactive"},
                "_id": ObjectId(manager_dept_id)
            }))
        else:
            departments = []
    else:
        dept_query = {"status": {"$ne": "inactive"}}
        if current_user.role == "admin":
            dept_query["company"] = current_user.company
        departments = list(
            mongo.db.departments.find(dept_query)
        )
    for  dept in departments:
         dept["id"] = str(dept["_id"])

    current_dept_id = user.get("department_id")
    if current_dept_id and not any(d.get("id") == current_dept_id for d in departments):
        keep = mongo.db.departments.find_one({"_id": ObjectId(current_dept_id)})
        if keep:
            keep["id"] = str(keep["_id"])
            departments.append(keep)

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email")
        email = (email or "").strip()

        if not username:
            flash("Username is required", "danger")
            return redirect(url_for("main.edit_user", id=id))

        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("main.edit_user", id=id))

        role = request.form.get("role") if is_admin_like else user.get("role")
        department_id = request.form.get("department_id")
        supervisor_id = request.form.get("supervisor_id")

        phone = normalize_phone(request.form.get("phone"))
        if not phone:
            flash(
                "Invalid phone number. Enter a real, active mobile number (e.g. +91 9876543210).",
                "danger"
            )
            return redirect(url_for("main.edit_user", id=id))

        existing_username = mongo.db.users.find_one({
            "username": {"$regex": "^{}$".format(re.escape(username)), "$options": "i"},
            "_id": {"$ne": ObjectId(id)}
        })

        if existing_username:
            flash("Username already exists!", "danger")
            return redirect(url_for("main.edit_user", id=id))

        existing_email = mongo.db.users.find_one({
            "email": {"$regex": "^{}$".format(re.escape(email)), "$options": "i"},
            "_id": {"$ne": ObjectId(id)}
        })

        if existing_email:
            flash("Email already exists!", "danger")
            return redirect(url_for("main.edit_user", id=id))

        existing_phone = mongo.db.users.find_one({
            "phone": phone,
            "_id": {"$ne": ObjectId(id)}
        })

        if existing_phone:
            flash("Phone already exists!", "danger")
            return redirect(url_for("main.edit_user", id=id))

        update_data = {
            "username": username,
            "email": email,
            "phone": phone,
            "role": role,
            "department_id": department_id,
            "updated_at": datetime.utcnow()
        }

        if role == "employee" and supervisor_id:
            update_data["supervisor_id"] = supervisor_id
        else:
            update_data["supervisor_id"] = None

        if is_admin_like and request.form.get("company") is not None:
            update_data["company"] = (request.form.get("company") or "").strip() or None

        if current_user.role == "super_admin":
            co_name = (request.form.get("company") or "").strip()
            if co_name:
                existing_co = mongo.db.companies.find_one({"company_name": {"$regex": "^{}$".format(re.escape(co_name)), "$options": "i"}})
                plan_slots = _to_int(request.form.get("employee_slots"), 0)
                charge_per = _to_int(request.form.get("per_employee_charge"), 0)
                gstin = (request.form.get("company_gst") or "").strip()
                address = (request.form.get("company_address") or "").strip()
                city = (request.form.get("company_city") or "").strip()

                final_slots = plan_slots if plan_slots else (existing_co.get("plan_slots", 0) if existing_co else 0)
                final_charge = charge_per if charge_per else (existing_co.get("per_employee_charge", 0) if existing_co else 0)

                if existing_co:
                    mongo.db.companies.update_one(
                        {"_id": existing_co["_id"]},
                        {"$set": {
                            "admin_id": id,
                            "admin_username": username,
                            "admin_email": email,
                            "gstin": gstin,
                            "address": address,
                            "city": city,
                            "plan_slots": final_slots,
                            "per_employee_charge": final_charge,
                            "total_amount": final_slots * final_charge
                        }}
                    )
                    if not existing_co.get("admin_id") or str(existing_co.get("admin_id")) != id:
                        update_data["company_id"] = str(existing_co["_id"])
                else:
                    result = mongo.db.companies.insert_one({
                        "company_name": co_name,
                        "gstin": gstin,
                        "address": address,
                        "city": city,
                        "admin_id": id,
                        "admin_username": username,
                        "admin_email": email,
                        "plan_slots": plan_slots,
                        "per_employee_charge": charge_per,
                        "total_amount": plan_slots * charge_per,
                        "status": "active",
                        "created_at": datetime.utcnow(),
                        "created_by": str(current_user.get_id())
                    })
                    update_data["company_id"] = str(result.inserted_id)

        mongo.db.users.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_data}
        )

        flash("Profile updated successfully!", "success")

        if is_self:
            return redirect(url_for("main.dashboard"))
        return redirect(url_for("main.manage_users"))

    user_company = (user.get("company") or "").strip()
    user_co_doc = None
    if user_company:
        user_co_doc = mongo.db.companies.find_one({"company_name": {"$regex": "^{}$".format(re.escape(user_company)), "$options": "i"}})

    return render_template(
        "edit_user.html",
        user=user,
        managers=managers,
        departments=departments,
        is_self=is_self,
        user_co_doc=user_co_doc or {}
    )

@bp.route("/recurring-task-history")
@login_required
def recurring_task_history():

    if current_user.role not in ["super_admin", "admin", "manager"]:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    if current_user.role == "manager":

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

        employee_ids = [str(emp["_id"]) for emp in employees]

        recurring_tasks = list(
            mongo.db.recurring_tasks.find({
                "assigned_to": {"$in": employee_ids}
            }).sort("created_at", -1)
        ) if employee_ids else []

    else:

        recurring_tasks = list(
            mongo.db.recurring_tasks.find().sort("created_at", -1)
        )

    for task in recurring_tasks:
        task["id"] = str(task["_id"])

    return render_template(
        "recurring_task_history.html",
        recurring_tasks=recurring_tasks
    )







# ---------------- AI SUGGESTION ----------------
@bp.route("/task/<task_id>/ai-suggestion")
@login_required
def ai_suggestion(task_id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(task_id)
    })

    if not task:
        return jsonify({
            "success": False,
            "message": "Task not found"
        }), 404

    # Permission
    if current_user.role == "employee" and task.get("assigned_to") != str(current_user.get_id()):
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 403

    if current_user.role == "manager":
        employee = mongo.db.users.find_one({
            "_id": ObjectId(task.get("assigned_to"))
        }) if task.get("assigned_to") else None

        if not employee or employee.get("supervisor_id") != str(current_user.get_id()):
            return jsonify({
                "success": False,
                "message": "Unauthorized"
            }), 403

    title = task.get("title", "Untitled Task")
    description = task.get("description", "")
    priority = task.get("priority", "Low")
    status = task.get("status", "Pending")
    due_date = task.get("due_date")

    reply = f"""
Hereâ€™s a smart action plan for this task:

**Task:** {title}

**Current Status:** {status}  
**Priority:** {priority}

**What you should do first:**  
Start by understanding the exact requirement of the task. Read the title and description carefully, then divide the work into small steps.

**Suggested steps:**  
1. Identify the main goal of the task.  
2. Break it into 2â€“3 smaller subtasks.  
3. Complete the most important part first.  
4. Keep proof or output file ready before submitting.  
5. Submit only after checking the work once.

"""

    if priority == "High":
        reply += """
**Priority advice:**  
This is a high-priority task, so avoid delays. Finish the critical work first and update your manager/admin if anything is blocking you.
"""
    elif priority == "Medium":
        reply += """
**Priority advice:**  
This is a medium-priority task. Plan it properly and complete it before the deadline without rushing at the last moment.
"""
    else:
        reply += """
**Priority advice:**  
This is a low-priority task, but still complete it on time to avoid backlog.
"""

    text = f"{title} {description}".lower()

    if "report" in text:
        reply += "\n**Extra tip:** Prepare the report in clear sections: summary, details, and conclusion.\n"
    if "design" in text or "ui" in text:
        reply += "\n**Extra tip:** First make a rough layout, then improve spacing, colors, alignment, and responsiveness.\n"
    if "data" in text or "excel" in text:
        reply += "\n**Extra tip:** Double-check formulas, totals, spelling, and formatting before submission.\n"
    if "client" in text or "meeting" in text:
        reply += "\n**Extra tip:** Keep communication professional, short, and properly documented.\n"
    if "upload" in text or "document" in text or "file" in text:
        reply += "\n**Extra tip:** Upload the correct final file and use a clear filename.\n"

    if due_date:
        try:
            reply += f"\n**Deadline:** Try to complete this before {due_date.strftime('%d %b %Y %I:%M %p')}.\n"
        except Exception:
            reply += f"\n**Deadline:** Try to complete this before {due_date}.\n"

    reply += """
**Final suggestion:**  
Work step-by-step, avoid multitasking, and submit clean proof of completion.
"""

    return jsonify({
        "success": True,
        "task_id": str(task["_id"]),
        "title": title,
        "reply": reply
    })

@bp.route("/toggle-user-status/<user_id>", methods=["POST"])
@login_required
def toggle_user_status(user_id):

    if current_user.role not in ("super_admin", "admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.manage_users"))

    try:
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.manage_users"))

    if str(user["_id"]) == str(current_user.get_id()):
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("main.manage_users"))

    if current_user.role == "admin" and user.get("company") != current_user.company:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.manage_users"))

    if current_user.role == "manager":
        if user.get("role") != "employee" or user.get("supervisor_id") != current_user.get_id():
            flash("Unauthorized", "danger")
            return redirect(url_for("main.manage_users"))

    new_status = "active" if user.get("status", "active") == "inactive" else "inactive"

    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"status": new_status}}
    )

    if new_status == "inactive":
        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_logged_in": False, "active_session_token": None}}
        )

    ua = request.headers.get("User-Agent")
    log_activity(
        event_type="user_status",
        module="Users",
        description="{} '{}' account".format(
            "Deactivated" if new_status == "inactive" else "Activated",
            user.get("username")
        ),
        device=device_label(ua)
    )

    flash("{} account {}".format(
        user.get("username"),
        "deactivated" if new_status == "inactive" else "activated"
    ), "success")

    return redirect(url_for("main.manage_users"))


@bp.route("/delete_user/<user_id>", methods=["POST"])
@login_required
def delete_user(user_id):

    if current_user.role not in ("super_admin", "admin"):
        abort(403)

    user = mongo.db.users.find_one({
        "_id": ObjectId(user_id)
    })

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.manage_users"))

    if current_user.role == "admin" and user.get("company") != current_user.company:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.manage_users"))

    if str(user["_id"]) == str(current_user.get_id()):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("main.manage_users"))

    deleted_company = None
    deleted_team = 0
    if user.get("role") == "admin" and current_user.role == "super_admin":
        company = mongo.db.companies.find_one({"admin_id": user_id}) or (
            mongo.db.companies.find_one({"_id": ObjectId(user.get("company_id"))}) if user.get("company_id") else None
        )
        if company:
            team_ids = [
                u["_id"] for u in mongo.db.users.find({
                    "$or": [
                        {"company_id": str(company["_id"])},
                        {"company": {"$regex": "^{}$".format(re.escape(company.get("company_name", ""))), "$options": "i"}}
                    ],
                    "role": {"$in": ["manager", "employee"]}
                }, {"_id": 1})
            ]
            if team_ids:
                deleted_team = len(team_ids)
                mongo.db.tasks.delete_many({"assigned_to": {"$in": [str(i) for i in team_ids]}})
                mongo.db.tasks.delete_many({"created_by": {"$in": [str(i) for i in team_ids]}})
                mongo.db.reminders.delete_many({"user_id": {"$in": [str(i) for i in team_ids]}})
                mongo.db.sub_tasks.delete_many({"created_by": {"$in": [str(i) for i in team_ids]}})
                mongo.db.recurring_tasks.delete_many({"assigned_to": {"$in": [str(i) for i in team_ids]}})
                mongo.db.task_attachments.delete_many({"user_id": {"$in": [str(i) for i in team_ids]}})
                mongo.db.login_requests.delete_many({"user_id": {"$in": [str(i) for i in team_ids]}})
                mongo.db.users.delete_many({"_id": {"$in": team_ids}})
            deleted_company = company.get("company_name", "company")
            mongo.db.companies.delete_one({"_id": company["_id"]})
            mongo.db.payments.delete_many({"company_id": str(company["_id"])})

    try:
        mongo.db.sub_tasks.delete_many({
            "created_by": user_id
        })

        mongo.db.reminders.delete_many({
            "user_id": user_id
        })

        mongo.db.recurring_tasks.delete_many({
            "assigned_to": user_id
        })

        mongo.db.task_attachments.delete_many({
            "user_id": user_id
        })

        mongo.db.tasks.delete_many({
            "$or": [
                {"created_by": user_id},
                {"assigned_to": user_id}
            ]
        })

        mongo.db.login_requests.delete_many({
            "user_id": user_id
        })

        mongo.db.users.delete_one({
            "_id": ObjectId(user_id)
        })

        if deleted_company:
            if deleted_team:
                flash("User and related records deleted. Company '{}', its {} manager/employee account(s) and billing were also removed.".format(deleted_company, deleted_team), "success")
            else:
                flash("User and related records deleted. Company '{}' and its billing were also removed.".format(deleted_company), "success")
        else:
            flash("User and related records deleted successfully.", "success")

    except Exception as e:
        flash(f"Unable to delete user: {str(e)}", "danger")

    return redirect(url_for("main.manage_users"))


@bp.route("/delete_reminder/<id>", methods=["POST"])
@login_required
def delete_reminder(id):

    reminder = mongo.db.reminders.find_one({
        "_id": ObjectId(id)
    })

    if not reminder:
        return "", 404

    if reminder.get("user_id") == str(current_user.get_id()):

        mongo.db.reminders.delete_one({
            "_id": ObjectId(id)
        })

    return "", 204




@bp.route("/create-recurring-task", methods=["GET", "POST"])
@login_required
def create_recurring_task():

    if current_user.role not in ["super_admin", "admin", "manager"]:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    # Employees list according to role
    if current_user.role == "manager":

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            }).sort("username", 1)
        )

    else:

        employees = list(
            mongo.db.users.find({
                "role": "employee"
            }).sort("username", 1)
        )

    # Recurring task history according to role
    if current_user.role == "manager":

        employee_ids = [str(emp["_id"]) for emp in employees]

        if employee_ids:

            recurring_tasks = list(
                mongo.db.recurring_tasks.find({
                    "assigned_to": {"$in": employee_ids}
                }).sort("created_at", -1)
            )

        else:
            recurring_tasks = []

    else:

        recurring_tasks = list(
            mongo.db.recurring_tasks.find().sort("created_at", -1)
        )

    if request.method == "POST":

        title = (request.form.get("title") or "").strip()
        assigned_to = request.form.get("assigned_to")
        start_date_raw = request.form.get("start_date")
        end_date_raw = request.form.get("end_date")
        frequency = (request.form.get("frequency") or "").strip().lower()

        if not title:
            flash("Task title is required.", "danger")

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        if not assigned_to:
            flash("Please select an employee.", "danger")

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        if frequency not in ["daily", "weekly", "monthly"]:
            flash("Invalid frequency selected.", "danger")

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        try:
            start_date = datetime.strptime(
                start_date_raw,
                "%Y-%m-%d"
            )

            end_date = datetime.strptime(
                end_date_raw,
                "%Y-%m-%d"
            )

        except (ValueError, TypeError):

            flash("Invalid start date or end date.", "danger")

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        if end_date < start_date:

            flash(
                "Repeat Until date must be after or equal to Start Date.",
                "danger"
            )

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        employee = mongo.db.users.find_one({
            "_id": ObjectId(assigned_to),
            "role": "employee"
        })

        if not employee:

            flash("Selected employee not found.", "danger")

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        # Manager restriction
        if (
            current_user.role == "manager"
            and employee.get("supervisor_id") != str(current_user.get_id())
        ):

            flash(
                "You can assign recurring tasks only to your own employees.",
                "danger"
            )

            return render_template(
                "create_recurring_task.html",
                employees=employees,
                recurring_tasks=recurring_tasks
            )

        mongo.db.recurring_tasks.insert_one({
            "title": title,
            "assigned_to": assigned_to,
            "start_date": start_date,
            "end_date": end_date,
            "frequency": frequency,
            "last_generated": None,
            "created_by": str(current_user.get_id()),
            "created_at": datetime.utcnow()
        })

        flash("Recurring task created successfully!", "success")

        return redirect(url_for("main.create_recurring_task"))

    return render_template(
        "create_recurring_task.html",
        employees=employees,
        recurring_tasks=recurring_tasks
    )

# ---------------- DELETE TASK ----------------
@bp.route("/task/delete/<task_id>", methods=["POST"])
@login_required
def delete_task(task_id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(task_id)
    })

    if not task:
        return jsonify({
            "success": False,
            "message": "Task not found!"
        }), 404

    if current_user.role not in ("super_admin", "admin") and task.get("created_by") != str(current_user.get_id()):
        return jsonify({
            "success": False,
            "message": "You are not authorized!"
        }), 403

    mongo.db.tasks.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "is_deleted": True,
            "deleted_at": datetime.utcnow()
        }}
    )

    return jsonify({
        "success": True,
        "message": "Task deleted successfully!"
    })
# ---------------- SUBMIT TASK WITH FILE ----------------
@bp.route("/task/submit/<id>", methods=["POST"])
@login_required
def submit_task(id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.dashboard"))

    if current_user.role != "employee":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    filename = None

    file = request.files.get("proof_file")

    if file and file.filename != "":

        filename = secure_filename(file.filename)

        upload_folder = current_app.config["UPLOAD_FOLDER"]

        os.makedirs(upload_folder, exist_ok=True)

        file_path = os.path.join(upload_folder, filename)

        file.save(file_path)

    mongo.db.tasks.update_one(
        {"_id": ObjectId(id)},
        {"$set": {
            "proof_file": filename,
            "status": "Submitted",
            "submitted_at": datetime.utcnow()
        }}
    )

    flash("Task submitted successfully with proof!", "success")

    return redirect(url_for("main.employee_panel"))

# ---------------- DOWNLOAD PROOF ----------------
@bp.route("/uploads/<filename>")
@login_required
def download_proof(filename):

    upload_folder = current_app.config["UPLOAD_FOLDER"]

    file_path = os.path.join(upload_folder, filename)

    if not os.path.exists(file_path):
        flash("File not found", "danger")
        return redirect(url_for("main.dashboard"))

    return send_from_directory(
        upload_folder,
        filename,
        as_attachment=True
    )


@bp.route('/set-reminder', methods=['POST'])
@login_required
def set_reminder():

    reason = request.form.get('reason')
    remind_at = request.form.get('remind_at')
    end_at = request.form.get('end_at')

    is_daily = True if request.form.get('is_daily') else False

    try:

        remind_at_dt = (
            datetime.fromisoformat(remind_at)
            if remind_at else None
        )

        end_at_dt = (
            datetime.fromisoformat(end_at)
            if end_at else None
        )

        mongo.db.reminders.insert_one({
            "reason": reason,
            "remind_at": remind_at_dt,
            "end_at": end_at_dt,
            "user_id": str(current_user.get_id()),
            "is_daily": is_daily,
            "active": True,
            "created_at": datetime.utcnow()
        })

        flash("Reminder set successfully!", "success")

    except Exception as e:

        print("Reminder Error:", e)

        flash(f"Reminder failed: {e}", "danger")

    if current_user.role == "manager":
        return redirect(url_for("main.manager_panel"))

    elif current_user.role in ("super_admin", "admin"):
        return redirect(url_for("main.admin_panel"))

    else:
        return redirect(url_for("main.employee_panel"))

# CREATE REMINDER
@bp.route("/create_reminder", methods=["POST"])
@login_required
def create_reminder():

    reason = request.form.get("reason")
    remind_at = request.form.get("remind_at")
    end_at = request.form.get("end_at")

    is_daily = True if request.form.get("is_daily") else False

    ist_now = datetime.now(
        ZoneInfo("Asia/Kolkata")
    ).replace(tzinfo=None)

    remind_at_dt = (
        datetime.fromisoformat(remind_at)
        if remind_at else None
    )

    end_at_dt = (
        datetime.fromisoformat(end_at)
        if end_at else None
    )

    mongo.db.reminders.insert_one({
        "reason": reason,
        "remind_at": remind_at_dt,
        "end_at": end_at_dt,
        "user_id": str(current_user.get_id()),
        "is_daily": is_daily,
        "active": True,
        "created_at": ist_now
    })

    flash("Reminder created successfully!", "success")

    if current_user.role == "manager":
        return redirect(url_for("main.manager_panel"))

    elif current_user.role in ("super_admin", "admin"):
        return redirect(url_for("main.admin_panel"))

    else:
        return redirect(url_for("main.employee_panel"))





# ------------------ ANNOUNCEMENT ------------------
@bp.route("/create-announcement", methods=["POST"])
@login_required
def create_announcement():

    message = request.form.get("message")

    if not message or not message.strip():

        flash("Announcement message is required", "danger")

        return redirect(
            request.referrer or url_for("main.dashboard")
        )

    mongo.db.announcements.insert_one({
        "message": message.strip(),
        "created_by": str(current_user.get_id()),
        "active": True,
        "created_at": datetime.utcnow()
    })

    log_activity(
        event_type="announcement",
        module="Announcements",
        description='Published "{}"'.format(message.strip()),
        device=device_label(request.headers.get("User-Agent"))
    )

    flash("Announcement posted successfully!", "success")

    return redirect(
        request.referrer or url_for("main.dashboard")
    )  

# ------------- Latest announcements for dashboard ----------------
@bp.route("/get-latest-announcement")
@login_required
def get_latest_announcement():

    announcement = mongo.db.announcements.find_one(
        {"active": True},
        sort=[("created_at", -1)]
    )

    if not announcement:
        return jsonify({
            "show": False
        })

    creator_name = "Unknown"

    created_by = announcement.get("created_by")

    if created_by:

        creator = mongo.db.users.find_one({
            "_id": ObjectId(created_by)
        })

        if creator:
            creator_name = creator.get("username", "Unknown")

    created_at = announcement.get("created_at")

    formatted_date = ""

    if created_at:
        try:
            formatted_date = created_at.strftime("%d %b %Y %I:%M %p")
        except Exception:
            formatted_date = str(created_at)

    return jsonify({
        "show": True,
        "id": str(announcement["_id"]),
        "message": announcement.get("message"),
        "created_by": creator_name,
        "created_at": formatted_date
    })

# GET ACTIVE REMINDERS
@bp.route("/get_reminders")
@login_required
def get_reminders():

    now = datetime.now(
        ZoneInfo("Asia/Kolkata")
    ).replace(tzinfo=None)

    reminders = list(
        mongo.db.reminders.find({
            "user_id": str(current_user.get_id()),
            "active": True,
            "remind_at": {"$lte": now}
        })
    )

    data = []

    for r in reminders:

        reminder_id = str(r["_id"])

        if r.get("is_daily"):

            next_time = r.get("remind_at") + timedelta(days=1)

            mongo.db.reminders.update_one(
                {"_id": r["_id"]},
                {"$set": {
                    "remind_at": next_time
                }}
            )

        else:

            mongo.db.reminders.update_one(
                {"_id": r["_id"]},
                {"$set": {
                    "active": False
                }}
            )

        data.append({
            "id": reminder_id,
            "reason": r.get("reason")
        })

    return jsonify(data)


# STOP REMINDER
@bp.route("/stop_reminder/<id>", methods=["POST"])
@login_required
def stop_reminder(id):

    reminder = mongo.db.reminders.find_one({
        "_id": ObjectId(id)
    })

    if not reminder:
        return jsonify({
            "success": False,
            "message": "Reminder not found"
        }), 404

    if reminder.get("user_id") != str(current_user.get_id()):
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 403

    mongo.db.reminders.update_one(
        {"_id": ObjectId(id)},
        {"$set": {
            "active": False
        }}
    )

    return jsonify({
        "success": True
    })

# ---------------- APPROVE TASK ----------------
@bp.route("/task/approve/<id>")
@login_required
def approve_task(id):

    # Allow Super Admin + Admin + Manager
    if current_user.role not in ["super_admin", "admin", "manager"]:
        return "Unauthorized"

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.dashboard"))

    print("Approving task:", str(task["_id"]))
    print("Task reward points:", task.get("reward_points"))
    print("Task assigned_to:", task.get("assigned_to"))

    mongo.db.tasks.update_one(
        {"_id": ObjectId(id)},
        {"$set": {
            "status": "Approved",
            "work_status": "Completed",
            "completed_at": datetime.utcnow()
        }}
    )

    assigned_to = task.get("assigned_to")

    if assigned_to:

        employee = mongo.db.users.find_one({
            "_id": ObjectId(assigned_to)
        })

        if employee:

            print("Employee:", employee.get("username"))
            print("Old points:", employee.get("points", 0))

            new_points = (
                employee.get("points", 0)
                + task.get("reward_points", 0)
            )

            mongo.db.users.update_one(
                {"_id": employee["_id"]},
                {"$set": {
                    "points": new_points
                }}
            )

            print("New points:", new_points)

    print("Approve committed successfully")

    # Redirect according to role
    if current_user.role == "admin":
        return redirect(url_for("main.admin_panel"))

    return redirect(url_for("main.manager_panel"))

@bp.route("/heartbeat")
@login_required
def heartbeat():

    mongo.db.users.update_one(
        {"_id": ObjectId(current_user.get_id())},
        {"$set": {
            "last_seen": datetime.utcnow()
        }}
    )

    return "", 204


# ---------------- CREATE USER ----------------
@bp.route("/create-user", methods=["GET", "POST"])
@login_required
def create_user():

    if current_user.role not in ("super_admin", "admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    if current_user.role == "manager":
        manager_dept_id = current_user.department_id
        if manager_dept_id:
            dept_doc = mongo.db.departments.find_one({"_id": ObjectId(manager_dept_id)})
            departments = [{"id": str(dept_doc["_id"]), "name": dept_doc.get("name")}] if dept_doc else []
        else:
            departments = []
    else:
        dept_query = {} if current_user.role == "super_admin" else {"company": current_user.company}
        departments = [
            {"id": str(d["_id"]), "name": d.get("name")}
            for d in mongo.db.departments.find(dept_query)
            if d.get("status", "active") != "inactive"
        ]

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = (request.form.get("email") or "").strip()
        department_id = request.form.get("department_id")
        role = request.form.get("role")
        status = request.form.get("status", "active")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        company = (request.form.get("company") or "").strip() or None
        company_gst = (request.form.get("company_gst") or "").strip() or None
        company_address = (request.form.get("company_address") or "").strip() or None
        company_slots = _to_int(request.form.get("company_slots"), 0)
        company_charge = _to_int(request.form.get("company_charge"), 0)

        is_manager_creator = current_user.role == "manager"

        if current_user.role == "super_admin":
            role = "admin"
        else:
            allowed_roles = ["manager", "employee"]
            role = role if role in allowed_roles else ("employee" if is_manager_creator else "manager")
        status = "inactive" if status == "inactive" else "active"

        errors = {}

        if not username:
            errors["username"] = "Full name is required."

        if current_user.role == "super_admin":
            if not company:
                errors["company"] = "Company name is required."
            if not company_gst:
                errors["company_gst"] = "Company GST is required."
            elif not re.match(r"^[0-9A-Z]{15}$", company_gst.upper()):
                errors["company_gst"] = "GST must be a valid 15-character GSTIN."
            if not company_address:
                errors["company_address"] = "Company address is required."
            if company_slots < 1:
                errors["company_slots"] = "Enter at least 1 employee slot."

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors["email"] = "Please enter a valid email address."

        phone = normalize_phone(request.form.get("phone"))
        if not phone:
            phone = ""
            errors["phone"] = "Invalid phone number. Enter a real, active mobile number (e.g. +91 9876543210)."

        min_password_length = get_system_settings().get("min_password_length", 8)

        if not password or len(password) < min_password_length:
            errors["password"] = "Password must be at least {} characters long.".format(min_password_length)

        if password != confirm_password:
            errors["confirm"] = "Passwords do not match."

        if not errors:
            existing_user = mongo.db.users.find_one({
                "$or": [
                    {"username": {"$regex": "^{}$".format(re.escape(username)), "$options": "i"}},
                    {"email": {"$regex": "^{}$".format(re.escape(email)), "$options": "i"}},
                    {"phone": phone}
                ]
            })

            if existing_user:
                if existing_user.get("username", "").lower() == username.lower():
                    errors["username"] = f'Username "{username}" already exists!'
                elif existing_user.get("email", "").lower() == email.lower():
                    errors["email"] = f'Email "{email}" already exists!'
                else:
                    errors["phone"] = f'Phone "{phone}" already exists!'

        profile_image = None
        image = request.files.get("profile_image")

        if image and image.filename:
            if image.mimetype not in ("image/png", "image/jpeg"):
                errors["image"] = "Profile image must be PNG or JPG."
            else:
                image.seek(0, 2)
                if image.tell() > 2 * 1024 * 1024:
                    errors["image"] = "Profile image must be 2 MB or smaller."
                image.seek(0)
                ext = os.path.splitext(image.filename)[1].lower()
                if ext not in (".png", ".jpg", ".jpeg"):
                    errors["image"] = "Profile image must be PNG or JPG."

        if errors:
            return render_template(
                "create_user.html",
                departments=departments,
                form=request.form,
                errors=errors,
                status=status
            ), 400

        if image and image.filename:
            fname = f"{uuid.uuid4().hex}{ext}"
            image.save(os.path.join(current_app.config["UPLOAD_FOLDER"], fname))
            profile_image = fname

        if not company:
            company = current_user.company if current_user.role in ("admin", "manager") else None

        supervisor_id = None
        if is_manager_creator:
            supervisor_id = current_user.get_id()

        default_company_id = None
        if current_user.role in ("admin", "manager") and current_user.company_id:
            default_company_id = current_user.company_id

        user_doc = {
            "username": username,
            "email": email,
            "department_id": department_id,
            "phone": phone,
            "role": role,
            "company": company,
            "company_id": default_company_id,
            "company_gst": company_gst if current_user.role == "super_admin" else None,
            "company_address": company_address if current_user.role == "super_admin" else None,
            "supervisor_id": supervisor_id,
            "status": status,
            "profile_image": profile_image,
            "password_hash": hash_password(password),
            "points": 0,
            "is_logged_in": False,
            "active_session_token": None,
            "last_seen": None,
            "created_at": datetime.utcnow()
        }

        user_result = mongo.db.users.insert_one(user_doc)
        user_id = str(user_result.inserted_id)

        if current_user.role == "super_admin" and company:
                existing_co = mongo.db.companies.find_one({"company_name": company})
                if existing_co:
                    mongo.db.companies.update_one(
                        {"_id": existing_co["_id"]},
                        {"$set": {
                            "gstin": (company_gst or "").upper(),
                            "address": company_address or "",
                            "admin_id": user_id,
                            "admin_username": username,
                            "admin_email": email,
                            "plan_slots": company_slots if company_slots else existing_co.get("plan_slots", 0),
                            "per_employee_charge": company_charge if company_charge else existing_co.get("per_employee_charge", 0),
                        }}
                    )
                    mongo.db.users.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {"company_id": str(existing_co["_id"])}}
                    )
                else:
                    co_result = mongo.db.companies.insert_one({
                        "company_name": company,
                        "gstin": (company_gst or "").upper(),
                        "address": company_address or "",
                        "admin_id": user_id,
                        "admin_username": username,
                        "admin_email": email,
                        "plan_slots": company_slots,
                        "per_employee_charge": company_charge,
                        "total_amount": company_slots * company_charge,
                        "status": "active",
                        "created_at": datetime.utcnow()
                    })
                    mongo.db.users.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {"company_id": str(co_result.inserted_id)}}
                    )

        flash("User created successfully!", "success")
        return redirect(url_for("main.manage_users"))

    return render_template(
        "create_user.html",
        departments=departments,
        form={},
        errors={},
        status="active"
    )


def next_invoice_no():
    ctr = mongo.db.counters.find_one_and_update(
        {"_id": "invoice"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    return "FLW-{:04d}".format(ctr["seq"])


def count_company_slots(company_doc):
    return mongo.db.users.count_documents({
        "company_id": str(company_doc["_id"]),
        "role": {"$in": ["employee", "manager"]}
    })


@bp.route("/companies")
@login_required
def companies():

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    company_docs = list(mongo.db.companies.find().sort("created_at", -1))

    seen = set()
    merged = []
    admins = list(mongo.db.users.find({"role": "admin"}))

    def enrich(c, admin=None, from_users=False):
        if admin is None and c.get("admin_id"):
            admin = mongo.db.users.find_one({"_id": ObjectId(c["admin_id"])})
        if admin is None:
            for a in admins:
                aname = (a.get("company") or "").strip()
                cname = (c.get("company_name") or "").strip()
                if aname and aname.lower() == cname.lower():
                    admin = a
                    break
        c["admin_name"] = (admin.get("username") if admin else "-")
        c["admin_email"] = (admin.get("email") if admin else "-")
        c["admin_username"] = c["admin_name"]
        c["admin_phone"] = (admin.get("phone") if admin else None) or ""
        c["admin_cid"] = str(admin["_id"]) if admin else ""
        c["gstin"] = c.get("gstin") or (admin.get("company_gst") if admin else None) or c.get("company_gst") or None
        c["address"] = c.get("address") or (admin.get("company_address") if admin else None) or c.get("company_address") or None
        c["company_name"] = c.get("company_name") or (admin.get("company") if admin else "Unknown")
        if not c.get("plan_slots"):
            c["plan_slots"] = 0
        if not c.get("charge_per"):
            c["charge_per"] = 0
        if not c.get("total_amount"):
            c["total_amount"] = 0
        employees = mongo.db.users.count_documents({
            "role": {"$in": ["employee", "manager"]},
            "$or": [
                {"company_id": str(c["_id"]) if c.get("_id") else None},
                {"company": {"$regex": "^{}$".format(re.escape(c["company_name"])), "$options": "i"}}
            ]
        })
        c["count_created"] = employees
        c["quota_pct"] = round((employees / c["plan_slots"] * 100)) if c["plan_slots"] else 100 if employees else 0
        latest_pay = mongo.db.payments.find_one(
            {"company_id": str(c["_id"])} if c.get("_id") else {"company_name": c.get("company_name")},
            sort=[("created_at", -1)]
        ) if (c.get("_id") or c.get("company_name")) else None
        c["payment_status"] = latest_pay.get("status") if latest_pay else "No Payment"
        c["latest_payment_id"] = str(latest_pay["_id"]) if latest_pay else None
        c["status"] = c.get("status", "active")
        c["created_ist"] = to_ist(c.get("created_at")).strftime("%d %b %Y") if c.get("created_at") else "-"
        c["cid"] = str(c["_id"]) if c.get("_id") else c.get("company_name")
        return c

    for c in company_docs:
        merged.append(enrich(c))
        seen.add((c.get("company_name") or "").strip().lower())

    for a in admins:
        aname = (a.get("company") or "").strip()
        if not aname or aname.lower() in seen:
            continue
        merged.append(enrich({
            "company_name": aname,
            "gstin": a.get("company_gst"),
            "address": a.get("company_address"),
            "claim_image": False
        }, admin=a, from_users=True))
        seen.add(aname.lower())

    merged.sort(key=lambda c: (c.get("created_at") or datetime.min), reverse=True)

    return render_template("companies.html", companies=merged)


@bp.route("/company/<c_id>/view")
@login_required
def company_view(c_id):

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    company = None
    try:
        company = mongo.db.companies.find_one({"_id": ObjectId(c_id)})
    except Exception:
        company = None

    if not company:
        company = mongo.db.companies.find_one({"company_name": c_id})

    if not company:
        admin_doc = mongo.db.users.find_one({"role": "admin", "company": c_id})
        if not admin_doc:
            flash("Company not found.", "danger")
            return redirect(url_for("main.companies"))
        company = {
            "company_name": admin_doc.get("company"),
            "gstin": admin_doc.get("company_gst"),
            "address": admin_doc.get("company_address"),
            "status": "active",
            "admin_id": str(admin_doc["_id"])
        }

    company_name = company.get("company_name", c_id)
    admin = mongo.db.users.find_one({"_id": ObjectId(company["admin_id"])}) if company.get("admin_id") else None
    if not admin:
        admin = mongo.db.users.find_one({"role": "admin", "company": company_name})

    members = list(mongo.db.users.find({
        "company": company_name,
        "role": {"$in": ["manager", "employee"]}
    }))

    company["status"] = company.get("status", "active")
    company["admin_username"] = admin.get("username") if admin else "-"
    company["admin_email"] = admin.get("email") if admin else "-"
    company["admin_status"] = admin.get("status", "active") if admin else "-"
    company["gstin"] = company.get("gstin") or (admin.get("company_gst") if admin else None) or None
    company["address"] = company.get("address") or (admin.get("company_address") if admin else None) or None
    company["created_ist"] = to_ist(company.get("created_at")).strftime("%d %b %Y") if company.get("created_at") else "-"

    template_name = "company_view_partial.html" if request.args.get("partial") == "1" else "company_view.html"

    return render_template(
        template_name,
        company=company,
        admin=admin,
        members=members
    )


@bp.route("/company/<c_id>/status", methods=["POST"])
@login_required
def toggle_company_status(c_id):

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    company = None
    try:
        company = mongo.db.companies.find_one({"_id": ObjectId(c_id)})
    except Exception:
        company = None
    if not company:
        company = mongo.db.companies.find_one({"company_name": c_id})

    if not company:
        admin = mongo.db.users.find_one({"role": "admin", "company": c_id})
        if not admin:
            return jsonify({"ok": False, "message": "Company not found."}), 404
        new_status = "inactive" if admin.get("status", "active") != "inactive" else "active"
        mongo.db.users.update_one(
            {"_id": admin["_id"]},
            {"$set": {"status": new_status}}
        )
        flash("Company '{}' {}".format(admin.get("company"), "deactivated" if new_status == "inactive" else "activated"), "success")
        return redirect(url_for("main.companies"))

    new_status = "inactive" if company.get("status", "active") != "inactive" else "active"
    mongo.db.companies.update_one(
        {"_id": company["_id"]},
        {"$set": {"status": new_status}}
    )

    if company.get("admin_id"):
        mongo.db.users.update_one(
            {"_id": ObjectId(company["admin_id"])},
            {"$set": {"status": new_status}}
        )

    flash("Company '{}' {}".format(company.get("company_name"), "deactivated" if new_status == "inactive" else "activated"), "success")
    return redirect(url_for("main.companies"))


@bp.route("/company/<c_id>/delete", methods=["POST"])
@login_required
def delete_company(c_id):

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    company = None
    try:
        company = mongo.db.companies.find_one({"_id": ObjectId(c_id)})
    except Exception:
        company = None
    if not company:
        company = mongo.db.companies.find_one({"company_name": c_id})

    if not company:
        admin = mongo.db.users.find_one({"role": "admin", "company": c_id})
        if not admin:
            flash("Company not found.", "danger")
            return redirect(url_for("main.companies"))
        company_name = admin.get("company")
        admin_id = str(admin["_id"])
        mongo.db.users.delete_one({"_id": admin["_id"]})
    else:
        company_name = company.get("company_name")
        admin_id = company.get("admin_id")
        company_oid = company["_id"]
        company_cid = str(company_oid)

        team_ids = [
            u["_id"] for u in mongo.db.users.find({
                "$or": [
                    {"company_id": company_cid},
                    {"company": {"$regex": "^{}$".format(re.escape(company_name or "")), "$options": "i"}}
                ],
                "role": {"$in": ["manager", "employee"]}
            }, {"_id": 1})
        ]
        if team_ids:
            team_str = [str(i) for i in team_ids]
            mongo.db.tasks.delete_many({"assigned_to": {"$in": team_str}})
            mongo.db.tasks.delete_many({"created_by": {"$in": team_str}})
            mongo.db.reminders.delete_many({"user_id": {"$in": team_str}})
            mongo.db.sub_tasks.delete_many({"created_by": {"$in": team_str}})
            mongo.db.recurring_tasks.delete_many({"assigned_to": {"$in": team_str}})
            mongo.db.task_attachments.delete_many({"user_id": {"$in": team_str}})
            mongo.db.login_requests.delete_many({"user_id": {"$in": team_str}})
            mongo.db.users.delete_many({"_id": {"$in": team_ids}})

        mongo.db.companies.delete_one({"_id": company_oid})
        mongo.db.payments.delete_many({"company_id": company_cid})
        if admin_id:
            try:
                mongo.db.users.delete_one({"_id": ObjectId(admin_id)})
            except Exception:
                pass

    log_activity(
        event_type="company_deleted",
        module="Companies",
        description="Company '{}' deleted".format(company_name),
        user_id=str(current_user.get_id()),
        username=current_user.username
    )

    flash("Company '{}' deleted.".format(company_name), "success")
    return redirect(url_for("main.companies"))


@bp.route("/company/<c_id>/edit", methods=["GET", "POST"])
@login_required
def edit_company(c_id):

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    company = None
    for q in ({"_id": ObjectId(c_id)}, {"company_name": c_id}):
        try:
            company = mongo.db.companies.find_one(q)
        except Exception:
            company = None
        if company:
            break

    if not company:
        flash("Company not found.", "danger")
        return redirect(url_for("main.companies"))

    admin = mongo.db.users.find_one({"_id": ObjectId(company["admin_id"])}) if company.get("admin_id") else None

    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip()
        gstin = (request.form.get("gstin") or "").strip()
        address = (request.form.get("address") or "").strip()
        city = (request.form.get("city") or "").strip()
        admin_username = (request.form.get("admin_username") or "").strip()
        admin_email = (request.form.get("admin_email") or "").strip()
        admin_phone = (request.form.get("admin_phone") or "").strip()

        errors = {}
        if not company_name:
            errors["company_name"] = "Company name is required."
        else:
            clash = mongo.db.companies.find_one({
                "company_name": {"$regex": "^{}$".format(re.escape(company_name)), "$options": "i"},
                "_id": {"$ne": company["_id"]}
            })
            if clash:
                errors["company_name"] = "A company with this name already exists."
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", admin_email):
            errors["admin_email"] = "Enter a valid admin email."

        if not normalize_phone(admin_phone):
            errors["admin_phone"] = "Invalid phone number. Enter a real, active mobile number (e.g. +91 9876543210)."

        if not errors:
            mongo.db.companies.update_one(
                {"_id": company["_id"]},
                {"$set": {
                    "company_name": company_name,
                    "gstin": gstin,
                    "address": address,
                    "city": city,
                    "admin_username": admin_username,
                    "admin_email": admin_email
                }}
            )
            if admin:
                mongo.db.users.update_one(
                    {"_id": admin["_id"]},
                    {"$set": {
                        "username": admin_username,
                        "email": admin_email,
                        "phone": normalize_phone(admin_phone),
                        "company": company_name,
                        "company_gst": gstin,
                        "company_address": address
                    }}
                )
                mongo.db.users.update_many(
                    {"company": company.get("company_name")},
                    {"$set": {"company": company_name}}
                )
            log_activity(
                event_type="company_updated",
                module="Companies",
                description="Company '{}' details updated".format(company_name),
                user_id=str(current_user.get_id()),
                username=current_user.username
            )
            flash("Company '{}' updated.".format(company_name), "success")
            return redirect(url_for("main.companies"))

        if errors:
            flash("; ".join(errors.values()), "danger")
            return redirect(url_for("main.companies"))

    if request.method == "GET":
        flash("Use the Edit button on the Companies page.", "info")
        return redirect(url_for("main.companies"))

    form = {
        "company_name": company.get("company_name"),
        "gstin": company.get("gstin") or "",
        "address": company.get("address") or "",
        "city": company.get("city") or "",
        "admin_username": (admin.get("username") if admin else None) or company.get("admin_username") or "",
        "admin_email": (admin.get("email") if admin else None) or company.get("admin_email") or "",
        "admin_phone": (admin.get("phone") if admin else "") or ""
    }

    return redirect(url_for("main.companies"))


@bp.route("/create-company", methods=["GET", "POST"])
@login_required
def create_company():

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    settings = get_system_settings()
    per_employee_charge = settings.get("per_employee_charge", 100)

    existing_companies = list(mongo.db.companies.find({}, {"company_name": 1}))

    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip()
        gstin = (request.form.get("gstin") or "").strip()
        address = (request.form.get("address") or "").strip()
        city = (request.form.get("city") or "").strip()
        admin_username = (request.form.get("admin_username") or "").strip()
        admin_email = (request.form.get("admin_email") or "").strip()
        employee_slots = _to_int(request.form.get("employee_slots"), 0)
        charge_per = _to_int(request.form.get("per_employee_charge"), per_employee_charge)
        total_amount = employee_slots * charge_per

        errors = {}

        if not company_name:
            errors["company_name"] = "Company name is required."
        else:
            existing = next(
                (c for c in existing_companies
                 if c.get("company_name", "").lower() == company_name.lower()),
                None
            )
            if existing:
                errors["company_name"] = "A company with this name already exists."

        if not admin_username:
            errors["admin_username"] = "Admin username is required."

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", admin_email):
            errors["admin_email"] = "Enter a valid admin email."

        if not normalize_phone(request.form.get("admin_phone")):
            errors["admin_phone"] = "Invalid phone number. Enter a real, active mobile number (e.g. +91 9876543210)."

        if employee_slots < 1:
            errors["employee_slots"] = "Enter at least 1 employee slot."

        for collide_key in ("username", "email"):
            query = {"email": {"$regex": "^{}$".format(re.escape(admin_email)), "$options": "i"}}
            if collide_key == "username":
                query = {"username": {"$regex": "^{}$".format(re.escape(admin_username)), "$options": "i"}}
            if mongo.db.users.find_one(query):
                errors["admin_username" if collide_key == "username" else "admin_email"] = (
                    "already in use"
                )

        if employee_slots < 1 or not errors:
            pass

        if not errors:

            admin_doc = {
                "username": admin_username,
                "email": admin_email,
                "phone": (normalize_phone(request.form.get("admin_phone")) or ""),
                "password_hash": hash_password(request.form.get("admin_password") or "Flowra@123"),
                "role": "admin",
                "company": company_name,
                "company_id": None,
                "company_website": (request.form.get("admin_website") or "").strip(),
                "status": "active",
                "failed_attempts": 0,
                "is_logged_in": False,
                "active_session_token": None,
                "created_at": datetime.utcnow(),
                "created_by": str(current_user.get_id()),
                "last_seen": None
            }

            company_doc = {
                "company_name": company_name,
                "gstin": gstin,
                "address": address,
                "city": city,
                "admin_id": None,
                "admin_username": admin_username,
                "plan_slots": employee_slots,
                "per_employee_charge": charge_per,
                "total_amount": total_amount,
                "created_at": datetime.utcnow(),
                "created_by": str(current_user.get_id()),
                "status": "active"
            }

            result = mongo.db.companies.insert_one(company_doc)
            admin_doc["company_id"] = str(result.inserted_id)
            company_doc["admin_id"] = str(mongo.db.users.insert_one(admin_doc).inserted_id)
            mongo.db.companies.update_one(
                {"_id": result.inserted_id},
                {"$set": {"admin_id": company_doc["admin_id"]}}
            )

            log_activity(
                event_type="company_created",
                module="Companies",
                description="Company '{}' created with {} employee slot(s) @ â‚¹{:,}/employee".format(
                    company_name, employee_slots, charge_per
                ),
                user_id=str(current_user.get_id()),
                username=current_user.username
            )

            flash("Company '{}' and its admin created. Billing (â‚¹{:,}) will be raised from the Payments page.".format(
                company_name, total_amount), "success")
            return redirect(url_for("main.companies"))

        flash("Please fix the highlighted fields.", "danger")
        form = {
            "company_name": request.form.get("company_name", ""),
            "gstin": gstin, "address": address, "city": city,
            "admin_username": admin_username, "admin_email": admin_email,
            "employee_slots": employee_slots,
            "per_employee_charge": charge_per
        }
        return render_template(
            "create_company.html",
            per_employee_charge=per_employee_charge,
            existing_companies=existing_companies,
            form=form,
            errors=errors
        )

    return render_template(
        "create_company.html",
        per_employee_charge=per_employee_charge,
        existing_companies=existing_companies,
        form={},
        errors={}
    )


@bp.route("/payments")
@login_required
def payments():

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    company_name_map = {}
    for c in mongo.db.companies.find({}, {"company_name": 1, "city": 1}):
        company_name_map[str(c["_id"])] = c

    payment_docs = list(mongo.db.payments.find().sort("created_at", -1))

    for p in payment_docs:
        p["created_ist"] = to_ist(p.get("created_at")).strftime("%d %b %Y, %I:%M %p") if p.get("created_at") else "-"
        p["method"] = (p.get("method") or "upi").lower()

    ptype = lambda d: (d.get("type") or ("invoice" if d.get("invoice_no") else "txn"))

    ledger_entries = [p for p in payment_docs if ptype(p) == "txn"]
    invoices = [p for p in payment_docs if ptype(p) == "invoice"]

    total_collected = sum(p.get("amount") or 0 for p in ledger_entries)
    total_invoiced = sum(p.get("amount") or 0 for p in invoices)
    paid_invoices = [p for p in invoices if (p.get("status") or "") == "Paid"]
    unpaid_invoices = [p for p in invoices if (p.get("status") or "") != "Paid"]

    company_docs = list(mongo.db.companies.find().sort("company_name", 1))
    admins = list(mongo.db.users.find({"role": "admin"}))
    admin_by_co = {}
    for a in admins:
        aname = (a.get("company") or "").strip().lower()
        admin_by_co.setdefault(aname, a)

    billing_rows = []
    company_options = []
    for c in company_docs:
        cid = str(c["_id"]) if c.get("_id") else c.get("company_name")
        cname = (c.get("company_name") or "").strip()
        admin = None
        if c.get("admin_id"):
            try:
                admin = mongo.db.users.find_one({"_id": ObjectId(c["admin_id"])})
            except Exception:
                admin = None
        if admin is None:
            admin = admin_by_co.get(cname.lower())

        plan_slots = c.get("plan_slots") or 0
        charge_per = c.get("per_employee_charge") or 0
        due_amount = plan_slots * charge_per

        employees = mongo.db.users.count_documents({
            "role": {"$in": ["employee", "manager"]},
            "$or": [
                {"company_id": cid},
                {"company": {"$regex": "^{}$".format(re.escape(cname)), "$options": "i"}}
            ]
        })

        latest_pay = mongo.db.payments.find_one(
            {"type": "invoice", "$or": [{"company_id": cid}, {"company_name": cname}]},
            sort=[("created_at", -1)]
        )

        opt = {
            "company_id": cid,
            "company_name": cname,
            "admin_username": (admin.get("username") if admin else None) or c.get("admin_username") or "—",
            "admin_email": (admin.get("email") if admin else "—"),
            "plan_slots": plan_slots,
            "charge_per": charge_per,
            "due_amount": due_amount
        }
        company_options.append(opt)

        billing_rows.append(dict(opt, **{
            "count_created": employees,
            "quota_pct": round((employees / plan_slots * 100)) if plan_slots else (100 if employees else 0),
            "invoice_no": latest_pay.get("invoice_no") if latest_pay else None,
            "payment_id": str(latest_pay["_id"]) if latest_pay else None,
            "payment_status": latest_pay.get("status") if latest_pay else None,
            "created_ist": to_ist(c.get("created_at")).strftime("%d %b %Y") if c.get("created_at") else "-"
        }))

    return render_template(
        "payments.html",
        ledger_entries=ledger_entries,
        invoices=invoices,
        total_collected=total_collected,
        total_invoiced=total_invoiced,
        total_transactions=len(ledger_entries),
        paid_count=len(paid_invoices),
        unpaid_count=len(unpaid_invoices),
        total_invoice_count=len(invoices),
        company_name_map=company_name_map,
        billing_rows=billing_rows,
        company_options=company_options
    )


@bp.route("/payments/record-txn", methods=["POST"])
@login_required
def record_payment_txn():

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    company_id = (request.form.get("company_id") or "").strip()
    amount = _to_int(request.form.get("amount"), 0)
    method = (request.form.get("method") or "upi").strip().lower()
    reference = (request.form.get("reference") or "").strip()
    period = (request.form.get("period") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if not company_id:
        return jsonify({"ok": False, "message": "Select a company/admin"}), 400
    if amount < 1:
        return jsonify({"ok": False, "message": "Enter a valid amount"}), 400

    company_doc = None
    try:
        company_doc = mongo.db.companies.find_one({"_id": ObjectId(company_id)})
    except Exception:
        company_doc = None
    if not company_doc:
        company_doc = mongo.db.companies.find_one({"company_name": company_id})

    if not company_doc:
        return jsonify({"ok": False, "message": "Company not found"}), 404

    cid = str(company_doc["_id"]) if company_doc.get("_id") else company_id
    cname = company_doc.get("company_name", "")

    admin = None
    if company_doc.get("admin_id"):
        try:
            admin = mongo.db.users.find_one({"_id": ObjectId(company_doc["admin_id"])})
        except Exception:
            admin = None

    txn_doc = {
        "type": "txn",
        "company_id": cid,
        "company_name": cname,
        "admin_username": (admin.get("username") if admin else None) or company_doc.get("admin_username"),
        "amount": amount,
        "method": method,
        "reference": reference,
        "period": period,
        "notes": notes,
        "status": "Received",
        "created_at": datetime.utcnow()
    }
    mongo.db.payments.insert_one(txn_doc)

    pending_invoice = mongo.db.payments.find_one({
        "type": "invoice",
        "company_id": cid,
        "status": {"$ne": "Paid"}
    }, sort=[("created_at", -1)])
    if pending_invoice:
        mongo.db.payments.update_one(
            {"_id": pending_invoice["_id"]},
            {"$set": {
                "status": "Paid",
                "paid_at": datetime.utcnow(),
                "method": method,
                "reference": reference,
                "period": period,
                "notes": notes or pending_invoice.get("notes", "")
            }}
        )

    log_activity(
        event_type="payment_received",
        module="Billing",
        description="Recording payment for {} Â· â‚¹{:,} via {} {}".format(
            cname, amount, method, ("(" + reference + ")") if reference else "")
        ,
        user_id=str(current_user.get_id()),
        username=current_user.username
    )

    return jsonify({
        "ok": True,
        "message": "Payment of â‚¹{:,} recorded for {} and synced to its invoice.".format(amount, cname)
    })


@bp.route("/payments/<payment_id>/paid", methods=["POST"])
@login_required
def record_payment(payment_id):

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    try:
        payment_doc = mongo.db.payments.find_one({"_id": ObjectId(payment_id)})
    except Exception:
        payment_doc = None

    if not payment_doc:
        return jsonify({"ok": False, "message": "Payment/invoice not found"}), 404

    mongo.db.payments.update_one(
        {"_id": payment_doc["_id"]},
        {"$set": {
            "status": "Paid",
            "paid_at": datetime.utcnow()
        }}
    )

    log_activity(
        event_type="payment_received",
        module="Billing",
        description="Payment received for {} Â· {} (â‚¹{:,})".format(
            payment_doc.get("company_name"), payment_doc.get("invoice_no"),
            payment_doc.get("amount", 0)
        ),
        user_id=str(current_user.get_id()),
        username=current_user.username
    )

    return jsonify({"ok": True, "message": "Marked as paid"})


@bp.route("/payments/<payment_id>/unpaid", methods=["POST"])
@login_required
def mark_invoice_unpaid(payment_id):

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    try:
        payment_doc = mongo.db.payments.find_one({"_id": ObjectId(payment_id)})
    except Exception:
        payment_doc = None

    if not payment_doc or (payment_doc.get("type") and payment_doc.get("type") != "invoice"):
        return jsonify({"ok": False, "message": "Invoice not found"}), 404

    mongo.db.payments.update_one(
        {"_id": payment_doc["_id"]},
        {"$set": {"status": "Pending", "paid_at": None}}
    )

    return jsonify({"ok": True, "message": "Marked as unpaid"})


@bp.route("/payments/generate-invoice/<company_id>", methods=["POST"])
@login_required
def generate_invoice(company_id):

    if current_user.role != "super_admin":
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    form_company_id = (request.form.get("company_id") or "").strip()

    company_doc = None
    try:
        company_doc = mongo.db.companies.find_one({"_id": ObjectId(form_company_id or company_id)})
    except Exception:
        company_doc = None

    if not company_doc:
        company_doc = mongo.db.companies.find_one({"company_name": form_company_id or company_id})

    if not company_doc:
        return jsonify({"ok": False, "message": "Company not found"}), 404

    cid = str(company_doc["_id"]) if company_doc.get("_id") else form_company_id

    existing = mongo.db.payments.find_one({"type": "invoice", "company_id": cid})
    if existing:
        return jsonify({
            "ok": False,
            "message": "Invoice {} already exists for this company".format(existing.get("invoice_no"))
        }), 400

    plan_slots = company_doc.get("plan_slots") or 0
    charge_per = company_doc.get("per_employee_charge") or 0
    amount = plan_slots * charge_per

    admin = None
    if company_doc.get("admin_id"):
        try:
            admin = mongo.db.users.find_one({"_id": ObjectId(company_doc["admin_id"])})
        except Exception:
            admin = None

    method = (request.form.get("method") or "").strip().lower()
    reference = (request.form.get("reference") or "").strip()
    period = (request.form.get("period") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    payment_doc = {
        "type": "invoice",
        "invoice_no": next_invoice_no(),
        "company_id": cid,
        "company_name": company_doc.get("company_name", ""),
        "admin_username": (admin.get("username") if admin else None) or company_doc.get("admin_username"),
        "amount": amount,
        "slots": plan_slots,
        "charge_per": charge_per,
        "method": method,
        "reference": reference,
        "period": period,
        "notes": notes,
        "status": "Paid" if method else "Pending",
        "paid_at": datetime.utcnow() if method else None,
        "created_at": datetime.utcnow()
    }
    mongo.db.payments.insert_one(payment_doc)

    log_activity(
        event_type="invoice_generated",
        module="Billing",
        description="Invoice {} generated for {} (â‚¹{:,}) Â· {} slot(s){}".format(
            payment_doc["invoice_no"], company_doc.get("company_name", ""), amount, plan_slots,
            " Â· payment via {}".format(method) if method else "")
        ,
        user_id=str(current_user.get_id()),
        username=current_user.username
    )

    return jsonify({"ok": True, "message": "Invoice {} generated".format(payment_doc["invoice_no"])})


@bp.route("/invoice/<payment_id>")
@login_required
def invoice(payment_id):

    if current_user.role != "super_admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    try:
        payment_doc = mongo.db.payments.find_one({"_id": ObjectId(payment_id)})
    except Exception:
        payment_doc = None

    if not payment_doc:
        flash("Invoice not found", "danger")
        return redirect(url_for("main.payments"))

    company_doc = None
    try:
        company_doc = mongo.db.companies.find_one({"_id": ObjectId(payment_doc.get("company_id"))})
    except Exception:
        company_doc = None

    if not company_doc:
        company_doc = mongo.db.companies.find_one({"company_name": payment_doc.get("company_name")})

    company_doc = company_doc or {}

    cid = payment_doc.get("company_id") or str(company_doc.get("_id") or "")
    employees = 0
    if company_doc:
        employees = mongo.db.users.count_documents({
            "role": {"$in": ["employee", "manager"]},
            "$or": [
                {"company_id": cid} if cid else {"company_id": None},
                {"company": {"$regex": "^{}$".format(re.escape(company_doc.get("company_name", "zz"))), "$options": "i"}}
            ]
        })

    payment_doc["created_ist"] = to_ist(payment_doc.get("created_at")).strftime("%d %b %Y, %I:%M %p") if payment_doc.get("created_at") else "-"
    payment_doc["paid_ist"] = to_ist(payment_doc.get("paid_at")).strftime("%d %b %Y, %I:%M %p") if payment_doc.get("paid_at") else None
    payment_doc["method_display"] = {
        "upi": "UPI", "cash": "Cash", "bank": "Bank Transfer", "bank transfer": "Bank Transfer",
        "card": "Card", "cheque": "Cheque"
    }.get((payment_doc.get("method") or "").lower(), (payment_doc.get("method") or "").title() if payment_doc.get("method") else "â€”")
    payment_doc["employees"] = employees

    if request.args.get("format") == "pdf":
        html = render_template(
            "invoice_pdf.html",
            payment=payment_doc,
            company=company_doc,
            invoice_no=payment_doc.get("invoice_no")
        )
        pdf = io.BytesIO()
        pisa.CreatePDF(io.StringIO(html), pdf)
        response = make_response(pdf.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename={}.pdf".format(
            payment_doc.get("invoice_no") or "invoice"
        )
        return response

    return render_template(
        "invoice.html",
        payment=payment_doc,
        company=company_doc,
        invoice_no=payment_doc.get("invoice_no")
    )



@bp.route("/manage-users")
@login_required
def manage_users():

    if current_user.role not in ("super_admin", "admin", "manager"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    if current_user.role == "super_admin":
        users = list(mongo.db.users.find({"role": "admin"}))
    elif current_user.role == "admin":
        users = list(mongo.db.users.find({
            "role": {"$in": ["admin", "manager", "employee"]},
            "company": current_user.company
        }))
    else:
        manager_dept_id = current_user.department_id
        if manager_dept_id:
            users = list(mongo.db.users.find({
                "role": "employee",
                "department_id": manager_dept_id
            }))
        else:
            users = list(mongo.db.users.find({
                "role": "employee",
                "supervisor_id": current_user.get_id()
            }))

    users.sort(key=lambda u: u.get("created_at") or datetime.min, reverse=True)

    dept_docs = {str(d["_id"]): d for d in mongo.db.departments.find()}

    name_map = {str(u["_id"]): u.get("username", "-") for u in mongo.db.users.find()}

    users_data = []

    for user in users:
        if str(user["_id"]) == current_user.get_id():
            continue

        dept = dept_docs.get(user.get("department_id"))
        dept_name = dept.get("name", "-") if dept else "-"

        created = user.get("created_at")

        if created:
            try:
                created_ist = to_ist(created).strftime("%d %b %Y")
            except Exception:
                created_ist = created.strftime("%d %b %Y")
        else:
            created_ist = "-"

        last_seen = user.get("last_seen")
        last_seen_ist = "-"
        if last_seen:
            try:
                last_seen_ist = to_ist(last_seen).strftime("%d %b %Y, %I:%M %p")
            except Exception:
                last_seen_ist = str(last_seen)

        users_data.append({
            "id": str(user["_id"]),
            "name": user.get("username", "-"),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "company": user.get("company") or "-",
            "department": dept_name,
            "role": user.get("role", "employee"),
            "status": user.get("status", "active"),
            "created": created_ist,
            "points": user.get("points", 0),
            "supervisor": name_map.get(user.get("supervisor_id") or "", "-"),
            "attempts": user.get("failed_attempts", 0),
            "last_seen": last_seen_ist,
        })

    n_people = len(users_data)
    n_departments = len(dept_docs)

    return render_template(
        "manage_users.html",
        users_data=users_data,
        departments=sorted({u["department"] for u in users_data if u["department"] != "-"}),
        n_people=n_people,
        n_departments=n_departments
    )
@bp.route("/department-dashboard")
@login_required
def department_dashboard():

    if current_user.role not in ("super_admin", "admin"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    departments = list(mongo.db.departments.find(
        {} if current_user.role == "super_admin" else {"company": current_user.company}
    ))
    department_data = []

    for dept in departments:
        dept["id"] = str(dept["_id"])

        employees = list(mongo.db.users.find({
            "role": "employee",
            "department_id": str(dept["_id"])
        }))

        employee_cards = []

        for emp in employees:
            emp["id"] = str(emp["_id"])

            tasks = list(mongo.db.tasks.find({
                "assigned_to": str(emp["_id"]),
                "is_deleted": False
            }))

            for task in tasks:
                task["id"] = str(task["_id"])

            employee_cards.append({
                "employee": emp,
                "tasks": tasks
            })

        department_data.append({
            "department": dept,
            "count": len(employees),
            "employee_cards": employee_cards
        })

    return render_template(
        "department_dashboard.html",
        department_data=department_data
    )
# ---------------- ADMIN PANEL ----------------
@bp.route("/admin")
@login_required
def admin_panel():

    if current_user.role not in ("super_admin", "admin"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    is_super = current_user.role == "super_admin"
    my_company = current_user.company

    if is_super:
        users = list(mongo.db.users.find())
        tasks = list(mongo.db.tasks.find({"is_deleted": {"$ne": True}}))
        announcements = list(
            mongo.db.announcements.find({"active": True}).sort("created_at", -1).limit(3)
        )
    else:
        users = list(mongo.db.users.find({
            "role": {"$in": ["manager", "employee"]},
            "company": my_company
        }))
        me_doc = mongo.db.users.find_one({"_id": ObjectId(current_user.get_id())})
        if me_doc:
            users.append(me_doc)

        cohort_ids = [str(u["_id"]) for u in users]

        tasks = list(mongo.db.tasks.find({
            "is_deleted": {"$ne": True},
            "$or": [
                {"assigned_to": {"$in": cohort_ids}},
                {"created_by": {"$in": cohort_ids}}
            ]
        }))

        announcements = list(mongo.db.announcements.find({
            "active": True,
            "created_by": {"$in": cohort_ids}
        }).sort("created_at", -1).limit(3))

    managers = [u for u in users if u.get("role") == "manager"]
    employees = [u for u in users if u.get("role") == "employee"]
    departments = list(mongo.db.departments.find(
        {} if is_super else {"company": my_company}
    ))

    user_map = {str(u["_id"]): u for u in users}
    dept_map = {str(d["_id"]): d for d in departments}

    def dept_name_of_user(uid):
        u = user_map.get(uid)
        if not u:
            return "-"
        d = dept_map.get(u.get("department_id"))
        return d.get("name") if d else "-"

    # ---------------- HEADCOUNTS ----------------
    n_users = len(users)
    n_active_users = len([u for u in users if u.get("is_logged_in")])
    n_super_admins = len([u for u in users if u.get("role") == "super_admin"])
    n_admins = len([u for u in users if u.get("role") == "admin"])
    n_managers = len([u for u in users if u.get("role") == "manager"])
    n_employees = len([u for u in users if u.get("role") == "employee"])
    n_active_employees = len(
        [u for u in users if u.get("role") == "employee" and u.get("is_logged_in")]
    )
    n_managers_with_dept = len(
        [u for u in users if u.get("role") == "manager" and u.get("department_id")]
    )
    n_departments = len(departments)
    n_active_departments = len([
        d for d in departments
        if any(u.get("department_id") == str(d["_id"]) for u in users)
    ])

    # ---------------- TASKS ----------------
    n_tasks = len(tasks)
    completed = len([t for t in tasks if t.get("status") == "Approved"])
    pending = len([t for t in tasks if t.get("status") == "Pending"])
    submitted = len([t for t in tasks if t.get("status") == "Submitted"])
    rejected = len([t for t in tasks if t.get("status") == "Rejected"])
    in_progress = len([
        t for t in tasks
        if t.get("work_status") == "Started" and t.get("status") != "Approved"
    ])

    now_utc = datetime.utcnow()

    overdue = len([
        t for t in tasks
        if t.get("status") != "Approved"
        and t.get("due_date")
        and t.get("due_date") < now_utc
    ])

    completed_pct = round(completed * 100 / n_tasks) if n_tasks else 0
    overdue_pct = round(overdue * 100 / n_tasks) if n_tasks else 0
    in_progress_pct = round(in_progress * 100 / n_tasks) if n_tasks else 0
    pending_pct = round(pending * 100 / n_tasks) if n_tasks else 0
    submitted_pct = round(submitted * 100 / n_tasks) if n_tasks else 0

    # ---------------- MONTHLY TREND (last 8 months) ----------------
    periods = []
    for i in range(7, -1, -1):
        py, pm = now_utc.year, now_utc.month - i
        while pm < 1:
            pm += 12
            py -= 1
        periods.append((py, pm))

    month_labels = [datetime(py, pm, 1).strftime("%b") for py, pm in periods]
    period_index = {p: i for i, p in enumerate(periods)}

    created_counts = [0] * len(periods)
    completed_counts = [0] * len(periods)
    growth_counts = [0] * len(periods)

    for t in tasks:
        ca = t.get("created_at")
        if ca and (ca.year, ca.month) in period_index:
            created_counts[period_index[(ca.year, ca.month)]] += 1
        cc = t.get("completed_at")
        if cc and (cc.year, cc.month) in period_index:
            completed_counts[period_index[(cc.year, cc.month)]] += 1

    for u in users:
        ca = u.get("created_at")
        if ca and (ca.year, ca.month) in period_index:
            growth_counts[period_index[(ca.year, ca.month)]] += 1

    user_growth = []
    cumulative = 0
    for c in growth_counts:
        cumulative += c
        user_growth.append(cumulative)

    # ---------------- ROLE DISTRIBUTION ----------------
    employees_pct = round(n_employees * 100 / n_users) if n_users else 0
    managers_pct = round(n_managers * 100 / n_users) if n_users else 0
    admins_pct = round(n_admins * 100 / n_users) if n_users else 0
    super_admins_pct = round(n_super_admins * 100 / n_users) if n_users else 0

    role_distribution = [
        {"role": "Employees",       "count": n_employees,  "pct": employees_pct},
        {"role": "Managers",        "count": n_managers,   "pct": managers_pct},
        {"role": "Admins",          "count": n_admins,     "pct": admins_pct},
        {"role": "Super Admins",    "count": n_super_admins, "pct": super_admins_pct},
    ]

    task_overview = [
        {"label": "Completed",   "count": completed,    "pct": completed_pct},
        {"label": "In Progress", "count": in_progress,  "pct": in_progress_pct},
        {"label": "Pending",     "count": pending,      "pct": pending_pct},
        {"label": "Overdue",     "count": overdue,      "pct": overdue_pct},
    ]

    # ---------------- RECENT TASKS ----------------
    recent_sorted = sorted(
        tasks, key=lambda t: t.get("created_at") or datetime.min, reverse=True
    )[:6]

    recent_tasks = []
    for t in recent_sorted:
        assigned_to = t.get("assigned_to")
        emp_name = user_map.get(assigned_to).get("username") if assigned_to in user_map else "-"
        recent_tasks.append({
            "id": str(t["_id"]),
            "title": t.get("title", "-"),
            "description": t.get("description", ""),
            "employee": emp_name,
            "department": dept_name_of_user(assigned_to) if assigned_to else "-",
            "status": t.get("status", "-"),
            "priority": t.get("priority", "-"),
            "reward_points": t.get("reward_points", 0),
            "created_at_ist": to_ist(t.get("created_at")),
            "due_date": t.get("due_date"),
            "proof_file": t.get("proof_file"),
        })

    overdue_sorted = sorted(
        [t for t in tasks
            if t.get("status") != "Approved"
            and t.get("due_date")
            and t.get("due_date") < now_utc],
        key=lambda t: t.get("due_date") or datetime.max
    )[:6]

    overdue_tasks = []
    for t in overdue_sorted:
        assigned_to = t.get("assigned_to")
        emp_name = user_map.get(assigned_to).get("username") if assigned_to in user_map else "-"
        overdue_tasks.append({
            "id": str(t["_id"]),
            "title": t.get("title", "-"),
            "employee": emp_name,
            "status": t.get("status", "-"),
            "due_date": t.get("due_date"),
        })

    # ---------------- DEPARTMENT ACTIVITY ----------------
    dept_activity = []
    for d in departments:
        did = str(d["_id"])
        members = [u for u in users if u.get("department_id") == did]
        member_ids = {str(u["_id"]) for u in members}
        task_count = sum(
            1 for t in tasks if str(t.get("assigned_to") or "") in member_ids
        )
        dept_activity.append({
            "name": d.get("name", "Unknown"),
            "members": len(members),
            "tasks": task_count,
        })

    # ---------------- ANNOUNCEMENTS ----------------
    latest_announcements = []
    for a in announcements:
        creator_id = a.get("created_by")
        creator = user_map.get(creator_id)
        created_at = a.get("created_at")
        created_ist = to_ist(created_at)
        time_ago = ""
        if created_ist:
            now_ist = datetime.now(ZoneInfo("Asia/Kolkata"))
            diff = now_ist - created_ist
            secs = int(diff.total_seconds())
            if secs < 60:
                time_ago = "just now"
            elif secs < 3600:
                time_ago = f"{secs // 60}m ago"
            elif secs < 86400:
                time_ago = f"{secs // 3600}h ago"
            else:
                time_ago = f"{secs // 86400}d ago"
        latest_announcements.append({
            "title": (a.get("message", "") or "")[:42],
            "message": a.get("message", ""),
            "creator": creator.get("username") if creator else "Unknown",
            "created_at_ist": created_ist,
            "time_ago": time_ago,
            "audience": "All Users",
        })

    # ---------------- SYSTEM HEALTH ----------------
    active_recurring = mongo.db.recurring_tasks.count_documents({
        "end_date": {"$gt": now_utc}
    })

    # ---------------- NOW LOGGED IN USERS ----------------
    logged_in_users = []
    logged = [u for u in users if u.get("is_logged_in")]
    logged.sort(key=lambda u: u.get("last_seen") or datetime.min, reverse=True)

    for u in logged[:6]:
        logged_in_users.append({
            "username": u.get("username", "-"),
            "last_seen_ist": to_ist(u.get("last_seen")),
        })

    # ---------------- RECENT SYSTEM ACTIVITY ----------------
    recent_system_activity = []

    for a in announcements:
        creator_id = a.get("created_by")
        creator = user_map.get(creator_id)
        recent_system_activity.append({
            "icon": "bullhorn",
            "text": (creator.get("username") if creator else "System")
                    + " posted an announcement",
            "time": to_ist(a.get("created_at")),
        })

    if active_recurring:
        recent_system_activity.append({
            "icon": "arrows-rotate",
            "text": f"{active_recurring} recurring schedule(s) running",
            "time": None,
        })

    audit_entries = 0

    # ---------------- DEPARTMENT TASKS (keep existing view) ----------------
    department_tasks = {}

    for dept in departments:
        dept_id = str(dept["_id"])
        dept_name = dept.get("name", "Unknown Department")

        ids = [str(u["_id"]) for u in users if u.get("department_id") == dept_id]

        dept_tasks = list(mongo.db.tasks.find({
            "assigned_to": {"$in": ids},
            "is_deleted": False
        })) if ids else []

        for task in dept_tasks:
            task["id"] = str(task["_id"])

            if task.get("assigned_to"):
                task["assignee"] = user_map.get(task["assigned_to"])
            else:
                task["assignee"] = None

        department_tasks[dept_name] = dept_tasks

    # ---------------- GREETING + HEADER ----------------
    ist_now = to_ist(now_utc)

    if ist_now.hour < 12:
        greeting = "Good morning"
    elif ist_now.hour < 17:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"

    admin_name = current_user.username or current_user.role

    # ---------------- WEEKLY TREND (last 8 weeks) ----------------
    week_start = ist_now.date() - timedelta(days=ist_now.weekday())
    week_starts = [week_start - timedelta(days=7 * (7 - i)) for i in range(8)]
    week_labels = ["W{}".format(i + 1) for i in range(8)]
    week_index = {ws: i for i, ws in enumerate(week_starts)}

    assigned_counts = [0] * 8
    completed_counts = [0] * 8

    def _week_of(dt):
        if not dt:
            return None
        d = to_ist(dt).date()
        return d - timedelta(days=d.weekday())

    for t in tasks:
        ws = _week_of(t.get("created_at"))
        if ws in week_index:
            assigned_counts[week_index[ws]] += 1

        ctime = None
        if t.get("status") == "Approved":
            ctime = t.get("completed_at") or t.get("created_at")
        ws = _week_of(ctime)
        if ws in week_index:
            completed_counts[week_index[ws]] += 1

    # ---------------- MONTH-OVER-MONTH KPI DELTAS ----------------
    this_month_start = datetime(now_utc.year, now_utc.month, 1)
    last_lm = now_utc.month - 1
    last_lm_year = now_utc.year
    if last_lm < 1:
        last_lm = 12
        last_lm_year -= 1
    last_month_start = datetime(last_lm_year, last_lm, 1)

    created_this_month = sum(1 for t in tasks
                             if t.get("created_at") and t["created_at"] >= this_month_start)
    created_last_month = sum(1 for t in tasks
                             if t.get("created_at") and last_month_start <= t["created_at"] < this_month_start)

    def _completed_dt(t):
        if t.get("status") != "Approved":
            return None
        return t.get("completed_at") or t.get("created_at")

    completed_this_month = sum(1 for t in tasks
                               if _completed_dt(t) and _completed_dt(t) >= this_month_start)
    completed_last_month = sum(1 for t in tasks
                               if _completed_dt(t) and last_month_start <= _completed_dt(t) < this_month_start)

    overdue_before_month = sum(1 for t in tasks
                               if t.get("status") != "Approved"
                               and t.get("due_date") and t["due_date"] < this_month_start)

    def _mo_pct(cur, prev):
        if not prev:
            return None
        return round((cur - prev) * 100 / prev)

    tasks_delta_pct = _mo_pct(created_this_month, created_last_month)
    completed_delta_pct = _mo_pct(completed_this_month, completed_last_month)
    overdue_delta_pct = _mo_pct(overdue, overdue_before_month)

    # ---------------- UPCOMING / OVERDUE DEADLINES ----------------
    ist_today = ist_now.date()

    deadline_list = [
        t for t in tasks
        if t.get("status") != "Approved" and t.get("due_date")
    ]
    deadline_list.sort(key=lambda t: t["due_date"])

    upcoming_deadlines = []
    for t in deadline_list[:6]:
        assigned_to = t.get("assigned_to")
        emp_name = user_map.get(assigned_to).get("username") if assigned_to in user_map else "-"
        due = t["due_date"]
        days_left = (due.date() - ist_today).days
        if days_left < 0:
            due_label = "{}d late".format(abs(days_left))
            is_late = True
        elif days_left == 0:
            due_label = "Due today"
            is_late = False
        else:
            due_label = "in {}d".format(days_left)
            is_late = False
        upcoming_deadlines.append({
            "id": str(t["_id"]),
            "title": t.get("title", "-"),
            "employee": emp_name,
            "status": t.get("status", "-"),
            "due_date": due,
            "due_label": due_label,
            "is_late": is_late,
        })

    # ---------------- DEPARTMENT PERFORMANCE ----------------
    dept_performance = []
    for d in departments:
        did = str(d["_id"])
        member_ids = {str(u["_id"]) for u in users if u.get("department_id") == did}
        d_tasks = [t for t in tasks if str(t.get("assigned_to") or "") in member_ids]
        d_total = len(d_tasks)
        d_done = sum(1 for t in d_tasks if t.get("status") == "Approved")
        d_rate = round(d_done * 100 / d_total) if d_total else 0
        dept_performance.append({
            "name": d.get("name", "Unknown"),
            "total": d_total,
            "completed": d_done,
            "rate": d_rate,
        })

    # ---------------- COMPANY PERFORMANCE (super admin) ----------------
    # Companies exist as the `company` name on user docs (admin==company owner).
    company_performance = []
    if is_super:
        team_by_company = {}
        for u in users:
            cname = (u.get("company") or "").strip()
            if cname:
                team_by_company.setdefault(cname, []).append(str(u["_id"]))
        for cname, mids in team_by_company.items():
            mids_set = set(mids)
            c_tasks = [t for t in tasks if str(t.get("assigned_to") or "") in mids_set]
            c_total = len(c_tasks)
            c_done = sum(1 for t in c_tasks if t.get("status") == "Approved")
            c_rate = round(c_done * 100 / c_total) if c_total else 0
            if c_total:
                company_performance.append({
                    "name": cname,
                    "total": c_total,
                    "completed": c_done,
                    "rate": c_rate,
                })
        company_performance.sort(key=lambda x: -x["rate"])


    # ---------------- RECENT ACTIVITY ----------------
    recent_activity = []
    if is_super:
        # Super: only "user created" events, newest first
        new_users = sorted(
            (u for u in users if u.get("created_at")),
            key=lambda u: u["created_at"],
            reverse=True,
        )[:6]
        for u in new_users:
            creator = u.get("created_by")
            creator_name = user_map.get(creator).get("username") if creator and creator in user_map else None
            role = u.get("role", "user")
            recent_activity.append({
                "icon": "user-plus",
                "text": (creator_name + " created user " + u.get("username", "-")) if creator_name else
                        ("New user created: " + u.get("username", "-")),
                "desc": "Added as " + role,
                "time": u["created_at"],
            })
    else:
        latest_tasks = sorted(
            tasks, key=lambda t: t.get("created_at") or datetime.min, reverse=True
        )[:6]
        for t in latest_tasks:
            creator_id = t.get("created_by")
            creator = user_map.get(creator_id)
            creator_name = creator.get("username") if creator else "System"
            created_at = t.get("created_at")
            recent_activity.append({
                "icon": "circle-plus",
                "text": "{} created this task".format(creator_name),
                "desc": "",
                "time": created_at,
            })
            assigned_to = t.get("assigned_to")
            if assigned_to and assigned_to in user_map:
                recent_activity.append({
                    "icon": "user-check",
                    "text": "{} is working on \"{}\"".format(user_map[assigned_to].get("username"), t.get("title", "")),
                    "desc": "",
                    "time": created_at,
                })
    companies_count = mongo.db.companies.count_documents({}) if is_super else 0
    admin_count = mongo.db.users.count_documents({"role": "admin"}) if is_super else 0

    return render_template(
        "admin_panel.html",
        greeting=greeting,
        admin_name=admin_name,
        
        total_users=n_users,
        total_departments=n_departments,
        admin_count=admin_count,
        total_tasks=n_tasks,
        pending=pending,
        pending_pct=pending_pct,
        in_progress=in_progress,
        in_progress_pct=in_progress_pct,
        completed=completed,
        completed_pct=completed_pct,
        overdue=overdue,
        overdue_pct=overdue_pct,
        tasks_delta_pct=tasks_delta_pct,
        completed_delta_pct=completed_delta_pct,
        overdue_delta_pct=overdue_delta_pct,
        week_labels=week_labels,
        assigned_counts=assigned_counts,
        completed_counts=completed_counts,
        task_overview=task_overview,
        recent_tasks=recent_tasks,
        upcoming_deadlines=upcoming_deadlines,
        dept_performance=dept_performance,
        company_performance=company_performance,
        recent_activity=recent_activity,
        is_super_admin=is_super,
        companies_count=companies_count,
        latest_announcements=latest_announcements,
    )

@bp.route("/create-department", methods=["GET", "POST"])
@login_required
def create_department():

    if current_user.role not in ("super_admin", "admin"):
        flash("Only admin can create departments", "danger")
        return redirect(url_for("main.dashboard"))

    is_super = current_user.role == "super_admin"

    company_query = {} if is_super else {"company": current_user.company}
    heads = list(
        mongo.db.users.find({
            "role": {"$in": ["admin", "manager"]},
            **company_query
        }).sort("username", 1)
    )

    for h in heads:
        h["id"] = str(h["_id"])

    companies = list(mongo.db.companies.find({}).sort("company_name", 1)) if is_super else []
    for c in companies:
        c["id"] = str(c["_id"])

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        head_id = request.form.get("head_id", "").strip() or None
        status = request.form.get("status", "active")

        if is_super:
            company_id = request.form.get("company_id", "").strip() or None
            company_doc = None
            if company_id:
                try:
                    company_doc = mongo.db.companies.find_one({"_id": ObjectId(company_id)})
                except Exception:
                    company_doc = None
            company_name = company_doc.get("company_name") if company_doc else (request.form.get("company", "") or "").strip() or None
        else:
            company_name = current_user.company
            company_doc = None
            if current_user.company_id:
                try:
                    company_doc = mongo.db.companies.find_one({"_id": ObjectId(current_user.company_id)})
                except Exception:
                    company_doc = None
            company_id = str(company_doc["_id"]) if company_doc else None

        if not name:
            flash("Department name is required", "danger")
            return redirect(url_for("main.create_department"))

        if is_super and not company_name:
            flash("Please choose the company for this department", "danger")
            return redirect(url_for("main.create_department"))

        existing = mongo.db.departments.find_one({
            "name": {"$regex": "^{}$".format(re.escape(name)), "$options": "i"},
            "company": company_name
        })

        if existing:
            flash("Department already exists in this company", "danger")
            return redirect(url_for("main.create_department"))

        mongo.db.departments.insert_one({
            "name": name,
            "description": description,
            "head_id": head_id,
            "company": company_name,
            "company_id": company_id,
            "status": status if status in ("active", "inactive") else "active",
            "created_at": datetime.utcnow(),
            "created_by": str(current_user.get_id())
        })

        flash("Department created successfully!", "success")
        return redirect(url_for("main.manage_departments"))

    return render_template(
        "create_department.html",
        heads=heads,
        companies=companies,
        department=None
    )


@bp.route("/edit-department/<id>", methods=["GET", "POST"])
@login_required
def edit_department(id):

    if current_user.role not in ("super_admin", "admin"):
        flash("Only admin can edit departments", "danger")
        return redirect(url_for("main.dashboard"))

    department = mongo.db.departments.find_one({"_id": ObjectId(id)})

    if not department:
        flash("Department not found.", "danger")
        return redirect(url_for("main.manage_departments"))

    if current_user.role == "admin" and department.get("company") != current_user.company:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.manage_departments"))

    department["id"] = str(department["_id"])
    department["status"] = department.get("status", "active")

    company_query = {} if current_user.role == "super_admin" else {"company": current_user.company}
    heads = list(
        mongo.db.users.find({
            "role": {"$in": ["admin", "manager"]},
            **company_query
        }).sort("username", 1)
    )

    for h in heads:
        h["id"] = str(h["_id"])

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        head_id = request.form.get("head_id", "").strip() or None
        status = request.form.get("status", "active")

        if not name:
            flash("Department name is required", "danger")
            return redirect(url_for("main.edit_department", id=id))

        company_name = department.get("company")
        company_id = department.get("company_id")

        if current_user.role == "super_admin":
            chosen_cid = request.form.get("company_id", "").strip() or None
            if chosen_cid:
                try:
                    chosen_co = mongo.db.companies.find_one({"_id": ObjectId(chosen_cid)})
                except Exception:
                    chosen_co = None
                if chosen_co:
                    company_name = chosen_co.get("company_name")
                    company_id = str(chosen_co["_id"])

        duplicate = mongo.db.departments.find_one({
            "_id": {"$ne": ObjectId(id)},
            "name": {"$regex": "^{}$".format(re.escape(name)), "$options": "i"},
            "company": company_name
        })

        if duplicate:
            flash("Another department already has this name in this company", "danger")
            return redirect(url_for("main.edit_department", id=id))

        mongo.db.departments.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "name": name,
                "description": description,
                "head_id": head_id,
                "company": company_name,
                "company_id": company_id,
                "status": status if status in ("active", "inactive") else "active"
            }}
        )

        flash("Department updated successfully!", "success")
        return redirect(url_for("main.manage_departments"))

    companies = list(mongo.db.companies.find({}).sort("company_name", 1)) if current_user.role == "super_admin" else []
    for c in companies:
        c["id"] = str(c["_id"])

    return render_template(
        "create_department.html",
        heads=heads,
        companies=companies,
        department=department
    )


@bp.route("/manage-departments")
@login_required
def manage_departments():

    if current_user.role not in ("super_admin", "admin"):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    role_labels = {
        "super_admin": "Super Admin",
        "admin": "Admin",
        "manager": "Manager",
        "employee": "Employee"
    }

    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    if current_user.role == "admin":
        scope = {"company": current_user.company}
    else:
        scope = {}

    all_departments = list(mongo.db.departments.find(scope))

    query = dict(scope)

    if status_filter in ("active", "inactive"):
        query["status"] = status_filter

    departments = list(mongo.db.departments.find(query).sort("created_at", -1))

    user_map = {}
    for u in mongo.db.users.find():
        user_map[str(u["_id"])] = u

    all_dept_ids = {str(d["_id"]) for d in all_departments}
    total_people = len({
        str(u["_id"]) for u in user_map.values()
        if str(u.get("department_id") or "") in all_dept_ids
    })

    head_name_map = {}

    for dept in departments:
        dept["id"] = str(dept["_id"])
        dept["status"] = dept.get("status", "active")
        dept["description"] = dept.get("description", "")

        head_id = dept.get("head_id")
        head = user_map.get(head_id) if head_id else None

        if head:
            name_parts = (head.get("username") or "").split()
            head_name_map[str(dept["_id"])] = {
                "username": head.get("username"),
                "initials": "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "H",
                "role": role_labels.get(head.get("role"), "Member")
            }
        else:
            head_name_map[str(dept["_id"])] = None

        member_ids = [
            str(u["_id"]) for u in user_map.values()
            if str(u.get("department_id") or "") == str(dept["_id"])
               and u.get("role") != "super_admin"
        ]

        dept["member_ids"] = member_ids
        dept["member_count"] = len(member_ids)

        dept_tasks = list(
            mongo.db.tasks.find({
                "assigned_to": {"$in": member_ids},
                "is_deleted": {"$ne": True}
            })
        )

        dept["task_count"] = len(dept_tasks)
        dept["done_count"] = sum(1 for t in dept_tasks if t.get("status") == "Approved")
        dept["done_pct"] = round(dept["done_count"] * 100 / dept["task_count"]) if dept["task_count"] else 0
        dept["created_label"] = to_ist(dept.get("created_at")).strftime("%d %b %Y") if dept.get("created_at") else "-"

    if q:
        rx = re.compile(re.escape(q), re.IGNORECASE)
        departments = [d for d in departments if rx.search(d.get("name", "") + " " + d.get("description", ""))]

    return render_template(
        "manage_departments.html",
        departments=departments,
        head_name_map=head_name_map,
        q=q,
        status_filter=status_filter,
        total_departments=len(all_departments),
        total_people=total_people
    )


@bp.route("/toggle-department-status/<id>", methods=["POST"])
@login_required
def toggle_department_status(id):

    if current_user.role not in ("super_admin", "admin"):
        abort(403)

    department = mongo.db.departments.find_one({
        "_id": ObjectId(id)
    })

    if not department:
        flash("Department not found.", "danger")
        return redirect(url_for("main.manage_departments"))

    if current_user.role == "admin" and department.get("company") != current_user.company:
        abort(403)

    new_status = "inactive" if department.get("status", "active") != "inactive" else "active"

    mongo.db.departments.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": new_status}}
    )

    flash(
        "Department {} {}.".format(
            department.get("name"),
            "deactivated" if new_status == "inactive" else "activated"
        ),
        "success"
    )

    return redirect(url_for("main.manage_departments"))


@bp.route("/department-details/<id>")
@login_required
def department_details(id):

    if current_user.role not in ("super_admin", "admin"):
        abort(403)

    department = mongo.db.departments.find_one({
        "_id": ObjectId(id)
    })

    if not department:
        return jsonify({"error": "Department not found"}), 404

    if current_user.role == "admin" and department.get("company") != current_user.company:
        return jsonify({"error": "Unauthorized"}), 403

    role_labels = {
        "super_admin": "Super Admin",
        "admin": "Admin",
        "manager": "Manager",
        "employee": "Employee"
    }

    head_info = None

    if department.get("head_id"):
        try:
            head = mongo.db.users.find_one({"_id": ObjectId(department["head_id"])})
        except Exception:
            head = None

        if head:
            name_parts = (head.get("username") or "").split()
            head_info = {
                "username": head.get("username"),
                "initials": "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "H",
                "role": role_labels.get(head.get("role"), "Member")
            }

    department["id"] = str(department["_id"])
    department["status"] = department.get("status", "active")

    members = list(
        mongo.db.users.find({
            "department_id": department["id"],
            "role": {"$ne": "super_admin"}
        }).sort("username", 1)
    )

    member_ids = [str(m["_id"]) for m in members]

    tasks = list(
        mongo.db.tasks.find({
            "assigned_to": {"$in": member_ids},
            "is_deleted": {"$ne": True}
        })
    )

    now = datetime.utcnow()

    member_list = []

    for m in members:
        name_parts = (m.get("username") or "").split()
        member_list.append({
            "username": m.get("username"),
            "initials": "".join(p[0].upper() for p in name_parts[:2]) if name_parts else "U",
            "role": role_labels.get(m.get("role"), "Employee"),
            "email": m.get("email", ""),
            "phone": m.get("phone", "")
        })

    done_count = sum(1 for t in tasks if t.get("status") == "Approved")
    pending_count = sum(1 for t in tasks if t.get("status") != "Approved")
    overdue_count = sum(
        1 for t in tasks
        if t.get("status") != "Approved"
           and t.get("due_date")
           and t["due_date"] < now
    )

    return jsonify({
        "name": department.get("name"),
        "description": department.get("description", ""),
        "status": department["status"],
        "status_label": "Active" if department["status"] == "active" else "Inactive",
        "head": head_info,
        "created_label": to_ist(department.get("created_at")).strftime("%d %b %Y")
                        if department.get("created_at") else "-",
        "member_count": len(member_list),
        "member_list": member_list,
        "task_count": len(tasks),
        "done_count": done_count,
        "pending_count": pending_count,
        "overdue_count": overdue_count,
        "done_pct": round(done_count * 100 / len(tasks)) if tasks else 0
    })


@bp.route("/delete-department/<id>", methods=["POST"])
@login_required
def delete_department(id):

    if current_user.role not in ("super_admin", "admin"):
        abort(403)

    department = mongo.db.departments.find_one({
        "_id": ObjectId(id)
    })

    if not department:
        flash("Department not found.", "danger")
        return redirect(url_for("main.manage_departments"))

    if current_user.role == "admin" and department.get("company") != current_user.company:
        abort(403)

    linked_users = mongo.db.users.count_documents({
        "department_id": id
    })

    if linked_users > 0:
        flash(
            "Department cannot be deleted because users are assigned to it.",
            "danger"
        )

        return redirect(url_for("main.manage_departments"))

    mongo.db.departments.delete_one({
        "_id": ObjectId(id)
    })

    flash("Department deleted successfully.", "success")

    return redirect(url_for("main.manage_departments"))



# ---------------- MANAGER PANEL ----------------
@bp.route("/manager")
@login_required
def manager_panel():

    if current_user.role != "manager":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.admin_panel"))

    # ONLY employees under this manager's department
    manager_dept_id = current_user.department_id

    if manager_dept_id:
        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "department_id": manager_dept_id
            })
        )
    else:
        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

    print("Manager ID:", current_user.get_id())
    print("Employees found:", employees)

    for emp in employees:
        emp["id"] = str(emp["_id"])

    employee_ids = [str(emp["_id"]) for emp in employees]

    if employee_ids:

        tasks = list(
            mongo.db.tasks.find({
                "assigned_to": {"$in": employee_ids},
                "is_deleted": False
            })
        )

    else:
        tasks = []

    for task in tasks:
        task["id"] = str(task["_id"])
        
        if task.get("assigned_to"):
  
           employee = mongo.db.users.find_one({
               "_id": ObjectId(task["assigned_to"])
           })

           task["assignee"] = employee

        else:

           task["assignee"] = None
    return render_template(
        "manager_panel.html",
        tasks=tasks,
        employees=employees
    )
# ---------------- EMPLOYEE PANEL ----------------
@bp.route("/employee")
@login_required
def employee_panel():

    if current_user.role != "employee":
        flash("Unauthorized access", "danger")
        return redirect(url_for("main.admin_panel"))

    filter_type = request.args.get("filter", "mytasks")
    user_id = str(current_user.get_id())

    today = date.today()

    query = {
        "assigned_to": user_id,
        "is_deleted": False
    }

    if filter_type == "today":
        start_today = datetime.combine(today, datetime.min.time())
        end_today = datetime.combine(today, datetime.max.time())

        query["due_date"] = {
            "$gte": start_today,
            "$lte": end_today
        }

    elif filter_type == "upcoming":
        tomorrow_start = datetime.combine(
            today + timedelta(days=1),
            datetime.min.time()
        )

        query["due_date"] = {
            "$gte": tomorrow_start
        }

    elif filter_type == "completed":
        query["status"] = "Approved"

    tasks = list(mongo.db.tasks.find(query))

    for task in tasks:
        task["id"] = str(task["_id"])

        if task.get("created_by"):
            creator = mongo.db.users.find_one({
                "_id": ObjectId(task["created_by"])
            })
            task["creator"] = creator

        else:
            task["creator"] = None

    employee = mongo.db.users.find_one({
        "_id": ObjectId(user_id)
    })

    employee = mongo.db.users.find_one({
        "_id": ObjectId(user_id)
    })

    if employee:
        employee["id"] = str(employee["_id"])

    return render_template(
        "employee_panel.html",
        tasks=tasks,
        employee=employee,
        active_filter=filter_type
    )


# ---------------- ANALYTICS ----------------
@bp.route("/analytics")
@login_required
def analytics():

    if current_user.role not in ["admin", "manager"]:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    if current_user.role in ("super_admin", "admin"):

        employees = list(
            mongo.db.users.find({
                "role": "employee"
            })
        )

    else:

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

    employee_ids = [str(emp["_id"]) for emp in employees]

    if employee_ids:

        tasks = list(
            mongo.db.tasks.find({
                "assigned_to": {"$in": employee_ids},
                "is_deleted": False
            })
        )

    else:
        tasks = []

    total = len(tasks)

    approved = len([
        t for t in tasks
        if t.get("status") == "Approved"
    ])

    pending = len([
        t for t in tasks
        if t.get("status") != "Approved"
    ])

    today = date.today()

    overdue_tasks = []

    for t in tasks:
        due_date = t.get("due_date")

        if due_date and t.get("status") != "Approved":

            due_date_only = due_date.date() if hasattr(due_date, "date") else due_date

            if due_date_only < today:
                overdue_tasks.append(t)

    overdue = len(overdue_tasks)

    employee_names = []
    employee_completed = []
    employee_points = []
    employee_report = []

    for emp in employees:

        emp_id = str(emp["_id"])

        emp_tasks = [
            t for t in tasks
            if t.get("assigned_to") == emp_id
        ]

        completed = len([
            t for t in emp_tasks
            if t.get("status") == "Approved"
        ])

        pending_count = len([
            t for t in emp_tasks
            if t.get("status") != "Approved"
        ])

        in_progress = len([
            t for t in emp_tasks
            if t.get("work_status") == "Started"
        ])

        employee_names.append(emp.get("username"))
        employee_completed.append(completed)
        employee_points.append(emp.get("points", 0))

        employee_report.append({
            "name": emp.get("username"),
            "completed": completed,
            "pending": pending_count,
            "in_progress": in_progress,
            "points": emp.get("points", 0)
        })

    project_completed = approved
    project_remaining = total - approved if total >= approved else 0
    progress_percent = round((approved / total) * 100, 2) if total > 0 else 0

    overdue_task_data = []

    for task in overdue_tasks:

        assigned_to = task.get("assigned_to")

        employee = mongo.db.users.find_one({
            "_id": ObjectId(assigned_to)
        }) if assigned_to else None

        overdue_task_data.append({
            "title": task.get("title"),
            "employee": employee.get("username") if employee else "-",
            "due_date": task.get("due_date"),
            "status": task.get("status")
        })

    month_labels = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]

    productivity_trend = [0] * 12

    for task in tasks:

        completed_at = task.get("completed_at")

        if task.get("status") == "Approved" and completed_at:
            productivity_trend[completed_at.month - 1] += 1

    top_performer = None

    if employees:
        top_emp = max(
            employees,
            key=lambda e: e.get("points", 0)
        )

        top_performer = top_emp.get("username")

    return render_template(
        "analytics.html",
        total=total,
        approved=approved,
        pending=pending,
        overdue=overdue,
        employee_names=employee_names,
        employee_completed=employee_completed,
        employee_points=employee_points,
        employee_report=employee_report,
        project_completed=project_completed,
        project_remaining=project_remaining,
        progress_percent=progress_percent,
        overdue_tasks=overdue_task_data,
        month_labels=month_labels,
        productivity_trend=productivity_trend,
        top_performer=top_performer
    )
    

from xhtml2pdf import pisa
import io


@bp.route("/notifications")
@login_required
def notifications():

    if current_user.role != "super_admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("main.my_reminders"))

    mongo.db.notifications.update_many(
        {"target_role": "super_admin", "read": False},
        {"$set": {"read": True}}
    )

    lock_after_attempts = get_system_settings().get("lock_after_attempts", 5)

    reconcile_lock_notifications()

    entries = list(
        mongo.db.notifications
        .find({"target_role": "super_admin"})
        .sort("created_at", -1)
        .limit(100)
    )

    for e in entries:
        e["id"] = str(e.get("_id"))
        e["time_ist"] = to_ist(e.get("created_at"))
        name_parts = (e.get("ref_username") or "").split()
        e["initials"] = "".join(p[0].upper() for p in name_parts[:2]) or "S"

        user_doc = None
        if e.get("ref_user_id"):
            user_doc = mongo.db.users.find_one({"_id": ObjectId(e["ref_user_id"])})

        if not user_doc:
            e["locked"] = False
            e["resolved"] = True
        else:
            e["locked"] = user_doc.get("failed_attempts", 0) >= lock_after_attempts
            e["resolved"] = not e["locked"]

    avatar_palette = ["#2563eb", "#7c3aed", "#db2777", "#ea580c", "#16a34a", "#0891b2", "#ca8a04", "#dc2626"]

    for e in entries:
        e["_avatar_color"] = avatar_palette[sum(ord(c) for c in e.get("ref_username", "")) % len(avatar_palette)]

    return render_template(
        "notifications.html",
        entries=entries
    )


@bp.route("/activity-logs")
@login_required
def activity_logs():

    page = max(1, request.args.get("page", 1, type=int))
    per_page = 12

    query = build_activity_query(current_user, request.args)

    grand_total = mongo.db.activity_log.count_documents({})
    total = mongo.db.activity_log.count_documents(query)

    entries = list(
        mongo.db.activity_log
        .find(query)
        .sort("created_at", -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    avatar_palette = ["#2563eb", "#7c3aed", "#db2777", "#ea580c", "#16a34a", "#0891b2", "#ca8a04", "#dc2626"]

    for e in entries:
        e["id"] = str(e.get("_id"))
        e["time_ist"] = to_ist(e.get("created_at"))
        e["_avatar_color"] = avatar_palette[sum(ord(c) for c in e.get("username", "")) % len(avatar_palette)]

    users = list(
        mongo.db.users.find(
            {},
            {"username": 1, "role": 1, "company": 1}
        ).sort("username", 1)
    )

    if current_user.role != "super_admin":
        scoped_ids = []

        if current_user.role == "admin":
            scoped_ids = [
                str(u["_id"]) for u in mongo.db.users.find(
                    {"company": current_user.company or ""}
                )
            ]
            scoped_ids.append(str(current_user.get_id()))

        elif current_user.role == "manager":
            scoped_ids = [
                str(e2["_id"]) for e2 in mongo.db.users.find(
                    {"supervisor_id": str(current_user.get_id())}
                )
            ]
            scoped_ids.append(str(current_user.get_id()))

        else:
            scoped_ids = [str(current_user.get_id())]

        users = [u for u in users if str(u["_id"]) in scoped_ids]

    actions = sorted(mongo.db.activity_log.distinct("event_type"))
    modules = sorted(mongo.db.activity_log.distinct("module"))

    total_pages = max(1, (total + per_page - 1) // per_page)
    start = (page - 1) * per_page + 1 if total else 0
    end = min(page * per_page, total)

    return render_template(
        "activity_logs.html",
        entries=entries,
        total=total,
        grand_total=grand_total,
        total_pages=total_pages,
        page=page,
        start=start,
        end=end,
        users=users,
        actions=actions,
        modules=modules,
        q=request.args.get("q", ""),
        filter_user=request.args.get("user", ""),
        filter_action=request.args.get("action", ""),
        filter_module=request.args.get("module", ""),
        from_date=request.args.get("from", ""),
        to_date=request.args.get("to", "")
    )


@bp.route("/activity-logs/export")
@login_required
def export_activity_logs():

    query = build_activity_query(current_user, request.args)

    entries = list(
        mongo.db.activity_log
        .find(query)
        .sort("created_at", -1)
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["User", "Action", "Module", "Description", "Device", "Timestamp (IST)"])

    for e in entries:
        ts = to_ist(e.get("created_at"))
        writer.writerow([
            e.get("username", ""),
            e.get("event_type", ""),
            e.get("module", ""),
            e.get("description", ""),
            e.get("device", ""),
            ts.strftime("%d %b %Y %I:%M %p") if ts else ""
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=activity_logs.csv"

    return response


@bp.route("/task-history")
@login_required
def task_history():

    selected_employee_id = request.args.get("employee_id")
    overdue = request.args.get("overdue")

    # ---------------- ADMIN ----------------
    if current_user.role in ("super_admin", "admin"):

        query = {
            "is_deleted": {"$ne": True}
        }

        if selected_employee_id:
            query["assigned_to"] = selected_employee_id

        tasks = list(
            mongo.db.tasks.find(query).sort("created_at", -1)
        )

    # ---------------- MANAGER ----------------
    elif current_user.role == "manager":

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

        employee_ids = [str(emp["_id"]) for emp in employees]

        query = {
            "assigned_to": {"$in": employee_ids},
            "is_deleted": {"$ne": True}
        }

        if selected_employee_id:

            if selected_employee_id not in employee_ids:
                flash("Unauthorized employee selection", "danger")
                return redirect(url_for("main.task_history"))

            query["assigned_to"] = selected_employee_id

        tasks = list(
            mongo.db.tasks.find(query).sort("created_at", -1)
        )

    # ---------------- EMPLOYEE ----------------
    else:

        tasks = list(
            mongo.db.tasks.find({
                "assigned_to": str(current_user.get_id()),
                "is_deleted": {"$ne": True}
            }).sort("created_at", -1)
        )

    # Format dates
    for task in tasks:

        task["id"] = str(task["_id"])

        task["created_at_ist"] = to_ist(
            task.get("created_at")
        )

        task["completed_at_ist"] = to_ist(
            task.get("completed_at")
        )

        # Employee name
        assigned_to = task.get("assigned_to")

        if assigned_to:

            employee = mongo.db.users.find_one({
                "_id": ObjectId(assigned_to)
            })

            task["employee_name"] = (
                employee.get("username")
                if employee else "-"
            )

        else:
            task["employee_name"] = "-"

    if overdue:
        now_utc = datetime.utcnow()
        tasks = [
            t for t in tasks
            if t.get("status") != "Approved"
            and t.get("due_date")
            and t.get("due_date") < now_utc
        ]

    return render_template(
        "task_history.html",
        tasks=tasks,
        overdue=bool(overdue)
    )



@bp.route("/export-report")
@login_required
def export_report_pdf():

    employees = list(mongo.db.users.find({
        "role": "employee"
    }))

    employee_report = []

    for e in employees:

        emp_id = str(e["_id"])

        completed = mongo.db.tasks.count_documents({
            "assigned_to": emp_id,
            "status": "Approved"
        })

        pending = mongo.db.tasks.count_documents({
            "assigned_to": emp_id,
            "status": {"$ne": "Approved"}
        })

        employee_report.append({
            "name": e.get("username"),
            "completed": completed,
            "pending": pending,
            "points": e.get("points", 0)
        })

    html = render_template(
        "report_pdf.html",
        employee_report=employee_report
    )

    pdf = io.BytesIO()

    pisa.CreatePDF(
        io.StringIO(html),
        pdf
    )

    response = make_response(pdf.getvalue())

    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=flowra_report.pdf"

    return response



@bp.route("/task-history/export")
@login_required
def export_task_history():

    selected_employee_id = request.args.get("employee_id")

    # Admin users
    if current_user.role in ("super_admin", "admin"):
        query = {
            "is_deleted": {"$ne": True}
        }

        if selected_employee_id:
            query["assigned_to"] = selected_employee_id

        tasks = list(
            mongo.db.tasks.find(query).sort("created_at", -1)
        )

    # Manager users
    elif current_user.role == "manager":

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

        employee_ids = [str(emp["_id"]) for emp in employees]

        query = {
            "assigned_to": {"$in": employee_ids},
            "is_deleted": {"$ne": True}
        }

        if selected_employee_id:

            if selected_employee_id not in employee_ids:
                flash("Unauthorized employee selection", "danger")
                return redirect(url_for("main.export_task_history"))

            query["assigned_to"] = selected_employee_id

        tasks = list(
            mongo.db.tasks.find(query).sort("created_at", -1)
        )

    else:
        flash("Unauthorized", "danger")
        return redirect(url_for("main.task_history"))

    data = []

    for task in tasks:

        assigned_to = task.get("assigned_to")
        created_by = task.get("created_by")

        assignee = mongo.db.users.find_one({
            "_id": ObjectId(assigned_to)
        }) if assigned_to else None

        creator = mongo.db.users.find_one({
            "_id": ObjectId(created_by)
        }) if created_by else None

        department_name = "-"

        if assignee and assignee.get("department_id"):

            dept = mongo.db.departments.find_one({
                "_id": ObjectId(assignee.get("department_id"))
            })

            if dept:
                department_name = dept.get("name", "-")

        data.append({
            "Task ID": str(task["_id"]),
            "Title": task.get("title", "-"),
            "Description": task.get("description", "-"),
            "Priority": task.get("priority", "-"),
            "Status": task.get("status", "-"),
            "Deleted": "Yes" if task.get("is_deleted") else "No",
            "Assigned To": assignee.get("username") if assignee else "-",
            "Assigned By": creator.get("username") if creator else "-",
            "Department": department_name,
            "Reward Points": task.get("reward_points", 0),
            "Work Status": task.get("work_status", "-"),
            "Start Time": task.get("start_time").strftime("%Y-%m-%d %H:%M:%S") if task.get("start_time") else "-",
            "End Time": task.get("end_time").strftime("%Y-%m-%d %H:%M:%S") if task.get("end_time") else "-",
            "Total Time Spent (sec)": task.get("total_time_spent", 0),
            "Created At": task.get("created_at").strftime("%Y-%m-%d %H:%M:%S") if task.get("created_at") else "-",
            "Completed At": task.get("completed_at").strftime("%Y-%m-%d %H:%M:%S") if task.get("completed_at") else "-",
            "Due Date": task.get("due_date").strftime("%Y-%m-%d %H:%M:%S") if task.get("due_date") else "-",
            "Remarks": task.get("remarks", "-"),
            "Proof File": task.get("proof_file", "-")
        })

    df = pd.DataFrame(data)

    output = BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(
            writer,
            index=False,
            sheet_name="Task History"
        )

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="task_history.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
@bp.route("/task/reject/<id>", methods=["POST"])
@login_required
def reject_task(id):

    if current_user.role not in ["admin", "manager"]:
        return "Unauthorized"

    remarks = request.form.get("remarks")

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.dashboard"))

    mongo.db.tasks.update_one(
        {"_id": ObjectId(id)},
        {"$set": {
            "status": "Rejected",
            "remarks": remarks,
            "updated_at": datetime.utcnow()
        }}
    )

    flash("Task rejected with remarks", "warning")

    if current_user.role in ("super_admin", "admin"):
        return redirect(url_for("main.admin_panel"))

    return redirect(url_for("main.manager_panel"))


@bp.route("/productivity")
@login_required
def productivity():

    if current_user.role not in ("super_admin", "admin"):
        return "Unauthorized"

    employees = list(
        mongo.db.users.find({
            "role": {"$in": ["manager", "employee"]}
        })
    )

    stats = []

    for emp in employees:

        emp_id = str(emp["_id"])

        total = mongo.db.tasks.count_documents({
            "assigned_to": emp_id
        })

        completed = mongo.db.tasks.count_documents({
            "assigned_to": emp_id,
            "status": "Approved"
        })

        stats.append({
            "employee": emp.get("username"),
            "total": total,
            "completed": completed
        })

    return render_template(
        "productivity.html",
        stats=stats
    )





@bp.route("/resubmit-task/<id>", methods=["POST"])
@login_required
def resubmit_task(id):

    if current_user.role != "employee":
        return "Unauthorized"

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.employee_panel"))

    if task.get("status") != "Rejected":
        return redirect(url_for("main.employee_panel"))

    update_data = {
        "status": "Submitted",
        "remarks": None,
        "updated_at": datetime.utcnow()
    }

    file = request.files.get("proof_file")

    if file and file.filename != "":

        upload_folder = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        old_file = task.get("proof_file")

        if old_file:
            old_path = os.path.join(upload_folder, old_file)
            if os.path.exists(old_path):
                os.remove(old_path)

        filename = secure_filename(file.filename)
        new_path = os.path.join(upload_folder, filename)
        file.save(new_path)

        update_data["proof_file"] = filename

    mongo.db.tasks.update_one(
        {"_id": ObjectId(id)},
        {"$set": update_data}
    )

    flash("Task resubmitted successfully!", "success")

    return redirect(url_for("main.employee_panel"))


@bp.route("/download_attachment/<filename>")
@login_required
def download_attachment(filename):

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    file_path = os.path.join(upload_folder, filename)

    if not os.path.exists(file_path):
        flash("File not found", "danger")
        return redirect(url_for("main.dashboard"))

    return send_from_directory(
        upload_folder,
        filename,
        as_attachment=True
    )




# START WORK
@bp.route("/task/start/<id>")
@login_required
def start_task(id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.employee_panel"))

    if current_user.role != "employee" or task.get("assigned_to") != str(current_user.get_id()):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.employee_panel"))

    if task.get("work_status") != "Started":

        mongo.db.tasks.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "work_status": "Started",
                "start_time": datetime.utcnow(),
                "end_time": None,
                "is_timer_running": True,
                "updated_at": datetime.utcnow()
            }}
        )

        flash("Work Started!", "success")

    return redirect(url_for("main.employee_panel"))


# STOP WORK
@bp.route("/task/stop/<id>")
@login_required
def stop_task(id):

    task = mongo.db.tasks.find_one({
        "_id": ObjectId(id)
    })

    if not task:
        flash("Task not found", "danger")
        return redirect(url_for("main.employee_panel"))

    if current_user.role != "employee" or task.get("assigned_to") != str(current_user.get_id()):
        flash("Unauthorized", "danger")
        return redirect(url_for("main.employee_panel"))

    if task.get("work_status") == "Started" and task.get("start_time"):

        now = datetime.utcnow()

        elapsed = int(
            (now - task.get("start_time")).total_seconds()
        )

        total_time_spent = task.get("total_time_spent", 0) + elapsed

        mongo.db.tasks.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "work_status": "Stopped",
                "end_time": now,
                "start_time": None,
                "is_timer_running": False,
                "total_time_spent": total_time_spent,
                "updated_at": now
            }}
        )

        flash(f"Work Stopped! Total seconds worked: {total_time_spent}", "warning")

    return redirect(url_for("main.employee_panel"))


# ---------------- LOGOUT ----------------
@bp.route("/logout")
@login_required
def logout():

    mongo.db.users.update_one(
        {"_id": ObjectId(current_user.get_id())},
        {"$set": {
            "is_logged_in": False,
            "active_session_token": None,
            "last_seen": datetime.utcnow()
        }}
    )

    logout_user()
    session.clear()

    return redirect(url_for("main.home"))



