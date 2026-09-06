from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, session, current_app, send_from_directory,
    send_file, make_response
)
from flask import abort
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from app.extensions import mongo
from app.models import MongoUser, hash_password
from app.utils.whatsapp import send_whatsapp_message
from bson import ObjectId
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
from io import BytesIO
import pandas as pd
import os
import re
import uuid
import io

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


@bp.before_app_request
def keep_session_alive():

    if current_user.is_authenticated:

        saved_token = session.get("session_token")
        current_token = getattr(current_user, "active_session_token", None)

        print("SESSION TOKEN:", saved_token)
        print("CURRENT TOKEN:", current_token)

        if current_token and saved_token != current_token:
            logout_user()
            session.clear()
            flash(
                "Your session was ended because this account was approved on another device.",
                "warning"
            )
            return redirect(url_for("main.login"))

        session["last_activity"] = datetime.utcnow().isoformat()
@bp.route("/")
def home():
    return render_template("home.html")


# ---------------- LOGIN ----------------
@bp.route("/login", methods=["GET", "POST"])
def login():

    existing_admin = mongo.db.users.find_one({"role": "admin"})

    if not existing_admin:
        mongo.db.users.insert_one({
            "username": "admin",
            "email": "admin@example.com",
            "role": "admin",
            "password_hash": hash_password("admin123"),
            "phone": "",
            "points": 0,
            "is_logged_in": False,
            "active_session_token": None,
            "last_seen": None,
            "created_at": datetime.utcnow()
        })

        print("Default admin created: admin / admin123")

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user_doc = mongo.db.users.find_one({"username": username})

        if user_doc and check_password_hash(user_doc.get("password_hash", ""), password):

            current_device = request.headers.get("User-Agent", "Unknown Device")

            if user_doc.get("is_logged_in") is True and user_doc.get("last_seen"):
                if datetime.utcnow() - user_doc.get("last_seen") > timedelta(seconds=20):
                    mongo.db.users.update_one(
                        {"_id": user_doc["_id"]},
                        {"$set": {
                            "is_logged_in": False,
                            "active_session_token": None
                        }}
                    )
                    user_doc["is_logged_in"] = False
                    user_doc["active_session_token"] = None

            if user_doc.get("is_logged_in") is True:

                if session.get("session_token") == user_doc.get("active_session_token"):
                    pass

                else:
                    existing_pending = mongo.db.login_requests.find_one({
                        "user_id": str(user_doc["_id"]),
                        "status": "Pending"
                    })

                    if (
                        existing_pending is not None
                        and existing_pending.get("created_at") is not None
                        and datetime.utcnow() - existing_pending.get("created_at") > timedelta(minutes=2)
                    ):
                        mongo.db.login_requests.update_one(
                            {"_id": existing_pending["_id"]},
                            {"$set": {"status": "Denied"}}
                        )

                        mongo.db.users.update_one(
                            {"_id": user_doc["_id"]},
                            {"$set": {
                                "is_logged_in": False,
                                "active_session_token": None
                            }}
                        )

                        existing_pending = None
                        user_doc["is_logged_in"] = False
                        user_doc["active_session_token"] = None

                    if existing_pending is not None:
                        return jsonify({
                            "status": "waiting",
                            "token": existing_pending.get("token"),
                            "message": "Waiting for approval..."
                        })

                    token = str(uuid.uuid4())

                    mongo.db.login_requests.insert_one({
                        "user_id": str(user_doc["_id"]),
                        "device_info": current_device,
                        "ip_address": request.remote_addr,
                        "token": token,
                        "status": "Pending",
                        "created_at": datetime.utcnow()
                    })

                    return jsonify({
                        "status": "waiting",
                        "token": token,
                        "message": "Login request sent"
                    })

            session_token = str(uuid.uuid4())

            mongo.db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {
                    "is_logged_in": True,
                    "active_session_token": session_token,
                    "last_seen": datetime.utcnow()
                }}
            )

            updated_user = mongo.db.users.find_one({"_id": user_doc["_id"]})

            login_user(MongoUser(updated_user))

            session["last_activity"] = datetime.utcnow().isoformat()
            session["session_token"] = session_token

            role = updated_user.get("role")

            if role == "admin":
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

        return jsonify({
            "status": "error",
            "message": "Invalid username or password"
        })

    return render_template("login.html")


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

    if role == "admin":
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

    role = current_user.role
    user_id = str(current_user.get_id())

    if role == "admin":

        tasks = list(mongo.db.tasks.find({
            "is_deleted": False
        }))

        managers = list(mongo.db.users.find({
            "role": "manager"
        }))

        employees = list(mongo.db.users.find({
            "role": "employee"
        }))

        departments = list(mongo.db.departments.find())

        department_tasks = {}

        for dept in departments:

            dept_id = str(dept.get("_id"))

            users = list(mongo.db.users.find({
                "department_id": dept_id
            }))

            ids = [str(u.get("_id")) for u in users]

            if ids:
                dept_tasks = list(mongo.db.tasks.find({
                    "assigned_to": {"$in": ids},
                    "is_deleted": False
                }))
            else:
                dept_tasks = []

            department_tasks[dept.get("name")] = dept_tasks

        return render_template(
            "admin_panel.html",
            tasks=tasks,
            managers=managers,
            employees=employees,
            department_tasks=department_tasks
        )

    elif role == "manager":

        employees = list(mongo.db.users.find({
            "supervisor_id": user_id
        }))

        employee_ids = [str(emp.get("_id")) for emp in employees]

        tasks = list(mongo.db.tasks.find({
            "assigned_to": {"$in": employee_ids},
            "is_deleted": False
        })) if employee_ids else []

        return render_template(
            "manager_panel.html",
            tasks=tasks,
            employees=employees
        )

    else:

        tasks = list(mongo.db.tasks.find({
            "assigned_to": user_id,
            "is_deleted": False
        }))

        employee = mongo.db.users.find_one({
            "_id": ObjectId(user_id)
        })

        return render_template(
            "employee_panel.html",
            tasks=tasks,
            employee=employee
        )


@bp.route("/reminders_page")
@login_required
def reminders_page():
    return render_template("reminders.html")


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

    if current_user.role not in ["admin", "manager"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST": 


        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority")
        assigned_to_id = request.form.get("assigned_to")

        print("=" * 50)
        print("FORM DATA =", request.form)
        print("ASSIGNED_TO_ID =", assigned_to_id)
        print("=" * 50)
        due_date_str = request.form.get("due_date")
        reward_points = int(request.form.get("reward_points", 5))
        estimated_time = request.form.get("estimated_time")

        print("Reward points from form:", reward_points)

        if not title:
            flash("Title is required", "danger")
            return redirect(request.url)

        due_date = None

        if due_date_str:
            try:
                due_date = datetime.strptime(
                    due_date_str,
                    "%Y-%m-%dT%H:%M"
                )
            except ValueError:
                flash("Invalid date format", "danger")
                return redirect(request.url)

        if not description:
            description = "General task created"

        assigned_to = assigned_to_id if assigned_to_id else None

        task_data = {
            "title": title,
            "description": description,
            "priority": priority,
            "due_date": due_date,
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
                "active": True,
                "created_at": datetime.utcnow()
            })

        # WhatsApp notification
        if assigned_to:

            employee = mongo.db.users.find_one({
                "_id": ObjectId(assigned_to)
            })

            print("Assigned To ID:", assigned_to)
            print("Employee object:", employee)

            if employee:

                print("Employee username:", employee.get("username"))
                print("Employee phone:", employee.get("phone"))

            if employee and employee.get("phone"):

                message = f"""
Hello {employee.get('username')},

You have been assigned a new task.

📌 Task: {title}
⏰ Due Date: {due_date}
🏆 Reward Points: {reward_points}

Please check your dashboard.
"""

                print("About to send WhatsApp message...")
                print("Message body:", message)

                try:
                    send_whatsapp_message(
                        employee.get("phone"),
                        message
                    )

                    print("send_whatsapp_message function called successfully")

                except Exception as e:
                    print("WhatsApp Error:", e)

            else:
                print("Employee phone missing or employee not found")

        else:
            print("No assigned_to value received")

        flash("Task created successfully!", "success")

        if current_user.role == "manager":
            return redirect(url_for("main.manager_panel"))

        return redirect(url_for("main.admin_panel"))

    # Manager employee filter
    if current_user.role == "manager":

        employees = list(
            mongo.db.users.find({
                "role": "employee",
                "supervisor_id": str(current_user.get_id())
            })
        )

    else:

        employees = list(
            mongo.db.users.find({
                "role": "employee"
            })
        )
    for emp in employees:
        emp["id"] = str(emp["_id"])

    return render_template(
        "create_task.html",
        users=employees
    )



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

    if current_user.role == "admin":
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

    if current_user.role != "admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    user = mongo.db.users.find_one({
        "_id": ObjectId(id)
    })

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("main.dashboard"))

    managers = list(
        mongo.db.users.find({
            "role": "manager"
        })
    )
    for mgr in managers:
        mgr["id"] = str(mgr["_id"])


    departments = list(
        mongo.db.departments.find()
    )
    for  dept in departments:
         dept["id"] = str(dept["_id"])

    if request.method == "POST":

        username = request.form.get("username", "").capitalize()
        email = request.form.get("email")
        phone = request.form.get("phone")
        role = request.form.get("role")
        department_id = request.form.get("department_id")
        supervisor_id = request.form.get("supervisor_id")
                 
        print("ROLE =",  role)
        print("SUPERVISOR =", supervisor_id)
        print("DEPARTMENT =" , department_id)
        if not re.match(r'^\+\d{10,15}$', phone):
            flash(
                "Invalid phone number format. Use +919876543210",
                "danger"
            )
            return redirect(url_for("main.edit_user", id=id))

        # Duplicate username check
        existing_username = mongo.db.users.find_one({
            "username": username,
            "_id": {"$ne": ObjectId(id)}
        })

        if existing_username:
            flash("Username already exists!", "danger")
            return redirect(url_for("main.edit_user", id=id))

        # Duplicate phone check
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

        mongo.db.users.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_data}
        )

        flash("User updated successfully!", "success")

        return redirect(url_for("main.admin_panel"))

    return render_template(
        "edit_user.html",
        user=user,
        managers=managers,
        departments=departments
    )

@bp.route("/recurring-task-history")
@login_required
def recurring_task_history():

    if current_user.role not in ["admin", "manager"]:
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
Here’s a smart action plan for this task:

**Task:** {title}

**Current Status:** {status}  
**Priority:** {priority}

**What you should do first:**  
Start by understanding the exact requirement of the task. Read the title and description carefully, then divide the work into small steps.

**Suggested steps:**  
1. Identify the main goal of the task.  
2. Break it into 2–3 smaller subtasks.  
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

@bp.route("/delete_user/<user_id>", methods=["POST"])
@login_required
def delete_user(user_id):

    if current_user.role != "admin":
        abort(403)

    user = mongo.db.users.find_one({
        "_id": ObjectId(user_id)
    })

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.manage_users"))

    if str(user["_id"]) == str(current_user.get_id()):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("main.manage_users"))

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

    if current_user.role not in ["admin", "manager"]:
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

    if current_user.role != "admin" and task.get("created_by") != str(current_user.get_id()):
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

    elif current_user.role == "admin":
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

    elif current_user.role == "admin":
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

    # Allow Admin + Manager
    if current_user.role not in ["admin", "manager"]:
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

    if current_user.role != "admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    managers = list(
        mongo.db.users.find({
            "role": "manager"
        })
    )

    departments = list(
        mongo.db.departments.find()
    )

    if request.method == "POST":

        username = request.form.get("username", "").capitalize()
        email = request.form.get("email")
        department_id = request.form.get("department_id")
        phone = request.form.get("phone")
        password = request.form.get("password")
        role = request.form.get("role")
        supervisor_id = request.form.get("supervisor_id")

        if not re.match(r'^\+\d{10,15}$', phone):
            flash("Invalid phone number format. Use +919876543210", "danger")
            return redirect(url_for("main.create_user"))

        existing_user = mongo.db.users.find_one({
            "$or": [
                {"username": username},
                {"email": email},
                {"phone": phone}
            ]
        })

        if existing_user:
            flash("Username, Email or Phone already exists!", "danger")
            return redirect(url_for("main.create_user"))

        if role == "employee" and supervisor_id:
            supervisor_id = supervisor_id
        else:
            supervisor_id = None

        mongo.db.users.insert_one({
            "username": username,
            "email": email,
            "department_id": department_id,
            "phone": phone,
            "role": role,
            "supervisor_id": supervisor_id,
            "password_hash": hash_password(password),
            "points": 0,
            "is_logged_in": False,
            "active_session_token": None,
            "last_seen": None,
            "created_at": datetime.utcnow()
        })

        flash("User created successfully!", "success")
        return redirect(url_for("main.admin_panel"))

    return render_template(
        "create_user.html",
        managers=managers,
        departments=departments
    )



@bp.route("/manage-users")
@login_required
def manage_users():

    if current_user.role != "admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    users = list(mongo.db.users.find())

    for user in users:
        user["id"] = str(user["_id"])

        dept_id = user.get("department_id")

        if dept_id:
            dept = mongo.db.departments.find_one({
                "_id": ObjectId(dept_id)
            })
            user["department"] = dept
        else:
            user["department"] = None

    return render_template(
        "manage_users.html",
        users=users
    )
@bp.route("/department-dashboard")
@login_required
def department_dashboard():

    if current_user.role != "admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    departments = list(mongo.db.departments.find())
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

    if current_user.role != "admin":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.dashboard"))

    managers = list(mongo.db.users.find({"role": "manager"}))
    employees = list(mongo.db.users.find({"role": "employee"}))
    departments = list(mongo.db.departments.find())

    for manager in managers:
        manager["id"] = str(manager["_id"])

    for employee in employees:
        employee["id"] = str(employee["_id"])

    department_tasks = {}

    for dept in departments:
        dept_id = str(dept["_id"])
        dept_name = dept.get("name", "Unknown Department")

        users = list(mongo.db.users.find({
            "department_id": dept_id
        }))

        ids = [str(user["_id"]) for user in users]

        tasks = list(mongo.db.tasks.find({
            "assigned_to": {"$in": ids},
            "is_deleted": False
        })) if ids else []

        for task in tasks:
            task["id"] = str(task["_id"])
   
            if task.get("assigned_to"):
               employee = mongo.db.users.find_one({
                   "_id": ObjectId(task["assigned_to"])
               })
               task["assignee"] = employee
            else:
                task["assignee"] = None 
        department_tasks[dept_name] = tasks

    return render_template(
        "admin_panel.html",
        managers=managers,
        employees=employees,
        department_tasks=department_tasks
    )

@bp.route("/create-department", methods=["GET", "POST"])
@login_required
def create_department():

    if current_user.role != "admin":
        flash("Only admin can create departments", "danger")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()

        if not name:
            flash("Department name is required", "danger")
            return redirect(url_for("main.create_department"))

        existing = mongo.db.departments.find_one({
            "name": name
        })

        if existing:
            flash("Department already exists", "danger")
            return redirect(url_for("main.create_department"))

        mongo.db.departments.insert_one({
            "name": name,
            "created_at": datetime.utcnow()
        })

        flash("Department created successfully!", "success")
        return redirect(url_for("main.admin_panel"))

    departments = list(mongo.db.departments.find())

    for dept in departments:
        dept["id"] = str(dept["_id"])

    return render_template(
        "create_department.html",
        departments=departments
    )


@bp.route("/delete-department/<id>", methods=["POST"])
@login_required
def delete_department(id):

    if current_user.role != "admin":
        abort(403)

    department = mongo.db.departments.find_one({
        "_id": ObjectId(id)
    })

    if not department:
        flash("Department not found.", "danger")
        return redirect(url_for("main.create_department"))

    linked_users = mongo.db.users.count_documents({
        "department_id": id
    })

    if linked_users > 0:
        flash(
            "Department cannot be deleted because users are assigned to it.",
            "danger"
        )

        return redirect(url_for("main.create_department"))

    mongo.db.departments.delete_one({
        "_id": ObjectId(id)
    })

    flash("Department deleted successfully.", "success")

    return redirect(url_for("main.create_department"))



# ---------------- MANAGER PANEL ----------------
@bp.route("/manager")
@login_required
def manager_panel():

    if current_user.role != "manager":
        flash("Unauthorized", "danger")
        return redirect(url_for("main.admin_panel"))

    # ONLY employees under this manager
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

    if current_user.role == "admin":

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


@bp.route("/task-history")
@login_required
def task_history():

    selected_employee_id = request.args.get("employee_id")

    # ---------------- ADMIN ----------------
    if current_user.role == "admin":

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

    return render_template(
        "task_history.html",
        tasks=tasks
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
    if current_user.role == "admin":

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

    if current_user.role == "admin":
        return redirect(url_for("main.admin_panel"))

    return redirect(url_for("main.manager_panel"))


@bp.route("/productivity")
@login_required
def productivity():

    if current_user.role != "admin":
        return "Unauthorized"

    employees = list(
        mongo.db.users.find({
            "role": {"$ne": "admin"}
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

    flash("Logged out successfully.", "success")

    return redirect(url_for("main.home"))



