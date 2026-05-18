from datetime import datetime, timedelta
from app import db
from app.models import RecurringTask, User, Reminder
from app.utils.whatsapp import send_whatsapp_message


def recurring_task_job(app):
    with app.app_context():
        today = datetime.utcnow().date()

        tasks = RecurringTask.query.all()

        for task in tasks:
            if not (task.start_date <= today <= task.end_date):
                continue

            if task.last_generated == today:
                continue

            should_send = False

            if task.frequency == "daily":
                should_send = True
            elif task.frequency == "weekly":
                should_send = today.weekday() == task.start_date.weekday()
            elif task.frequency == "monthly":
                should_send = today.day == task.start_date.day

            if not should_send:
                continue

            user = User.query.get(task.assigned_to)

            if not user:
                print(f"Recurring task skipped: user not found for task {task.id}")
                continue

            if user.phone:
                message = f"""
🔁 Recurring Task Reminder

Hello {user.username},

Task: {task.title}
📅 Date: {today}
🔁 Frequency: {task.frequency.title()}

Please complete your task today.
"""
                try:
                    send_whatsapp_message(user.phone, message)
                    print(f"Recurring WhatsApp sent to {user.username}")
                except Exception as e:
                    print("Recurring WhatsApp error:", e)

            try:
                reminder = Reminder(
                    reason=f"Recurring Task: {task.title}",
                    remind_at=datetime.utcnow() + timedelta(seconds=5),
                    end_at=None,
                    user_id=user.id,
                    is_daily=False,
                    active=True
                )
                db.session.add(reminder)
            except Exception as e:
                print("Recurring reminder error:", e)

            task.last_generated = today

        db.session.commit()