from datetime import datetime, timedelta
from app.extensions import mongo


def recurring_task_job(app):
    with app.app_context():
        today = datetime.utcnow().date()

        recurring_tasks = list(
            mongo.db.recurring_tasks.find({"is_deleted": {"$ne": True}})
        )

        for task in recurring_tasks:
            start_date = task.get("start_date")
            end_date = task.get("end_date")
            frequency = task.get("frequency", "")

            if not start_date or not end_date:
                continue

            if not (start_date.date() <= today <= end_date.date()):
                continue

            last_generated = task.get("last_generated")

            if isinstance(last_generated, datetime) and last_generated.date() == today:
                continue
            if isinstance(last_generated, str):
                try:
                    if datetime.fromisoformat(last_generated).date() == today:
                        continue
                except ValueError:
                    pass

            should_create = False

            if frequency == "daily":
                should_create = True
            elif frequency == "weekly":
                should_create = today.weekday() == start_date.weekday()
            elif frequency == "monthly":
                should_create = today.day == start_date.day

            if not should_create:
                continue

            assigned_to = task.get("assigned_to")
            user = mongo.db.users.find_one({"_id": __import__("bson").ObjectId(assigned_to)}) if assigned_to else None

            if not user:
                print(f"Recurring task skipped: user not found for task {task.get('_id')}")
                continue

            recurring_task_id = str(task["_id"])

            existing = mongo.db.tasks.find_one({
                "recurring_task_id": recurring_task_id,
                "generated_date": today.strftime("%Y-%m-%d")
            })

            if existing:
                continue

            task_data = {
                "title": task.get("title", "Recurring Task"),
                "description": task.get("description", ""),
                "priority": task.get("priority", "Medium"),
                "due_date": datetime.combine(today, datetime.min.time()),
                "start_date": datetime.combine(today, datetime.min.time()),
                "category": "Recurring",
                "notes": "",
                "assigned_to": assigned_to,
                "created_by": task.get("created_by"),
                "reward_points": task.get("reward_points", 50),
                "estimated_time": "",
                "status": "Pending",
                "is_deleted": False,
                "recurring_task_id": recurring_task_id,
                "generated_date": today.strftime("%Y-%m-%d"),
                "created_at": datetime.utcnow(),
                "attachment": None
            }

            result = mongo.db.tasks.insert_one(task_data)

            new_task_id = str(result.inserted_id)

            template_subtasks = list(
                mongo.db.sub_tasks.find({"recurring_task_id": recurring_task_id})
            )

            for sub in template_subtasks:
                mongo.db.sub_tasks.insert_one({
                    "task_id": new_task_id,
                    "title": sub.get("title", ""),
                    "status": "Pending",
                    "created_by": task.get("created_by"),
                    "created_at": datetime.utcnow()
                })

            mongo.db.recurring_tasks.update_one(
                {"_id": task["_id"]},
                {"$set": {"last_generated": datetime.utcnow()}}
            )

            print(f"Recurring task generated: {task.get('title')} for {user.get('username')}")

        return True