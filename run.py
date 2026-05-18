from app import create_app, db

app = create_app()

with app.app_context():
    from app.models import User, Task
    db.create_all()

if __name__ == "__main__": 
    app.run(host="0.0.0.0", port=5000, debug=True)