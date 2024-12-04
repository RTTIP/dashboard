# ti/app.py
import os
from flask import Flask
from .extensions import db, login_manager, mongo  # Import mongo from extensions
from .models import User

def create_app():
    app = Flask(__name__)
    
    # Basic configuration
    app.config['SECRET_KEY'] = '1234abcd'
    
    # Create the instance directory if it doesn't exist
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ti', 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # SQLite configuration
    db_path = os.path.join(instance_path, 'your_database.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # MongoDB configuration
    # app.config["MONGO_URI"] = "mongodb+srv://bka2bg:QcqSyZpNSyiH52cU@crisismanagement.vypxy.mongodb.net/Crisis_Management"
    app.config["MONGO_URI"] = (
        "mongodb+srv://bka2bg:QcqSyZpNSyiH52cU@crisismanagement.vypxy.mongodb.net/Crisis_Management"
        "?retryWrites=true"
        "&w=majority"
        "&tls=true"
    )



    # Initialize extensions
    db.init_app(app)
    mongo.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Import and register blueprints/routes here
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Create SQLite database tables
    with app.app_context():
        db.create_all()
        # Test MongoDB connection
        try:
            mongo.db.command('ping')
            print("MongoDB connection successful!")
        except Exception as e:
            print(f"MongoDB connection failed: {e}")

    return app