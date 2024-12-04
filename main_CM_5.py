from flask import Flask
from flask_pymongo import PyMongo
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from bson import ObjectId
from routes.routes import register_routes

# Initialize the Flask application
app = Flask(__name__)

# MongoDB connection details
app.config["MONGO_URI"] = "mongodb+srv://bka2bg:QcqSyZpNSyiH52cU@crisismanagement.vypxy.mongodb.net/Crisis_Management"
mongo = PyMongo(app)

# Initialize the transformer pipeline
model_name = "distilgpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)
transformer_pipeline = pipeline("text-generation", model=model, tokenizer=tokenizer)

# Register routes
register_routes(app, mongo)

if __name__ == "__main__":
    app.run(debug=True)