from pymongo import MongoClient

uri = (
    "mongodb+srv://bka2bg:QcqSyZpNSyiH52cU@crisismanagement.vypxy.mongodb.net/Crisis_Management"
    "?retryWrites=true"
    "&w=majority"
    "&tls=true"
)

try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("MongoDB connection successful!")
except Exception as e:
    print(f"Error: {e}")
