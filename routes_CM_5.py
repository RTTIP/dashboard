from flask import jsonify, render_template, request, redirect
import requests

def register_routes(app, mongo):
    # Home route for displaying documents and adding new ones
    @app.route("/", methods=["GET", "POST"])
    def home():
        if request.method == "POST":
            # Get form data
            new_document = {
                "title": request.form.get("title"),
                "severity": request.form.get("severity"),
                "status": request.form.get("status"),
                "description": request.form.get("description"),
                "type": request.form.get("type"),
                "location": request.form.get("location"),
                "affected_assets": request.form.getlist("affected_assets"),
                "resolution_time": request.form.get("resolution_time")
            }
            # Send POST request to Flask API (using separate POST route for documents)
            response = requests.post("http://127.0.0.1:5000/api/documents/add", json=new_document)
            if response.status_code == 200:
                return redirect("/")
        
        # Fetch all documents from the collection
        documents = list(mongo.db.crisismanagement.find())
        
        # Convert ObjectId to string for JSON serialization
        for doc in documents:
            doc['_id'] = str(doc['_id'])
        
        return render_template('index.html', documents=documents)

    # API route to fetch all documents (GET)
    @app.route("/api/documents", methods=["GET"])
    def get_documents():
        documents = list(mongo.db.crisismanagement.find())
        
        # Convert ObjectId to string for JSON serialization
        for doc in documents:
            doc['_id'] = str(doc['_id'])
        
        return jsonify(documents)

    # API route to add new document (POST)
    
# Route for POST request to create a new document
    @app.route("/api/documents/add", methods=["POST"])
    def create_document():
        # Check if the request has JSON content
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        
        try:
            # Get the JSON data from the request
            data = request.get_json()

            # Validate if the necessary fields are present
            if not all(key in data for key in ["title", "severity", "status", "description", "type"]):
                return jsonify({"error": "Missing required fields"}), 400

            # Insert the document into MongoDB
            result = mongo.db.crisismanagement.insert_one(data)

            # Return the inserted document ID
            return jsonify({"id": str(result.inserted_id)}), 201
        except Exception as e:
            # Return error if anything goes wrong
            return jsonify({"error": str(e)}), 500