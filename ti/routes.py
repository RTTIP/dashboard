# ti/routes.py
import datetime
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask import request, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import Asset, AssetRisk, AssetMonitoring, AssetReport, User
from .extensions import db
import requests
from datetime import datetime, timezone, timedelta
import logging
from flask import jsonify, request
from flask_login import login_required
# from mongo_helper import MongoHelper
from bson import ObjectId
from .extensions import mongo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# mongo = PyMongo()

ASSET_API = "http://3.142.189.47:5000"
THREAT_API = "http://54.164.144.74:5000/api/v1/"
INCIDENT_API = "http://54.242.228.131:5002/api"
RISK_ASSESSMENT_API = "http://76.92.190.91:8000"
CRISIS_MANAGEMENT_API = "" ## Not deployed. Running locally. 
main = Blueprint('main', __name__)

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('main.login'))

        login_user(user, remember=remember)
        return redirect(url_for('main.dashboard'))

    return render_template('login.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    # if current_user.is_authenticated:
    #     return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('main.register'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('main.register'))
        
        new_user = User(username=username, 
                        email=email, 
                        password_hash=generate_password_hash(password, method='pbkdf2:sha256'))

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('main.login'))

    return render_template('register.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', name=current_user.username)

@main.route('/asset_management')
@login_required
def asset_management():
    return render_template('asset_management.html')

@main.route('/threat_intelligence')
@login_required
def threat_intelligence():
    return render_template('threat_intelligence.html')

@main.route('/vulnerability_risk_assessment')
@login_required
def vulnerability_risk_assessment():
    return render_template('vulnerability_risk_assessment.html')

@main.route('/incident_response')
@login_required
def incident_response():
    return render_template('incident_response.html')

@main.route('/incident_details/<int:id>')
@login_required
def incident_details(id):
    return render_template('incident_details.html', incident_id=id)

@main.route('/crisis_management', methods=['GET', 'POST'])
@login_required
def crisis_management():
    if request.method == 'POST':
        title = request.form.get('title')
        severity = request.form.get('severity')
        status = request.form.get('status')
        description = request.form.get('description')
        type_ = request.form.get('type')
        location = request.form.get('location')
        affected_assets = request.form.get('affected_assets').split(',')  # Assuming a comma-separated list
        resolution_time = request.form.get('resolution_time')

        # Create a new document (replace with your actual model logic)
        new_document = {
            'title': title,
            'severity': severity,
            'status': status,
            'description': description,
            'type': type_,
            'location': location,
            'affected_assets': affected_assets,
            'created_at': datetime.now(),
            'updated_at': datetime.now(),
            'resolution_time': resolution_time
        }

        
        # db.session.add(new_document)
        # db.session.commit()

        return redirect(url_for('main.crisis_management'))

    # Fetch existing documents to display in the table
    documents = []  # Replace with actual fetching logic
    return render_template('crisis_management.html', documents=documents)

@main.route('/api/incidents')
@login_required
def get_incidents():
    try:
        response = requests.get(f"{INCIDENT_API}/incidents")
        incidents = response.json()
        
        active_incidents = len([i for i in incidents if i['status'] == 'Open'])
        resolved_incidents = len([i for i in incidents if i['status'] == 'Resolved'])
        
        return {
            "active": active_incidents,
            "avgResponseTime": calculate_avg_response_time(incidents),
            "resolved": resolved_incidents,
            "trend": calculate_incident_trend(incidents),
            "incidents": [{
                "id": inc['incident_id'],
                "type": inc['type'],
                "severity": inc['severity'],
                "status": inc['status'],
                "reportedDate": inc['detected_at'],
                "lastUpdated": inc['resolved_at'] or inc['detected_at']
            } for inc in incidents if inc['type'] is not None]
        }
    except Exception as e:
        print(f"Error fetching incidents: {str(e)}")
        return jsonify({"error": str(e)}), 500

def calculate_avg_response_time(incidents):
    resolved_incidents = [i for i in incidents if i['resolved_at'] and i['detected_at']]
    if not resolved_incidents:
        return "0h"
    
    total_hours = 0
    count = 0
    
    for incident in resolved_incidents:
        detected = datetime.strptime(incident['detected_at'], "%a, %d %b %Y %H:%M:%S GMT")
        resolved = datetime.strptime(incident['resolved_at'], "%a, %d %b %Y %H:%M:%S GMT")
        delta = resolved - detected
        total_hours += delta.total_seconds() / 3600
        count += 1
    
    return f"{total_hours/count:.1f}h" if count > 0 else "0h"

def calculate_incident_trend(incidents):
    current_count = len([i for i in incidents if i['status'] == 'Open'])
    total_count = len(incidents)
    if total_count == 0:
        return "+0%"
    trend = (current_count / total_count) * 100
    return f"{'+' if trend >= 0 else ''}{trend:.1f}%"
        

@main.route('/api/incidents/<int:id>', methods=['PUT'])
@login_required
def update_incident(id):
    try:
        data = request.json
        response = requests.put(f"{INCIDENT_API}/incidents/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@main.route('/api/playbooks', methods=['GET', 'POST'])
@login_required
def playbooks():
    if request.method == 'GET':
        try:
            response = requests.get(f"{INCIDENT_API}/playbooks")
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            response = requests.post(f"{INCIDENT_API}/playbooks", json=data)
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@main.route('/api/recovery_actions', methods=['GET', 'POST'])
@login_required
def recovery_actions():
    if request.method == 'GET':
        try:
            response = requests.get(f"{INCIDENT_API}/recovery_actions")
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            response = requests.post(f"{INCIDENT_API}/recovery_actions", json=data)
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@main.route('/api/recovery_actions/<int:id>', methods=['PUT'])
@login_required
def update_recovery_action(id):
    try:
        data = request.json
        response = requests.put(f"{INCIDENT_API}/recovery_actions/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    




@main.route('/api/crisis_communications', methods=['GET', 'POST'])
@login_required
def crisis_communications():
    if request.method == 'GET':
        try:
            response = requests.get(f"{INCIDENT_API}/crisis_communications")
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            response = requests.post(f"{INCIDENT_API}/crisis_communications", json=data)
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@main.route('/api/crisis_communications/<int:id>', methods=['PUT'])
@login_required
def update_crisis_communication(id):
    try:
        data = request.json
        response = requests.put(f"{INCIDENT_API}/crisis_communications/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    



@main.route('/api/incident_logs', methods=['GET', 'POST'])
@login_required
def incident_logs():
    if request.method == 'GET':
        try:
            response = requests.get(f"{INCIDENT_API}/incident_logs")
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            response = requests.post(f"{INCIDENT_API}/incident_logs", json=data)
            return response.json(), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@main.route('/api/incident_logs/<int:id>', methods=['PUT'])
@login_required
def update_incident_log(id):
    try:
        data = request.json
        response = requests.put(f"{INCIDENT_API}/incident_logs/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@main.route('/api/incidents/<int:id>/recover', methods=['POST'])
@login_required
def recover_incident(id):
    try:
        response = requests.post(f"{INCIDENT_API}/incidents/{id}/recover")
        if response.status_code == 404:
            return jsonify({"error": "Incident not found"}), 404
        return response.json(), response.status_code
    except Exception as e:
        logger.error(f"Error recovering incident {id}: {str(e)}")
        return jsonify({"error": str(e)}), 500
    


def format_datetime(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%a, %d %b %Y %H:%M:%S GMT")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return dt_str

@main.route('/api/incidents/summary')
@login_required
def get_incident_summary():
    try:
        response = requests.get(f"{INCIDENT_API}/incidents")
        incidents = response.json()
        
        # Calculate summary statistics
        total = len(incidents)
        critical = len([i for i in incidents if i.get('severity', 0) >= 8])
        high = len([i for i in incidents if 6 <= i.get('severity', 0) < 8])
        medium = len([i for i in incidents if 4 <= i.get('severity', 0) < 6])
        low = len([i for i in incidents if i.get('severity', 0) < 4])
        
        return {
            "total": total,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "by_status": {
                "open": len([i for i in incidents if i.get('status') == 'Open']),
                "in_progress": len([i for i in incidents if i.get('status') == 'In Progress']),
                "resolved": len([i for i in incidents if i.get('status') == 'Resolved']),
                "closed": len([i for i in incidents if i.get('status') == 'Closed'])
            }
        }
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    



@main.route('/api/incidents/<int:id>/report')
@login_required
def generate_incident_report(id):
    try:
        # Fetch incident details
        incident_response = requests.get(f"{INCIDENT_API}/incidents/{id}")
        incident = incident_response.json()
        
        # Fetch related data
        playbook_response = requests.get(f"{INCIDENT_API}/playbooks?incident_id={id}")
        logs_response = requests.get(f"{INCIDENT_API}/incident_logs?incident_id={id}")
        recovery_response = requests.get(f"{INCIDENT_API}/recovery_actions?incident_id={id}")
        
        report = {
            "incident": incident,
            "playbook": playbook_response.json() if playbook_response.status_code == 200 else None,
            "logs": logs_response.json() if logs_response.status_code == 200 else [],
            "recovery_actions": recovery_response.json() if recovery_response.status_code == 200 else [],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    





################################################Routes for Asset Management#############################

# Add these new route handlers
@main.route('/api/assets/add', methods=['POST'])
@login_required
def add_asset():
    try:
        data = request.json
        response = requests.post(f"{ASSET_API}/addAssets", json={
            "name": data.get('name'),
            "type": data.get('type'),
            "value": data.get('value'),
            "criticality": data.get('criticality')
        })
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/risks/add', methods=['POST'])
@login_required
def add_asset_risk():
    try:
        data = request.json
        response = requests.post(f"{ASSET_API}/addAssetsRisks", json={
            "asset_id": data.get('asset_id'),
            "risk_score": data.get('risk_score'),
            "risk_description": data.get('risk_description'),
            "threat_level": data.get('threat_level')
        })
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/<int:id>', methods=['PUT'])
@login_required
def update_asset(id):
    try:
        data = request.json
        response = requests.put(f"{ASSET_API}/updateAsset/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/risks/<int:id>', methods=['PUT'])
@login_required
def update_asset_risk(id):
    try:
        data = request.json
        response = requests.put(f"{ASSET_API}/updateAssetRisk/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/<int:id>', methods=['DELETE'])
@login_required
def delete_asset(id):
    try:
        response = requests.delete(f"{ASSET_API}/deleteAsset/{id}")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/risks/<int:id>', methods=['DELETE'])
@login_required
def delete_asset_risk(id):
    try:
        response = requests.delete(f"{ASSET_API}/deleteAssetRisk/{id}")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets')
@login_required
def get_assets():
    try:
        response = requests.get(f"{ASSET_API}/GetAssets")
        assets = response.json()
        
        formatted_assets = []
        total = len(assets)
        healthy = warning = compromised = 0
        
        for asset in assets:
            status = calculate_asset_status(asset)
            formatted_asset = {
                "id": asset.get('asset_id'),  # Changed from 'id' to 'asset_id'
                "name": asset.get('name'),
                "type": asset.get('type'),
                "value": asset.get('value', 0),
                "criticality": asset.get('criticality', 'low'),
                "status": status,
                "risk_score": asset.get('risk_score', 0),
                "lastUpdated": asset.get('updated_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            }
            formatted_assets.append(formatted_asset)
            
            if status == 'Healthy':
                healthy += 1
            elif status == 'Warning':
                warning += 1
            else:
                compromised += 1
                
        return {
            "total": total,
            "healthy": healthy,
            "warning": warning,
            "compromised": compromised,
            "assets": formatted_assets
        }
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/<int:id>')
@login_required
def get_asset_by_id(id):
    try:
        if id is None:
            return jsonify({"error": "Asset ID is required"}), 400
            
        response = requests.get(f"{ASSET_API}/GetAssetById/{id}")
        if response.status_code == 404:
            return jsonify({"error": "Asset not found"}), 404
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/risks/<int:id>')
@login_required
def get_asset_risk_by_id(id):
    try:
        response = requests.get(f"{ASSET_API}/GetAssetRiskById/{id}")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/predict-impact', methods=['POST'])
@login_required
def predict_impact():
    try:
        data = request.json
        response = requests.post(f"{ASSET_API}/predict_impact", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/read-threat', methods=['POST'])
@login_required
def read_threat():
    try:
        data = request.json
        response = requests.post(f"{ASSET_API}/readThreat", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/reports/<int:id>')
@login_required
def generate_asset_report(id):
    try:
        response = requests.get(f"{ASSET_API}/generate_asset_report/{id}")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/assets/monitoring/start')
@login_required
def start_monitoring():
    try:
        response = requests.get(f"{ASSET_API}/initiate_monitoring")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def calculate_asset_status(asset):
    """Helper function to determine asset status based on risk score and criticality"""
    risk_score = float(asset.get('risk_score', 0))
    criticality = asset.get('criticality', 'low').lower()
    
    if criticality == 'high' and risk_score > 70:
        return 'Danger'
    elif risk_score > 50 or criticality == 'high':
        return 'Warning'
    else:
        return 'Healthy'
    



##################################################################Incident Routes#######################

@main.route('/api/incidents/<int:id>', methods=['GET'])
@login_required
def get_incident(id):
    try:
        response = requests.get(f"{INCIDENT_API}/incidents/{id}")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/playbooks', methods=['GET'])
@login_required
def get_playbooks():
    try:
        incident_id = request.args.get('incident_id')
        if incident_id:
            response = requests.get(f"{INCIDENT_API}/playbooks?incident_id={incident_id}")
        else:
            response = requests.get(f"{INCIDENT_API}/playbooks")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/playbooks', methods=['POST'])
@login_required
def create_playbook():
    try:
        data = request.json
        response = requests.post(f"{INCIDENT_API}/playbooks", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/playbooks/<int:id>', methods=['PUT'])
@login_required
def update_playbook(id):
    try:
        data = request.json
        response = requests.put(f"{INCIDENT_API}/playbooks/{id}", json=data)
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/recovery_actions', methods=['GET'])
@login_required
def get_recovery_actions():
    try:
        incident_id = request.args.get('incident_id')
        if incident_id:
            response = requests.get(f"{INCIDENT_API}/recovery_actions?incident_id={incident_id}")
        else:
            response = requests.get(f"{INCIDENT_API}/recovery_actions")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/crisis_communications', methods=['GET'])
@login_required
def get_crisis_communications():
    try:
        incident_id = request.args.get('incident_id')
        if incident_id:
            response = requests.get(f"{INCIDENT_API}/crisis_communications?incident_id={incident_id}")
        else:
            response = requests.get(f"{INCIDENT_API}/crisis_communications")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/incident_logs', methods=['GET'])
@login_required
def get_incident_logs():
    try:
        incident_id = request.args.get('incident_id')
        if incident_id:
            response = requests.get(f"{INCIDENT_API}/incident_logs?incident_id={incident_id}")
        else:
            response = requests.get(f"{INCIDENT_API}/incident_logs")
        return response.json(), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add error handling middleware
@main.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@main.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500



# Add request logging middleware
@main.before_request
def log_request_info():
    # logger.info('Headers: %s', request.headers)
    # logger.info('Body: %s', request.get_data())
    return None

# Add response logging middleware
@main.after_request
def log_response_info(response):
    logger.info('Response Status: %s', response.status)
    return response



################# Incidents ###########################

@main.route('/api/threats')
@login_required
def get_threats():
    try:
        # First get the list of all threats
        response = requests.get(f"{THREAT_API}/threats/")
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch threats"}), 500
            
        threats = response.json()
        
        # Fetch complete details for each threat
        formatted_threats = []
        for threat in threats:
            threat_id = threat.get('threat_id')
            if threat_id:
                # Get detailed information for each threat
                detail_response = requests.get(f"{THREAT_API}/threats/{threat_id}")
                if detail_response.status_code == 200:
                    threat_details = detail_response.json()
                    formatted_threat = {
                        "threat_id": threat_details.get('threat_id'),
                        "source": threat_details.get('source'),
                        "type": threat_details.get('type'),
                        "severity": threat_details.get('severity', 4),
                        "description": threat_details.get('description'),
                        "observed_date": threat_details.get('observed_date'),
                        "indicators": threat_details.get('indicators', [])
                    }
                    formatted_threats.append(formatted_threat)
        
        severities = [t.get('severity', 0) for t in formatted_threats]
        
        return {
            "critical": len([s for s in severities if s == 1]),
            "high": len([s for s in severities if s == 2]),
            "medium": len([s for s in severities if s == 3]),
            "low": len([s for s in severities if s == 4]),
            "threats": formatted_threats,
            "total": len(formatted_threats)
        }
    except Exception as e:
        print(f"Error fetching threats: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/threats/<string:threat_id>')
@login_required
def get_threat(threat_id):
    try:
        response = requests.get(f"{THREAT_API}/threats/{threat_id}")
        if response.status_code == 404:
            return jsonify({"error": "Threat not found"}), 404
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch threat"}), 500
        return response.json()
    except Exception as e:
        logger.error(f"Error fetching threat {threat_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/threats/ingest', methods=['POST'])
@login_required
def ingest_threat():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Validate required fields
        required_fields = ['threat_id', 'source', 'type', 'severity', 'description']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
            
        # Validate severity range
        if not 1 <= data['severity'] <= 4:
            return jsonify({"error": "Severity must be between 1 and 4"}), 400

        # Ensure observed_date is present and in correct format
        if 'observed_date' not in data:
            data['observed_date'] = datetime.now(timezone.utc).isoformat()

        # Ensure indicators is a list
        if 'indicators' in data and not isinstance(data['indicators'], list):
            return jsonify({"error": "Indicators must be a list"}), 400

        # Make request to the threat API
        response = requests.post(
            f"{THREAT_API}/threats/ingest",
            json=data,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 409:
            return jsonify({"error": "Threat ID already exists"}), 409
        elif response.status_code != 200 and response.status_code != 201:
            return jsonify({"error": "Failed to ingest threat"}), response.status_code

        return response.json(), response.status_code

    except Exception as e:
        logger.error(f"Error ingesting threat: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Add utility functions for logging and validation
def validate_threat_data(data):
    """Utility function to validate threat data"""
    errors = []
    
    # Check data type validations
    if not isinstance(data.get('threat_id', ''), str):
        errors.append("threat_id must be a string")
    
    if not isinstance(data.get('severity', 0), int):
        errors.append("severity must be an integer")
    
    if not isinstance(data.get('description', ''), str):
        errors.append("description must be a string")
        
    if data.get('indicators') is not None and not isinstance(data.get('indicators'), list):
        errors.append("indicators must be a list")
        
    # Check value validations
    if len(data.get('threat_id', '')) < 1:
        errors.append("threat_id cannot be empty")
        
    if not 1 <= data.get('severity', 0) <= 4:
        errors.append("severity must be between 1 and 4")
        
    if len(data.get('description', '')) < 10:
        errors.append("description must be at least 10 characters long")
        
    return errors

def format_threat_response(threat_data):
    """Utility function to format threat response data"""
    return {
        "threat_id": threat_data.get('threat_id'),
        "source": threat_data.get('source'),
        "type": threat_data.get('type'),
        "severity": threat_data.get('severity'),
        "description": threat_data.get('description'),
        "observed_date": threat_data.get('observed_date'),
        "indicators": threat_data.get('indicators', []),
        "created_at": threat_data.get('created_at', datetime.now(timezone.utc).isoformat()),
        "updated_at": threat_data.get('updated_at', datetime.now(timezone.utc).isoformat())
    }

# Add error handling decorator
def handle_threat_api_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.error(f"API Request Error: {str(e)}")
            return jsonify({"error": "Failed to communicate with threat API"}), 503
        except Exception as e:
            logger.error(f"Unexpected Error: {str(e)}")
            return jsonify({"error": "An unexpected error occurred"}), 500
    return decorated_function


@main.route('/api/local/assets')
@login_required
def get_local_assets():
    try:
        # Fetch from the risk assessment API
        response = requests.get(f"{RISK_ASSESSMENT_API}/assets")
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch assets"}), 500
            
        all_assets = response.json()
        
        # Filter assets with ID <= 32
        filtered_assets = [asset for asset in all_assets if asset.get('id', 0) <= 32]
        return jsonify(filtered_assets)
    except Exception as e:
        logger.error(f"Error getting assets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/local/assets', methods=['POST'])
@login_required
def add_local_asset():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Format the data according to the API requirements
        asset_data = {
            "name": data.get('name'),
            "model": data.get('model'),
            "version": data.get('version')
        }

        # Make request to add asset
        response = requests.post(
            f"{RISK_ASSESSMENT_API}/assets",
            json=asset_data,
            headers={'Content-Type': 'application/json'}
        )

        return response.json(), response.status_code
    except Exception as e:
        logger.error(f"Error adding asset: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/local/assets/<int:id>', methods=['GET'])
@login_required
def get_local_asset_by_id(id):
    try:
        if id > 32:
            return jsonify({"error": "Asset ID out of range"}), 404
            
        response = requests.get(f"{RISK_ASSESSMENT_API}/assets/{id}")
        if response.status_code == 404:
            return jsonify({"error": "Asset not found"}), 404
        return response.json(), response.status_code
    except Exception as e:
        logger.error(f"Error getting asset details: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/local/assets/<int:id>', methods=['DELETE'])
@login_required
def delete_local_asset(id):
    try:
        if id > 32:
            return jsonify({"error": "Asset ID out of range"}), 404
            
        response = requests.delete(f"{RISK_ASSESSMENT_API}/assets/{id}")
        return response.json(), response.status_code
    except Exception as e:
        logger.error(f"Error deleting asset: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/local/vulnerabilities')
@login_required
def get_local_vulnerabilities():
    try:
        # Fetch assets to get CVE data
        response = requests.get(f"{RISK_ASSESSMENT_API}/assets")
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch assets"}), 500
            
        all_assets = response.json()
        filtered_assets = [asset for asset in all_assets if asset.get('id', 0) <= 32]
        
        # Process vulnerabilities
        vulnerabilities = []
        
        for asset in filtered_assets:
            if asset.get('CVEs'):
                for cve in asset['CVEs']:
                    risk_score = asset.get('Risk Score', 0)
                    vulnerabilities.append({
                        "id": cve,
                        "name": cve,
                        "affectedAsset": asset['Asset Name'],
                        "riskLevel": get_risk_level(risk_score),
                        "cvssScore": risk_score,
                        "status": "Active",
                        "discoveryDate": datetime.now().strftime("%Y-%m-%d")
                    })
        
        # Calculate statistics
        stats = {
            "vulnerabilities": vulnerabilities,
            "critical": len([v for v in vulnerabilities if v['riskLevel'] == "Critical"]),
            "high": len([v for v in vulnerabilities if v['riskLevel'] == "High"]),
            "medium": len([v for v in vulnerabilities if v['riskLevel'] == "Medium"]),
            "low": len([v for v in vulnerabilities if v['riskLevel'] == "Low"])
        }
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/local/report/<int:asset_id>')
@login_required
def generate_local_report(asset_id):
    """Redirect to the PDF report generation website"""
    try:
        return redirect(f"http://76.92.190.91:8501?asset_id={asset_id}")
    except Exception as e:
        logger.error(f"Error redirecting to report generator: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Helper function to determine risk level
def get_risk_level(score):
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"








###################### Crisis Management ##############################

@main.route('/api/test-connection')
@login_required
def test_connection():
    try:
        # Test MongoDB connection
        info = mongo.db.command('serverStatus')
        return jsonify({
            "status": "success",
            "message": "Connected to MongoDB",
            "version": info.get('version', 'unknown')
        })
    except Exception as e:
        logger.error(f"MongoDB connection error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@main.route('/api/documents', methods=['GET'])
@login_required
def get_all_documents():
    try:
        # Add debug logging
        logger.info("Attempting to fetch documents from MongoDB")
        logger.info(f"MongoDB instance: {mongo}")
        logger.info(f"MongoDB database: {mongo.db}")
        
        # Fetch all documents from MongoDB
        documents = list(mongo.db.crisismanagement.find())
        logger.info(f"Found {len(documents)} documents")
        
        # Convert ObjectId to string for JSON serialization
        for doc in documents:
            doc['_id'] = str(doc['_id'])
            
        return jsonify(documents)
    except Exception as e:
        logger.error(f"Error fetching documents: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/documents/<string:id>', methods=['GET'])  
@login_required
def get_document(id):
    try:
        document = mongo.db.crisismanagement.find_one({'_id': ObjectId(id)})
        if not document:
            return jsonify({"error": "Document not found"}), 404
            
        document['_id'] = str(document['_id'])
        return jsonify(document)
    except Exception as e:
        logger.error(f"Error fetching document: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/documents/add', methods=['POST']) 
@login_required
def add_document():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate required fields
        required_fields = ['title', 'severity', 'status', 'description', 'type']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        # Validate severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if data['severity'].lower() not in valid_severities:
            return jsonify({"error": "Invalid severity level"}), 400

        # Validate status
        valid_statuses = ['active', 'resolved', 'archived']
        if data['status'].lower() not in valid_statuses:
            return jsonify({"error": "Invalid status"}), 400

        # Add timestamps
        data['created_at'] = datetime.now(timezone.utc)
        data['updated_at'] = datetime.now(timezone.utc)

        # Insert into MongoDB
        result = mongo.db.crisismanagement.insert_one(data)
        return jsonify({"message": "Document created", "id": str(result.inserted_id)}), 201

    except Exception as e:
        logger.error(f"Error adding document: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/documents/<string:id>', methods=['PUT'])
@login_required
def update_document(id):
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Add updated timestamp
        data['updated_at'] = datetime.now(timezone.utc)

        # Update document
        result = mongo.db.crisismanagement.update_one(
            {'_id': ObjectId(id)},
            {'$set': data}
        )

        if result.matched_count == 0:
            return jsonify({"error": "Document not found"}), 404

        return jsonify({"message": "Document updated successfully"})

    except Exception as e:
        logger.error(f"Error updating document: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/api/documents/<string:id>', methods=['DELETE'])  # Updated endpoint
@login_required
def delete_document(id):
    try:
        result = mongo.db.crisismanagement.delete_one({'_id': ObjectId(id)})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Document not found"}), 404
            
        return jsonify({"message": "Document deleted successfully"})
    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        return jsonify({"error": str(e)}), 500