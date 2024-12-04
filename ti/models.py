# ti/models.py
from .extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(64))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50))
    value = db.Column(db.Float)  # Added for asset value
    criticality = db.Column(db.String(50))  # Added for asset criticality
    location = db.Column(db.String(100))
    status = db.Column(db.String(50))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with AssetRisk
    risks = db.relationship('AssetRisk', backref='asset', lazy=True)

class AssetRisk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    risk_description = db.Column(db.Text)
    threat_level = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AssetMonitoring(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    description = db.Column(db.Text)
    severity_level = db.Column(db.String(50))
    incident_type = db.Column(db.String(100))
    duration = db.Column(db.Integer)
    impact_prediction = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AssetReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    report_data = db.Column(db.JSON)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.String(50), unique=True)
    source = db.Column(db.String(100))
    type = db.Column(db.String(50))
    severity = db.Column(db.Integer)
    description = db.Column(db.Text)
    observed_date = db.Column(db.DateTime)
    indicators = db.Column(db.JSON)