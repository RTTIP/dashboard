# websocket.py
from flask_socketio import SocketIO, emit
from . import socketio

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('incident_update')
def handle_incident_update(data):
    emit('incident_updated', data, broadcast=True)