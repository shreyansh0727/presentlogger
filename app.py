from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_file
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import func
from models import db, Student, AttendanceLog, UnknownCard, AdminUser, SystemLog
from config import Config
import schedule
import time
import threading
from datetime import datetime, date, time as dt_time, timedelta
import pytz
import os
import csv
import io
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import json
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Initialize extensions
db.init_app(app)
CORS(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Timezone setup
IST = pytz.timezone('Asia/Kolkata')

# System start time for uptime calculation
system_start_time = datetime.now()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# API key authentication decorator
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or api_key != app.config.get('API_KEY', 'default-api-key'):
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

def create_tables():
    """Create database tables with error handling"""
    try:
        with app.app_context():
            # Ensure database directory exists
            db_path = app.config['SQLALCHEMY_DATABASE_URI']
            if 'sqlite:///' in db_path:
                db_file = db_path.replace('sqlite:///', '')
                db_dir = os.path.dirname(db_file)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir)
                    print(f"Created database directory: {db_dir}")
            
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Create default admin user
            create_default_admin()
            
            # Add sample data if tables are empty
            if Student.query.count() == 0:
                add_sample_students()
                
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        print("💡 Make sure the database directory exists and is writable")

def create_default_admin():
    """Create default admin user if none exists"""
    if not AdminUser.query.first():
        admin = AdminUser(
            username='admin',
            email='admin@school.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin user created (username: admin, password: admin123)")

def add_sample_students():
    """Add sample students for testing"""
    sample_students = [
        {
            'rfid_uid': '04:52:F4:2A',
            'reg_no': 'REG001',
            'name': 'John Doe',
            'class_name': '10A',
            'parent_email': 'parent1@example.com'
        },
        {
            'rfid_uid': '04:63:A5:3B',
            'reg_no': 'REG002', 
            'name': 'Jane Smith',
            'class_name': '10A',
            'parent_email': 'parent2@example.com'
        },
        {
            'rfid_uid': '04:A1:B2:C3',
            'reg_no': 'REG003',
            'name': 'Mike Johnson', 
            'class_name': '10B',
            'parent_email': 'parent3@example.com'
        },
        {
            'rfid_uid': '04:D4:E5:F6',
            'reg_no': 'REG004',
            'name': 'Sarah Wilson',
            'class_name': '10B', 
            'parent_email': 'parent4@example.com'
        }
    ]
    
    try:
        for data in sample_students:
            student = Student(**data)
            db.session.add(student)
        
        db.session.commit()
        print(f"✅ Added {len(sample_students)} sample students to database")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error adding sample students: {e}")

def log_system_activity(action, details, user_id=None):
    """Log system activities"""
    try:
        log = SystemLog(
            action=action,
            details=details,
            user_id=user_id,
            ip_address=request.remote_addr if request else None,
            timestamp=datetime.now(IST)
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")

def get_current_time():
    """Get current time in IST"""
    return datetime.now(IST).time()

def get_current_date():
    """Get current date in IST"""
    return datetime.now(IST).date()

def calculate_uptime():
    """Calculate system uptime"""
    uptime = datetime.now() - system_start_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m"

# API Routes

@app.route('/', methods=['GET'])
def index():
    """API Information"""
    return jsonify({
        'name': 'Enhanced Arduino RFID Attendance System API',
        'version': '2.0.0',
        'description': 'Advanced REST API for IoT-based student attendance tracking',
        'status': 'active',
        'database_status': 'connected',
        'features': [
            'Real-time updates',
            'Advanced analytics',
            'Bulk operations',
            'Enhanced security',
            'Mobile responsive UI'
        ],
        'endpoints': {
            'students': '/api/students',
            'attendance': '/api/attendance/log',
            'logs': '/api/logs',
            'dashboard': '/dashboard',
            'reports': '/api/reports/daily',
            'analytics': '/api/analytics/advanced',
            'login': '/login'
        },
        'arduino_integration': 'enabled',
        'timezone': 'Asia/Kolkata',
        'uptime': calculate_uptime()
    })

# Login system
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user = AdminUser.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            # Update last login
            user.last_login = datetime.now(IST)
            db.session.commit()
            
            log_system_activity('USER_LOGIN', f'User {username} logged in', user.id)
            
            if request.is_json:
                return jsonify({'success': True, 'redirect': '/dashboard'})
            else:
                return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            else:
                return render_template_string(login_template, error='Invalid credentials')
    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    return render_template_string(login_template)

@app.route('/logout')
def logout():
    """Logout user"""
    log_system_activity('USER_LOGOUT', f'User {session.get("username")} logged out', session.get('user_id'))
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Enhanced Admin Dashboard with advanced features"""
    dashboard_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enhanced Arduino RFID Attendance System</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            :root {
                --primary-color: #2196F3;
                --secondary-color: #1976D2;
                --success-color: #4CAF50;
                --warning-color: #ff9800;
                --danger-color: #f44336;
                --dark-bg: #1a1a1a;
                --dark-surface: #2d2d2d;
                --dark-text: #ffffff;
                --light-bg: #f8f9fa;
                --border-color: #e0e0e0;
            }
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
                transition: all 0.3s ease;
            }
            
            body.dark-mode {
                background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
                color: var(--dark-text);
            }
            
            .container { 
                max-width: 1400px; 
                margin: 0 auto; 
                background: white; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            
            .dark-mode .container {
                background: var(--dark-surface);
                color: var(--dark-text);
            }
            
            .header { 
                background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
                color: white; 
                padding: 25px; 
                text-align: center;
                position: relative;
            }
            
            .header h1 { font-size: 2.5em; margin-bottom: 10px; }
            .header p { font-size: 1.1em; opacity: 0.9; }
            
            .header-controls {
                position: absolute;
                top: 20px;
                right: 20px;
                display: flex;
                gap: 10px;
                align-items: center;
            }
            
            .theme-toggle, .logout-btn {
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                padding: 8px 12px;
                border-radius: 20px;
                cursor: pointer;
                font-size: 14px;
                text-decoration: none;
                display: inline-block;
                transition: background 0.3s;
            }
            
            .theme-toggle:hover, .logout-btn:hover {
                background: rgba(255,255,255,0.3);
            }
            
            .user-info {
                font-size: 12px;
                opacity: 0.8;
            }
            
            .live-indicator {
                display: inline-block;
                width: 10px;
                height: 10px;
                background: #4CAF50;
                border-radius: 50%;
                margin-left: 10px;
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
            
            .nav-tabs {
                display: flex;
                background: var(--light-bg);
                border-bottom: 1px solid var(--border-color);
                flex-wrap: wrap;
                overflow-x: auto;
            }
            
            .dark-mode .nav-tabs {
                background: #3a3a3a;
                border-bottom-color: #555;
            }
            
            .nav-tab {
                flex: 1;
                min-width: 120px;
                padding: 15px;
                text-align: center;
                background: var(--light-bg);
                border: none;
                cursor: pointer;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.3s;
                white-space: nowrap;
            }
            
            .dark-mode .nav-tab {
                background: #3a3a3a;
                color: var(--dark-text);
            }
            
            .nav-tab.active {
                background: white;
                border-bottom: 3px solid var(--primary-color);
                color: var(--primary-color);
            }
            
            .dark-mode .nav-tab.active {
                background: var(--dark-surface);
            }
            
            .nav-tab:hover {
                background: #e9ecef;
            }
            
            .dark-mode .nav-tab:hover {
                background: #4a4a4a;
            }
            
            .tab-content {
                display: none;
                padding: 30px;
                min-height: 500px;
            }
            
            .tab-content.active {
                display: block;
            }
            
            .card { 
                background: white; 
                padding: 25px; 
                margin: 20px 0; 
                border: 1px solid var(--border-color); 
                border-radius: 10px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }
            
            .dark-mode .card {
                background: #3a3a3a;
                border-color: #555;
                color: var(--dark-text);
            }
            
            .card h3 {
                margin-bottom: 15px;
                color: #333;
                font-size: 1.4em;
            }
            
            .dark-mode .card h3 {
                color: var(--dark-text);
            }
            
            .enhanced-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                text-align: center;
                border-left: 4px solid var(--primary-color);
                position: relative;
                overflow: hidden;
                transition: transform 0.3s ease;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }
            
            .dark-mode .stat-card {
                background: #3a3a3a;
                color: var(--dark-text);
            }
            
            .stat-number {
                font-size: 2.5em;
                font-weight: bold;
                color: var(--primary-color);
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .dark-mode .stat-label {
                color: #ccc;
            }
            
            .status { 
                display: inline-block; 
                padding: 6px 12px; 
                border-radius: 20px; 
                color: white; 
                font-size: 12px; 
                font-weight: 500;
            }
            
            .online { background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); }
            .offline { background: linear-gradient(135deg, #f44336 0%, #da190b 100%); }
            .warning { background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); }
            
            .real-time-updates {
                background: #f0f8ff;
                border: 1px solid var(--primary-color);
                border-radius: 8px;
                padding: 15px;
                margin: 20px 0;
                max-height: 200px;
                overflow-y: auto;
            }
            
            .dark-mode .real-time-updates {
                background: #2a2a3a;
                border-color: #4a4a5a;
            }
            
            .update-item {
                padding: 8px 0;
                border-bottom: 1px solid #eee;
                font-size: 14px;
            }
            
            .dark-mode .update-item {
                border-bottom-color: #555;
            }
            
            .update-item:last-child {
                border-bottom: none;
            }
            
            .chart-container {
                position: relative;
                height: 300px;
                margin: 20px 0;
                background: white;
                border-radius: 8px;
                padding: 15px;
            }
            
            .dark-mode .chart-container {
                background: #3a3a3a;
            }
            
            .advanced-filter {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
                padding: 20px;
                background: var(--light-bg);
                border-radius: 8px;
            }
            
            .dark-mode .advanced-filter {
                background: #3a3a3a;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
            }
            
            .dark-mode .form-group label {
                color: var(--dark-text);
            }
            
            .form-control {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid var(--border-color);
                border-radius: 8px;
                font-size: 14px;
                transition: border-color 0.3s;
                background: white;
            }
            
            .dark-mode .form-control {
                background: #4a4a4a;
                border-color: #555;
                color: var(--dark-text);
            }
            
            .form-control:focus {
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 3px rgba(33, 150, 243, 0.1);
            }
            
            .btn { 
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
                color: white; 
                padding: 12px 24px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer; 
                margin: 5px; 
                font-size: 14px;
                font-weight: 500;
                transition: all 0.3s;
                text-decoration: none;
                display: inline-block;
            }
            
            .btn:hover { 
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(33, 150, 243, 0.3);
            }
            
            .btn-sm {
                padding: 8px 16px;
                font-size: 12px;
                margin: 2px;
            }
            
            .btn-success {
                background: linear-gradient(135deg, var(--success-color) 0%, #45a049 100%);
            }
            
            .btn-warning {
                background: linear-gradient(135deg, var(--warning-color) 0%, #f57c00 100%);
            }
            
            .btn-danger {
                background: linear-gradient(135deg, var(--danger-color) 0%, #da190b 100%);
            }
            
            .btn-secondary {
                background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
            }
            
            .table-container {
                overflow-x: auto;
                margin-top: 20px;
            }
            
            table { 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 15px;
                background: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }
            
            .dark-mode table {
                background: #3a3a3a;
            }
            
            th, td { 
                padding: 15px 12px; 
                text-align: left; 
                border-bottom: 1px solid var(--border-color); 
            }
            
            .dark-mode th, .dark-mode td {
                border-bottom-color: #555;
            }
            
            th { 
                background: var(--light-bg);
                font-weight: 600;
                color: #333;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 1px;
            }
            
            .dark-mode th {
                background: #4a4a4a;
                color: var(--dark-text);
            }
            
            tr:hover {
                background: var(--light-bg);
            }
            
            .dark-mode tr:hover {
                background: #4a4a4a;
            }
            
            .alert {
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                display: none;
            }
            
            .alert-success {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }
            
            .alert-danger {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
            }
            
            .alert-info {
                background: #d1ecf1;
                border: 1px solid #bee5eb;
                color: #0c5460;
            }
            
            .loading {
                display: inline-block;
                margin-left: 10px;
            }
            
            .spinner {
                border: 2px solid #f3f3f3;
                border-top: 2px solid var(--primary-color);
                border-radius: 50%;
                width: 20px;
                height: 20px;
                animation: spin 1s linear infinite;
                display: inline-block;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            .grid-2 {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
            }
            
            .notification-badge {
                position: absolute;
                top: -5px;
                right: -5px;
                background: var(--danger-color);
                color: white;
                border-radius: 50%;
                width: 20px;
                height: 20px;
                font-size: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            /* Modal Styles */
            .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.5);
            }
            
            .modal-content {
                background-color: white;
                margin: 5% auto;
                padding: 30px;
                border-radius: 10px;
                width: 90%;
                max-width: 500px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }
            
            .dark-mode .modal-content {
                background-color: var(--dark-surface);
                color: var(--dark-text);
            }
            
            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid var(--border-color);
            }
            
            .dark-mode .modal-header {
                border-bottom-color: #555;
            }
            
            .modal-header h3 {
                margin: 0;
                color: #333;
            }
            
            .dark-mode .modal-header h3 {
                color: var(--dark-text);
            }
            
            .close {
                color: #aaa;
                float: right;
                font-size: 28px;
                font-weight: bold;
                cursor: pointer;
                background: none;
                border: none;
            }
            
            .close:hover {
                color: #000;
            }
            
            .dark-mode .close:hover {
                color: var(--dark-text);
            }
            
            /* Responsive Design */
            @media (max-width: 768px) {
                body {
                    padding: 10px;
                }
                
                .header-controls {
                    position: relative;
                    top: auto;
                    right: auto;
                    text-align: center;
                    margin-top: 15px;
                }
                
                .enhanced-stats {
                    grid-template-columns: 1fr;
                }
                
                .advanced-filter {
                    grid-template-columns: 1fr;
                }
                
                .grid-2 {
                    grid-template-columns: 1fr;
                }
                
                .nav-tabs {
                    flex-wrap: wrap;
                }
                
                .nav-tab {
                    min-width: 50%;
                }
                
                .modal-content {
                    width: 95%;
                    margin: 10% auto;
                    padding: 20px;
                }
                
                .tab-content {
                    padding: 15px;
                }
                
                .chart-container {
                    height: 250px;
                }
            }
            
            @media (max-width: 480px) {
                .header h1 {
                    font-size: 1.8em;
                }
                
                .stat-number {
                    font-size: 2em;
                }
                
                .nav-tab {
                    font-size: 12px;
                    padding: 12px 8px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="header-controls">
                    <div class="user-info">Welcome, {{ session.get('username', 'Admin') }}</div>
                    <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
                    <a href="/logout" class="logout-btn">🚪 Logout</a>
                </div>
                <h1>🎓 Enhanced RFID Attendance System</h1>
                <p>Advanced Student Attendance Management Dashboard
                    <span class="live-indicator" title="Live Updates Active"></span>
                </p>
            </div>
            
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('overview')">📊 Overview</button>
                <button class="nav-tab" onclick="showTab('students')">👥 Students</button>
                <button class="nav-tab" onclick="showTab('attendance')">📝 Attendance</button>
                <button class="nav-tab" onclick="showTab('analytics')">📈 Analytics</button>
                <button class="nav-tab" onclick="showTab('reports')">📋 Reports</button>
                <button class="nav-tab" onclick="showTab('notifications')">🔔 Alerts</button>
                <button class="nav-tab" onclick="showTab('system')">⚙️ System</button>
            </div>
            
            <!-- Enhanced Overview Tab -->
            <div id="overview" class="tab-content active">
                <div class="enhanced-stats">
                    <div class="stat-card">
                        <div class="stat-number" id="totalStudents">0</div>
                        <div class="stat-label">Total Students</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="presentToday">0</div>
                        <div class="stat-label">Present Today</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="absentToday">0</div>
                        <div class="stat-label">Absent Today</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="lateArrivals">0</div>
                        <div class="stat-label">Late Arrivals</div>
                        <div class="notification-badge" id="lateBadge" style="display: none;">!</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="attendanceRate">0%</div>
                        <div class="stat-label">Attendance Rate</div>
                    </div>
                </div>
                
                <div class="real-time-updates">
                    <h3>🔴 Live Updates</h3>
                    <div id="liveUpdates">
                        <div class="update-item">Waiting for attendance updates...</div>
                    </div>
                </div>
                
                <div class="chart-container">
                    <canvas id="attendanceChart"></canvas>
                </div>
                
                <div class="card">
                    <h3>📊 System Status</h3>
                    <p><strong>Server Status:</strong> <span class="status online">ONLINE</span></p>
                    <p><strong>Database:</strong> <span class="status online">CONNECTED</span></p>
                    <p><strong>Arduino Integration:</strong> <span class="status online">READY</span></p>
                    <p><strong>Last Updated:</strong> <span id="timestamp">Loading...</span></p>
                    <p><strong>System Uptime:</strong> <span id="systemUptime">Loading...</span></p>
                </div>
                
                <div class="card">
                    <h3>🔄 Quick Actions</h3>
                    <button class="btn" onclick="refreshDashboard()">🔄 Refresh Dashboard</button>
                    <button class="btn btn-success" onclick="showTab('students')">➕ Add Student</button>
                    <button class="btn btn-warning" onclick="sendAbsentAlerts()">📧 Send Absent Alerts</button>
                    <button class="btn btn-secondary" onclick="exportData()">📥 Export Data</button>
                </div>
            </div>
            
            <!-- Students Tab -->
            <div id="students" class="tab-content">
                <div class="grid-2">
                    <div class="card">
                        <h3>➕ Add New Student</h3>
                        <div class="alert alert-success" id="successAlert"></div>
                        <div class="alert alert-danger" id="errorAlert"></div>
                        
                        <form id="studentForm">
                            <div class="form-group">
                                <label for="rfidUid">RFID UID *</label>
                                <input type="text" class="form-control" id="rfidUid" placeholder="e.g., 04:52:F4:2A" required>
                                <small>Use the UID registration tool to get this value</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="regNo">Registration Number *</label>
                                <input type="text" class="form-control" id="regNo" placeholder="e.g., REG001" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="studentName">Full Name *</label>
                                <input type="text" class="form-control" id="studentName" placeholder="e.g., John Doe" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="className">Class *</label>
                                <input type="text" class="form-control" id="className" placeholder="e.g., 10A" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="parentEmail">Parent Email *</label>
                                <input type="email" class="form-control" id="parentEmail" placeholder="e.g., parent@email.com" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="parentPhone">Parent Phone (Optional)</label>
                                <input type="tel" class="form-control" id="parentPhone" placeholder="e.g., +91-9876543210">
                            </div>
                            
                            <button type="submit" class="btn btn-success">
                                ➕ Add Student
                                <span class="loading" id="addStudentLoading" style="display: none;">
                                    <div class="spinner"></div>
                                </span>
                            </button>
                            <button type="button" class="btn btn-secondary" onclick="clearForm()">🗑️ Clear Form</button>
                        </form>
                    </div>
                    
                    <div class="card">
                        <h3>👥 Registered Students</h3>
                        <div class="form-group">
                            <input type="text" class="form-control" id="studentSearch" placeholder="🔍 Search students..." onkeyup="filterStudents()">
                        </div>
                        <div class="table-container">
                            <table id="studentsTable">
                                <thead>
                                    <tr>
                                        <th>RFID UID</th>
                                        <th>Reg No</th>
                                        <th>Name</th>
                                        <th>Class</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td colspan="6" style="text-align: center; padding: 40px;">
                                            <div class="spinner"></div>
                                            Loading students...
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <button class="btn" onclick="loadStudents()" style="margin-top: 15px;">🔄 Refresh Students</button>
                        <button class="btn btn-warning" onclick="showImportModal()" style="margin-top: 15px;">📤 Import CSV</button>
                    </div>
                </div>
            </div>
            
            <!-- Attendance Tab -->
            <div id="attendance" class="tab-content">
                <div class="card">
                    <h3>📝 Recent Attendance Logs</h3>
                    <div class="advanced-filter">
                        <div class="form-group">
                            <label for="dateFilter">Filter by Date:</label>
                            <input type="date" class="form-control" id="dateFilter">
                        </div>
                        <div class="form-group">
                            <label for="classFilterAttendance">Filter by Class:</label>
                            <select class="form-control" id="classFilterAttendance">
                                <option value="">All Classes</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="actionFilter">Filter by Action:</label>
                            <select class="form-control" id="actionFilter">
                                <option value="">All Actions</option>
                                <option value="ENTRY">Entry</option>
                                <option value="EXIT">Exit</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>&nbsp;</label>
                            <button class="btn" onclick="loadAttendanceLogs()">🔍 Apply Filters</button>
                        </div>
                    </div>
                    
                    <div class="table-container">
                        <table id="attendanceTable">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Time</th>
                                    <th>Student Name</th>
                                    <th>Reg No</th>
                                    <th>Class</th>
                                    <th>Action</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="7" style="text-align: center; padding: 40px;">
                                        <div class="spinner"></div>
                                        Loading attendance logs...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Analytics Tab -->
            <div id="analytics" class="tab-content">
                <div class="advanced-filter">
                    <div class="form-group">
                        <label>Start Date:</label>
                        <input type="date" id="analyticsStartDate" class="form-control">
                    </div>
                    <div class="form-group">
                        <label>End Date:</label>
                        <input type="date" id="analyticsEndDate" class="form-control">
                    </div>
                    <div class="form-group">
                        <label>Class Filter:</label>
                        <select id="classFilterAnalytics" class="form-control">
                            <option value="">All Classes</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Analysis Type:</label>
                        <select id="analysisType" class="form-control">
                            <option value="daily">Daily Trends</option>
                            <option value="weekly">Weekly Summary</option>
                            <option value="monthly">Monthly Overview</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <button class="btn" onclick="generateAnalytics()">📊 Generate Analytics</button>
                    </div>
                </div>
                
                <div id="analyticsResults">
                    <div class="chart-container">
                        <canvas id="trendsChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="classComparisonChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- Reports Tab -->
            <div id="reports" class="tab-content">
                <div class="card">
                    <h3>📈 Daily Attendance Report</h3>
                    <div class="form-group">
                        <label for="reportDate">Select Date:</label>
                        <input type="date" class="form-control" id="reportDate" style="width: auto; display: inline-block;">
                        <button class="btn" onclick="generateDailyReport()" style="margin-left: 10px;">📊 Generate Report</button>
                        <button class="btn btn-success" onclick="downloadReport()" style="margin-left: 10px;">📥 Download PDF</button>
                    </div>
                    
                    <div id="reportContent">
                        <p style="text-align: center; padding: 40px; color: #666;">
                            Select a date and click "Generate Report" to view attendance data
                        </p>
                    </div>
                </div>
            </div>
            
            <!-- Notifications Tab -->
            <div id="notifications" class="tab-content">
                <div class="card">
                    <h3>🔔 Notification Settings</h3>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="emailNotifications" checked>
                            Email Notifications
                        </label>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="realTimeAlerts" checked>
                            Real-time Dashboard Alerts
                        </label>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="lateArrivalAlerts" checked>
                            Late Arrival Notifications
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="lateThreshold">Late Arrival Threshold (minutes after 9:00 AM):</label>
                        <input type="number" id="lateThreshold" value="15" class="form-control" min="0" max="120">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="dailyReports">
                            Daily Summary Reports
                        </label>
                    </div>
                    <button class="btn btn-success" onclick="saveNotificationSettings()">💾 Save Settings</button>
                </div>
                
                <div class="card">
                    <h3>📤 Manual Notifications</h3>
                    <div class="form-group">
                        <label for="notificationDate">Select Date for Absent Alerts:</label>
                        <input type="date" id="notificationDate" class="form-control" style="width: auto; display: inline-block;">
                        <button class="btn btn-warning" onclick="sendAbsentAlerts()" style="margin-left: 10px;">📧 Send Alerts</button>
                    </div>
                    
                    <div class="form-group">
                        <button class="btn btn-info" onclick="sendDailySummary()">📋 Send Daily Summary</button>
                        <button class="btn btn-secondary" onclick="viewNotificationHistory()">📜 View History</button>
                    </div>
                </div>
            </div>
            
            <!-- System Management Tab -->
            <div id="system" class="tab-content">
                <div class="grid-2">
                    <div class="card">
                        <h3>📊 System Statistics</h3>
                        <p><strong>Total Students:</strong> <span id="systemTotalStudents">-</span></p>
                        <p><strong>Total Records:</strong> <span id="totalRecords">-</span></p>
                        <p><strong>Database Size:</strong> <span id="dbSize">Calculating...</span></p>
                        <p><strong>System Uptime:</strong> <span id="systemUptimeDetails">-</span></p>
                        <p><strong>Last Backup:</strong> <span id="lastBackup">Never</span></p>
                        <p><strong>API Requests Today:</strong> <span id="apiRequests">-</span></p>
                    </div>
                    
                    <div class="card">
                        <h3>🔧 System Tools</h3>
                        <button class="btn btn-success" onclick="backupData()">💾 Create Backup</button>
                        <button class="btn btn-warning" onclick="showImportModal()">📤 Import Data</button>
                        <button class="btn btn-info" onclick="exportData()">📥 Export Excel</button>
                        <button class="btn btn-secondary" onclick="viewSystemLogs()">📋 System Logs</button>
                        <button class="btn btn-danger" onclick="clearOldLogs()">🗑️ Clear Old Logs</button>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🎯 API Configuration</h3>
                    <p><strong>Server IP:</strong> <span id="serverIP">Getting IP...</span></p>
                    <p><strong>API Endpoint:</strong> http://<span id="apiEndpoint">loading</span>:5000/api/</p>
                    <p><strong>API Key:</strong> <code id="apiKeyDisplay">••••••••••••••••</code> 
                        <button class="btn btn-sm" onclick="toggleApiKey()">👁️ Show/Hide</button>
                    </p>
                    
                    <div style="margin-top: 15px;">
                        <button class="btn btn-secondary" onclick="testConnection()">🧪 Test API</button>
                        <button class="btn btn-warning" onclick="regenerateApiKey()">🔄 Regenerate API Key</button>
                    </div>
                    
                    <div id="connectionResult" style="margin-top: 15px;"></div>
                </div>
            </div>
        </div>
        
        <!-- Edit Student Modal -->
        <div id="editModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>✏️ Edit Student</h3>
                    <button class="close" onclick="closeEditModal()">&times;</button>
                </div>
                
                <div class="alert alert-success" id="editSuccessAlert"></div>
                <div class="alert alert-danger" id="editErrorAlert"></div>
                
                <form id="editStudentForm">
                    <input type="hidden" id="editStudentId">
                    
                    <div class="form-group">
                        <label for="editRfidUid">RFID UID *</label>
                        <input type="text" class="form-control" id="editRfidUid" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="editRegNo">Registration Number *</label>
                        <input type="text" class="form-control" id="editRegNo" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="editStudentName">Full Name *</label>
                        <input type="text" class="form-control" id="editStudentName" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="editClassName">Class *</label>
                        <input type="text" class="form-control" id="editClassName" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="editParentEmail">Parent Email *</label>
                        <input type="email" class="form-control" id="editParentEmail" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="editParentPhone">Parent Phone (Optional)</label>
                        <input type="tel" class="form-control" id="editParentPhone">
                    </div>
                    
                    <div style="text-align: right; margin-top: 20px;">
                        <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
                        <button type="submit" class="btn btn-success">
                            💾 Save Changes
                            <span class="loading" id="editStudentLoading" style="display: none;">
                                <div class="spinner"></div>
                            </span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Delete Confirmation Modal -->
        <div id="deleteModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>🗑️ Delete Student</h3>
                    <button class="close" onclick="closeDeleteModal()">&times;</button>
                </div>
                
                <div style="padding: 20px 0;">
                    <p>Are you sure you want to delete this student?</p>
                    <p><strong>Name:</strong> <span id="deleteStudentName">-</span></p>
                    <p><strong>Registration:</strong> <span id="deleteStudentReg">-</span></p>
                    <p><strong>Class:</strong> <span id="deleteStudentClass">-</span></p>
                    <br>
                    <p style="color: var(--danger-color); font-weight: 500;">⚠️ This action cannot be undone. All attendance records for this student will remain in the system.</p>
                </div>
                
                <div style="text-align: right; margin-top: 20px;">
                    <button type="button" class="btn btn-secondary" onclick="closeDeleteModal()">Cancel</button>
                    <button type="button" class="btn btn-danger" onclick="confirmDelete()">
                        🗑️ Delete Student
                        <span class="loading" id="deleteStudentLoading" style="display: none;">
                            <div class="spinner"></div>
                        </span>
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Import CSV Modal -->
        <div id="importModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>📤 Import Students from CSV</h3>
                    <button class="close" onclick="closeImportModal()">&times;</button>
                </div>
                
                <div class="alert alert-info" style="display: block;">
                    <strong>CSV Format:</strong> rfid_uid, reg_no, name, class, parent_email, parent_phone<br>
                    <strong>Example:</strong> 04:52:F4:2A, REG001, John Doe, 10A, parent@email.com, +91-9876543210
                </div>
                
                <form id="csvImportForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="csvFile">CSV File:</label>
                        <input type="file" id="csvFile" accept=".csv" class="form-control" required>
                    </div>
                    
                    <div style="text-align: right; margin-top: 20px;">
                        <button type="button" class="btn btn-secondary" onclick="closeImportModal()">Cancel</button>
                        <button type="submit" class="btn btn-success">
                            📤 Import Students
                            <span class="loading" id="importLoading" style="display: none;">
                                <div class="spinner"></div>
                            </span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            // Global variables
            let socket;
            let students = [];
            let attendanceLogs = [];
            let currentEditStudentId = null;
            let currentDeleteStudentId = null;
            let attendanceChart;
            let trendsChart;
            let classComparisonChart;
            let apiKeyVisible = false;
            
            // Initialize enhanced dashboard
            document.addEventListener('DOMContentLoaded', function() {
                initializeSocket();
                initializeCharts();
                loadEnhancedDashboard();
                setTodayDate();
                getServerIP();
                loadSystemStats();
                
                // Update every 30 seconds
                setInterval(updateLiveStats, 30000);
                setInterval(updateTimestamp, 1000);
            });
            
            // Socket.IO for real-time updates
            function initializeSocket() {
                socket = io();
                
                socket.on('connect', function() {
                    console.log('Connected to server');
                    showNotification('Connected to live updates', 'success');
                });
                
                socket.on('attendance_update', function(data) {
                    updateLiveDisplay(data);
                    updateStatsRealTime();
                });
                
                socket.on('system_alert', function(data) {
                    showNotification(data.message, data.type);
                });
                
                socket.on('disconnect', function() {
                    console.log('Disconnected from server');
                    showNotification('Disconnected from live updates', 'warning');
                });
            }
            
            // Initialize charts
            function initializeCharts() {
                // Attendance Overview Chart
                const ctx1 = document.getElementById('attendanceChart').getContext('2d');
                attendanceChart = new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Daily Attendance Rate',
                            data: [],
                            borderColor: '#2196F3',
                            backgroundColor: 'rgba(33, 150, 243, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Attendance Trends (Last 7 Days)'
                            },
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100,
                                ticks: {
                                    callback: function(value) {
                                        return value + '%';
                                    }
                                }
                            }
                        }
                    }
                });
                
                // Trends Chart for Analytics
                const ctx2 = document.getElementById('trendsChart').getContext('2d');
                trendsChart = new Chart(ctx2, {
                    type: 'bar',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Present',
                            data: [],
                            backgroundColor: '#4CAF50'
                        }, {
                            label: 'Absent',
                            data: [],
                            backgroundColor: '#f44336'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Attendance Analytics'
                            }
                        }
                    }
                });
                
                // Class Comparison Chart
                const ctx3 = document.getElementById('classComparisonChart').getContext('2d');
                classComparisonChart = new Chart(ctx3, {
                    type: 'doughnut',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [
                                '#2196F3', '#4CAF50', '#ff9800', '#f44336', 
                                '#9c27b0', '#00bcd4', '#ffeb3b', '#795548'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Class-wise Attendance Distribution'
                            }
                        }
                    }
                });
            }
            
            // Dark mode toggle
            function toggleTheme() {
                document.body.classList.toggle('dark-mode');
                const isDark = document.body.classList.contains('dark-mode');
                localStorage.setItem('darkMode', isDark);
                
                // Update chart colors for dark mode
                updateChartTheme(isDark);
            }
            
            function updateChartTheme(isDark) {
                const textColor = isDark ? '#ffffff' : '#333333';
                const gridColor = isDark ? '#555555' : '#e0e0e0';
                
                const charts = [attendanceChart, trendsChart, classComparisonChart];
                charts.forEach(chart => {
                    if (chart) {
                        chart.options.plugins.title.color = textColor;
                        if (chart.options.scales) {
                            if (chart.options.scales.x) chart.options.scales.x.ticks.color = textColor;
                            if (chart.options.scales.y) chart.options.scales.y.ticks.color = textColor;
                            if (chart.options.scales.x) chart.options.scales.x.grid.color = gridColor;
                            if (chart.options.scales.y) chart.options.scales.y.grid.color = gridColor;
                        }
                        chart.update();
                    }
                });
            }
            
            // Load saved theme preference
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
            }
            
            // Enhanced tab switching
            function showTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Remove active from all nav tabs
                document.querySelectorAll('.nav-tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
                
                // Load tab-specific data
                switch(tabName) {
                    case 'students':
                        loadStudents();
                        loadClassOptions();
                        break;
                    case 'attendance':
                        loadAttendanceLogs();
                        loadClassOptions();
                        break;
                    case 'analytics':
                        loadAnalyticsData();
                        loadClassOptions();
                        break;
                    case 'system':
                        loadSystemStats();
                        break;
                    case 'overview':
                        loadEnhancedDashboard();
                        break;
                }
            }
            
            // Update timestamp
            // Simple fix - just update the existing function
function updateTimestamp() {
    const now = new Date();
    const timestampElement = document.getElementById('timestamp');
    const uptimeElement = document.getElementById('systemUptime');
    
    if (timestampElement) {
        timestampElement.textContent = now.toLocaleString();
    }
    
    if (uptimeElement) {
        if (!window.startTime) {
            window.startTime = new Date();
        }
        
        const elapsed = new Date() - window.startTime;
        const hours = Math.floor(elapsed / 3600000);
        const minutes = Math.floor((elapsed % 3600000) / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        
        uptimeElement.textContent = `${hours}h ${minutes}m ${seconds}s`;
    }
}

// Make sure this runs on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        updateTimestamp();
        setInterval(updateTimestamp, 1000);
    });
} else {
    updateTimestamp();
    setInterval(updateTimestamp, 1000);
}

            
            function getSystemUptime() {
                // This would normally come from the server
                const startTime = new Date(Date.now() - Math.random() * 86400000); // Simulated
                const uptime = Date.now() - startTime.getTime();
                const hours = Math.floor(uptime / 3600000);
                const minutes = Math.floor((uptime % 3600000) / 60000);
                return `${hours}h ${minutes}m`;
            }
            
            // Set today's date in date inputs
            function setTodayDate() {
                const today = new Date().toISOString().split('T')[0];
                const dateInputs = ['dateFilter', 'reportDate', 'notificationDate', 'analyticsEndDate'];
                dateInputs.forEach(id => {
                    const element = document.getElementById(id);
                    if (element) element.value = today;
                });
                
                // Set start date to 7 days ago for analytics
                const weekAgo = new Date();
                weekAgo.setDate(weekAgo.getDate() - 7);
                const startDate = document.getElementById('analyticsStartDate');
                if (startDate) startDate.value = weekAgo.toISOString().split('T')[0];
            }
            
            // Load enhanced dashboard data
            async function loadEnhancedDashboard() {
                try {
                    const [studentsRes, reportRes, weeklyRes] = await Promise.all([
                        fetch('/api/students'),
                        fetch('/api/reports/daily'),
                        fetch('/api/analytics/weekly-trend')
                    ]);
                    
                    const studentsData = await studentsRes.json();
                    const reportData = await reportRes.json();
                    
                    if (studentsData.success) {
                        document.getElementById('totalStudents').textContent = studentsData.count;
                        students = studentsData.students;
                    }
                    
                    if (reportData.success) {
                        document.getElementById('presentToday').textContent = reportData.summary.present_count;
                        document.getElementById('absentToday').textContent = reportData.summary.absent_count;
                        document.getElementById('attendanceRate').textContent = reportData.summary.attendance_rate + '%';
                        
                        // Update late arrivals
                        const lateCount = reportData.late_arrivals || 0;
                        document.getElementById('lateArrivals').textContent = lateCount;
                        const lateBadge = document.getElementById('lateBadge');
                        if (lateCount > 0) {
                            lateBadge.style.display = 'flex';
                            lateBadge.textContent = lateCount;
                        } else {
                            lateBadge.style.display = 'none';
                        }
                    }
                    
                    // Load chart data
                    loadAttendanceChart();
                    
                } catch (error) {
                    console.error('Error loading dashboard data:', error);
                    showNotification('Error loading dashboard data', 'error');
                }
            }
            
            // Load attendance chart data
            async function loadAttendanceChart() {
                try {
                    const response = await fetch('/api/analytics/weekly-trend');
                    const data = await response.json();
                    
                    if (data.success && attendanceChart) {
                        attendanceChart.data.labels = data.labels;
                        attendanceChart.data.datasets[0].data = data.attendance_rates;
                        attendanceChart.update();
                    }
                } catch (error) {
                    console.error('Error loading chart data:', error);
                }
            }
            
            // Real-time updates
            function updateLiveDisplay(data) {
                const liveUpdates = document.getElementById('liveUpdates');
                const timestamp = new Date().toLocaleTimeString();
                const statusIcon = data.action === 'ENTRY' ? '✅' : '🚪';
                const lateIcon = data.is_late ? '⏰' : '';
                
                const updateItem = document.createElement('div');
                updateItem.className = 'update-item';
                updateItem.innerHTML = `[${timestamp}] ${statusIcon} ${data.student_name} - ${data.action} ${lateIcon}`;
                
                liveUpdates.insertBefore(updateItem, liveUpdates.firstChild);
                
                // Keep only last 10 updates
                while (liveUpdates.children.length > 10) {
                    liveUpdates.removeChild(liveUpdates.lastChild);
                }
                
                // Show notification for late arrivals
                if (data.is_late) {
                    showNotification(`Late arrival: ${data.student_name}`, 'warning');
                }
            }
            
            function updateStatsRealTime() {
                // Refresh stats without full page reload
                loadEnhancedDashboard();
            }
            
            // Load students table
            async function loadStudents() {
                try {
                    const response = await fetch('/api/students');
                    const data = await response.json();
                    
                    if (data.success) {
                        students = data.students;
                        displayStudents();
                    }
                } catch (error) {
                    console.error('Error loading students:', error);
                    showNotification('Error loading students', 'error');
                }
            }
            
            // Display students in table
            function displayStudents(filteredStudents = null) {
                const tbody = document.querySelector('#studentsTable tbody');
                const studentsToShow = filteredStudents || students;
                
                if (studentsToShow.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No students found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = studentsToShow.map(student => `
                    <tr>
                        <td><code>${student.rfid_uid}</code></td>
                        <td>${student.reg_no}</td>
                        <td>${student.name}</td>
                        <td>${student.class}</td>
                        <td>
                            ${student.is_present ? 
                                '<span class="status online">PRESENT</span>' : 
                                '<span class="status offline">ABSENT</span>'
                            }
                        </td>
                        <td>
                            <button class="btn btn-warning btn-sm" onclick="editStudent(${student.id})">✏️ Edit</button>
                            <button class="btn btn-danger btn-sm" onclick="deleteStudent(${student.id})">🗑️ Delete</button>
                        </td>
                    </tr>
                `).join('');
            }
            
            // Filter students
            function filterStudents() {
                const searchTerm = document.getElementById('studentSearch').value.toLowerCase();
                const filtered = students.filter(student => 
                    student.name.toLowerCase().includes(searchTerm) ||
                    student.reg_no.toLowerCase().includes(searchTerm) ||
                    student.class.toLowerCase().includes(searchTerm)
                );
                displayStudents(filtered);
            }
            
            // Load class options for filters
            async function loadClassOptions() {
                try {
                    const response = await fetch('/api/classes');
                    const data = await response.json();
                    
                    if (data.success) {
                        const selects = ['classFilterAttendance', 'classFilterAnalytics'];
                        selects.forEach(selectId => {
                            const select = document.getElementById(selectId);
                            if (select) {
                                select.innerHTML = '<option value="">All Classes</option>';
                                data.classes.forEach(className => {
                                    select.innerHTML += `<option value="${className}">${className}</option>`;
                                });
                            }
                        });
                    }
                } catch (error) {
                    console.error('Error loading classes:', error);
                }
            }
            
            // Add student form submission
            document.getElementById('studentForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const loading = document.getElementById('addStudentLoading');
                const successAlert = document.getElementById('successAlert');
                const errorAlert = document.getElementById('errorAlert');
                
                hideAlerts();
                loading.style.display = 'inline-block';
                
                const studentData = {
                    rfid_uid: document.getElementById('rfidUid').value,
                    reg_no: document.getElementById('regNo').value,
                    name: document.getElementById('studentName').value,
                    class: document.getElementById('className').value,
                    parent_email: document.getElementById('parentEmail').value,
                    parent_phone: document.getElementById('parentPhone').value
                };
                
                try {
                    const response = await fetch('/api/students', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(studentData)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showAlert(successAlert, '✅ Student added successfully!');
                        document.getElementById('studentForm').reset();
                        loadStudents();
                        loadEnhancedDashboard();
                        showNotification('Student added successfully', 'success');
                    } else {
                        showAlert(errorAlert, '❌ Error: ' + result.error);
                    }
                } catch (error) {
                    showAlert(errorAlert, '❌ Network error: ' + error.message);
                } finally {
                    loading.style.display = 'none';
                }
            });
            
            // Edit student functionality
            function editStudent(studentId) {
                const student = students.find(s => s.id === studentId);
                if (!student) {
                    showNotification('Student not found', 'error');
                    return;
                }
                
                currentEditStudentId = studentId;
                
                // Populate edit form
                document.getElementById('editStudentId').value = studentId;
                document.getElementById('editRfidUid').value = student.rfid_uid;
                document.getElementById('editRegNo').value = student.reg_no;
                document.getElementById('editStudentName').value = student.name;
                document.getElementById('editClassName').value = student.class;
                document.getElementById('editParentEmail').value = student.parent_email;
                document.getElementById('editParentPhone').value = student.parent_phone || '';
                
                // Clear alerts
                hideModalAlerts();
                
                // Show modal
                document.getElementById('editModal').style.display = 'block';
            }
            
            // Edit student form submission
            document.getElementById('editStudentForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const loading = document.getElementById('editStudentLoading');
                const successAlert = document.getElementById('editSuccessAlert');
                const errorAlert = document.getElementById('editErrorAlert');
                
                hideModalAlerts();
                loading.style.display = 'inline-block';
                
                const studentData = {
                    rfid_uid: document.getElementById('editRfidUid').value,
                    reg_no: document.getElementById('editRegNo').value,
                    name: document.getElementById('editStudentName').value,
                    class: document.getElementById('editClassName').value,
                    parent_email: document.getElementById('editParentEmail').value,
                    parent_phone: document.getElementById('editParentPhone').value
                };
                
                try {
                    const response = await fetch(`/api/students/${currentEditStudentId}`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(studentData)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showAlert(successAlert, '✅ Student updated successfully!');
                        
                        setTimeout(() => {
                            closeEditModal();
                            loadStudents();
                            loadEnhancedDashboard();
                            showNotification('Student updated successfully', 'success');
                        }, 1000);
                    } else {
                        showAlert(errorAlert, '❌ Error: ' + result.error);
                    }
                } catch (error) {
                    showAlert(errorAlert, '❌ Network error: ' + error.message);
                } finally {
                    loading.style.display = 'none';
                }
            });
            
            // Delete student functionality
            function deleteStudent(studentId) {
                const student = students.find(s => s.id === studentId);
                if (!student) {
                    showNotification('Student not found', 'error');
                    return;
                }
                
                currentDeleteStudentId = studentId;
                
                // Populate delete modal with student info
                document.getElementById('deleteStudentName').textContent = student.name;
                document.getElementById('deleteStudentReg').textContent = student.reg_no;
                document.getElementById('deleteStudentClass').textContent = student.class;
                
                // Show modal
                document.getElementById('deleteModal').style.display = 'block';
            }
            
            // Confirm delete
            async function confirmDelete() {
                const loading = document.getElementById('deleteStudentLoading');
                loading.style.display = 'inline-block';
                
                try {
                    const response = await fetch(`/api/students/${currentDeleteStudentId}`, {
                        method: 'DELETE'
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification('Student deleted successfully', 'success');
                        closeDeleteModal();
                        loadStudents();
                        loadEnhancedDashboard();
                    } else {
                        showNotification('Error: ' + result.error, 'error');
                    }
                } catch (error) {
                    showNotification('Network error: ' + error.message, 'error');
                } finally {
                    loading.style.display = 'none';
                }
            }
            
            // Load attendance logs with enhanced filtering
            async function loadAttendanceLogs() {
                try {
                    const dateFilter = document.getElementById('dateFilter').value;
                    const classFilter = document.getElementById('classFilterAttendance').value;
                    const actionFilter = document.getElementById('actionFilter').value;
                    
                    let url = '/api/logs?limit=100';
                    if (dateFilter) url += `&date=${dateFilter}`;
                    if (classFilter) url += `&class=${classFilter}`;
                    if (actionFilter) url += `&action=${actionFilter}`;
                    
                    const response = await fetch(url);
                    const data = await response.json();
                    
                    if (data.success) {
                        displayAttendanceLogs(data.logs);
                    }
                } catch (error) {
                    console.error('Error loading attendance logs:', error);
                    showNotification('Error loading attendance logs', 'error');
                }
            }
            
            // Display attendance logs
            function displayAttendanceLogs(logs) {
                const tbody = document.querySelector('#attendanceTable tbody');
                
                if (logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px;">No attendance logs found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = logs.map(log => `
                    <tr>
                        <td>${log.date}</td>
                        <td>${log.timestamp}</td>
                        <td>${log.student_name}</td>
                        <td>${log.reg_no}</td>
                        <td>${log.class}</td>
                        <td>
                            <span class="status ${log.action === 'ENTRY' ? 'online' : log.action === 'EXIT' ? 'warning' : 'offline'}">
                                ${log.action}
                            </span>
                        </td>
                        <td>
                            ${log.is_late ? '<span class="status warning">LATE</span>' : '<span class="status online">ON TIME</span>'}
                        </td>
                    </tr>
                `).join('');
            }
            
            // Generate daily report
            async function generateDailyReport() {
                const reportDate = document.getElementById('reportDate').value;
                const reportContent = document.getElementById('reportContent');
                
                if (!reportDate) {
                    showNotification('Please select a date', 'warning');
                    return;
                }
                
                try {
                    reportContent.innerHTML = '<div style="text-align: center; padding: 40px;"><div class="spinner"></div> Generating report...</div>';
                    
                    const response = await fetch(`/api/reports/daily?date=${reportDate}`);
                    const data = await response.json();
                    
                    if (data.success) {
                        const summary = data.summary;
                        const present = data.present_students;
                        const absent = data.absent_students;
                        
                        reportContent.innerHTML = `
                            <div class="enhanced-stats" style="margin-bottom: 30px;">
                                <div class="stat-card">
                                    <div class="stat-number">${summary.total_students}</div>
                                    <div class="stat-label">Total Students</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-number">${summary.present_count}</div>
                                    <div class="stat-label">Present</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-number">${summary.absent_count}</div>
                                    <div class="stat-label">Absent</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-number">${summary.attendance_rate}%</div>
                                    <div class="stat-label">Attendance Rate</div>
                                </div>
                            </div>
                            
                            <div class="grid-2">
                                <div>
                                    <h4 style="color: var(--success-color); margin-bottom: 15px;">✅ Present Students (${present.length})</h4>
                                    ${present.length > 0 ? `
                                        <div class="table-container">
                                            <table style="font-size: 14px;">
                                                <thead>
                                                    <tr><th>Name</th><th>Class</th><th>Entry</th><th>Exit</th></tr>
                                                </thead>
                                                <tbody>
                                                    ${present.map(p => `
                                                        <tr>
                                                            <td>${p.student.name}</td>
                                                            <td>${p.student.class}</td>
                                                            <td>${p.entry_time || 'N/A'}</td>
                                                            <td>${p.exit_time || 'Still present'}</td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    ` : '<p>No students were present on this date.</p>'}
                                </div>
                                
                                <div>
                                    <h4 style="color: var(--danger-color); margin-bottom: 15px;">❌ Absent Students (${absent.length})</h4>
                                    ${absent.length > 0 ? `
                                        <div class="table-container">
                                            <table style="font-size: 14px;">
                                                <thead>
                                                    <tr><th>Name</th><th>Class</th><th>Reg No</th></tr>
                                                </thead>
                                                <tbody>
                                                    ${absent.map(a => `
                                                        <tr>
                                                            <td>${a.name}</td>
                                                            <td>${a.class}</td>
                                                            <td>${a.reg_no}</td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    ` : '<p>All students were present on this date! 🎉</p>'}
                                </div>
                            </div>
                        `;
                    }
                } catch (error) {
                    reportContent.innerHTML = '<p style="color: var(--danger-color); text-align: center;">Error generating report: ' + error.message + '</p>';
                }
            }
            
            // CSV Import functionality
            document.getElementById('csvImportForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const loading = document.getElementById('importLoading');
                const fileInput = document.getElementById('csvFile');
                
                if (!fileInput.files[0]) {
                    showNotification('Please select a CSV file', 'warning');
                    return;
                }
                
                loading.style.display = 'inline-block';
                
                const formData = new FormData();
                formData.append('csv_file', fileInput.files[0]);
                
                try {
                    const response = await fetch('/api/students/import-csv', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification(`✅ ${result.message}`, 'success');
                        closeImportModal();
                        loadStudents();
                        loadEnhancedDashboard();
                    } else {
                        showNotification(`❌ ${result.error}`, 'error');
                    }
                } catch (error) {
                    showNotification('❌ Error importing CSV: ' + error.message, 'error');
                } finally {
                    loading.style.display = 'none';
                }
            });
            
            // System management functions
            async function loadSystemStats() {
                try {
                    const response = await fetch('/api/system/stats');
                    const data = await response.json();
                    
                    if (data.success) {
                        document.getElementById('systemTotalStudents').textContent = data.total_students;
                        document.getElementById('totalRecords').textContent = data.total_records;
                        document.getElementById('dbSize').textContent = data.db_size;
                        document.getElementById('systemUptimeDetails').textContent = data.uptime;
                        document.getElementById('apiRequests').textContent = data.api_requests_today;
                        
                        if (data.last_backup) {
                            document.getElementById('lastBackup').textContent = new Date(data.last_backup).toLocaleString();
                        }
                    }
                } catch (error) {
                    console.error('Error loading system stats:', error);
                }
            }
            
            // Backup data
            async function backupData() {
                try {
                    const response = await fetch('/api/system/backup', { method: 'POST' });
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification('✅ Backup created successfully!', 'success');
                        document.getElementById('lastBackup').textContent = new Date().toLocaleString();
                    } else {
                        showNotification('❌ Backup failed: ' + result.error, 'error');
                    }
                } catch (error) {
                    showNotification('❌ Backup failed: ' + error.message, 'error');
                }
            }
            
            // Export data to Excel
            function exportData() {
                window.open('/api/reports/export-excel', '_blank');
                showNotification('Exporting data to Excel...', 'info');
            }
            
            // API Key management
            function toggleApiKey() {
                const display = document.getElementById('apiKeyDisplay');
                const button = event.target;
                
                if (apiKeyVisible) {
                    display.textContent = '••••••••••••••••';
                    button.textContent = '👁️ Show';
                    apiKeyVisible = false;
                } else {
                    // In a real implementation, you'd fetch this from the server
                    display.textContent = 'your-api-key-here';
                    button.textContent = '🙈 Hide';
                    apiKeyVisible = true;
                }
            }
            
            async function regenerateApiKey() {
                if (!confirm('Are you sure you want to regenerate the API key? This will invalidate the current key.')) {
                    return;
                }
                
                try {
                    const response = await fetch('/api/system/regenerate-api-key', { method: 'POST' });
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification('API key regenerated successfully', 'success');
                        document.getElementById('apiKeyDisplay').textContent = '••••••••••••••••';
                        apiKeyVisible = false;
                    }
                } catch (error) {
                    showNotification('Error regenerating API key', 'error');
                }
            }
            
            // Test API connection
            async function testConnection() {
                const resultDiv = document.getElementById('connectionResult');
                try {
                    resultDiv.innerHTML = '<div class="spinner"></div> Testing connection...';
                    const response = await fetch('/');
                    const data = await response.json();
                    
                    if (data.status === 'active') {
                        resultDiv.innerHTML = '<div class="alert alert-success" style="display: block;">✅ API connection successful!</div>';
                    } else {
                        resultDiv.innerHTML = '<div class="alert alert-danger" style="display: block;">❌ API connection failed</div>';
                    }
                } catch (error) {
                    resultDiv.innerHTML = '<div class="alert alert-danger" style="display: block;">❌ Connection error: ' + error.message + '</div>';
                }
            }
            
            // Get server IP
            async function getServerIP() {
                try {
                    const ip = window.location.hostname;
                    document.getElementById('serverIP').textContent = ip;
                    document.getElementById('apiEndpoint').textContent = ip;
                } catch (error) {
                    console.error('Error getting IP:', error);
                }
            }
            
            // Notification functions
            async function sendAbsentAlerts() {
                const notificationDate = document.getElementById('notificationDate').value || new Date().toISOString().split('T')[0];
                
                try {
                    const response = await fetch('/api/notifications/send-absent-alerts', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ date: notificationDate })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification(`✅ ${result.message}`, 'success');
                    } else {
                        showNotification(`❌ Error: ${result.error}`, 'error');
                    }
                } catch (error) {
                    showNotification('❌ Error sending alerts: ' + error.message, 'error');
                }
            }
            
            function saveNotificationSettings() {
                const settings = {
                    email: document.getElementById('emailNotifications').checked,
                    realTime: document.getElementById('realTimeAlerts').checked,
                    lateArrival: document.getElementById('lateArrivalAlerts').checked,
                    lateThreshold: document.getElementById('lateThreshold').value,
                    dailyReports: document.getElementById('dailyReports').checked
                };
                
                localStorage.setItem('notificationSettings', JSON.stringify(settings));
                showNotification('Notification settings saved', 'success');
            }
            
            // Load notification settings
            function loadNotificationSettings() {
                const saved = localStorage.getItem('notificationSettings');
                if (saved) {
                    const settings = JSON.parse(saved);
                    document.getElementById('emailNotifications').checked = settings.email !== false;
                    document.getElementById('realTimeAlerts').checked = settings.realTime !== false;
                    document.getElementById('lateArrivalAlerts').checked = settings.lateArrival !== false;
                    document.getElementById('lateThreshold').value = settings.lateThreshold || 15;
                    document.getElementById('dailyReports').checked = settings.dailyReports || false;
                }
            }
            
            // Analytics functions
            async function generateAnalytics() {
                const startDate = document.getElementById('analyticsStartDate').value;
                const endDate = document.getElementById('analyticsEndDate').value;
                const classFilter = document.getElementById('classFilterAnalytics').value;
                const analysisType = document.getElementById('analysisType').value;
                
                if (!startDate || !endDate) {
                    showNotification('Please select start and end dates', 'warning');
                    return;
                }
                
                try {
                    const response = await fetch(`/api/analytics/advanced?start=${startDate}&end=${endDate}&class=${classFilter}&type=${analysisType}`);
                    const data = await response.json();
                    
                    if (data.success) {
                        updateAnalyticsCharts(data);
                        showNotification('Analytics generated successfully', 'success');
                    }
                } catch (error) {
                    console.error('Error generating analytics:', error);
                    showNotification('Error generating analytics', 'error');
                }
            }
            
            function updateAnalyticsCharts(data) {
                // Update trends chart
                if (trendsChart && data.trends) {
                    trendsChart.data.labels = data.trends.labels;
                    trendsChart.data.datasets[0].data = data.trends.present;
                    trendsChart.data.datasets[1].data = data.trends.absent;
                    trendsChart.update();
                }
                
                // Update class comparison chart
                if (classComparisonChart && data.class_comparison) {
                    classComparisonChart.data.labels = data.class_comparison.labels;
                    classComparisonChart.data.datasets[0].data = data.class_comparison.data;
                    classComparisonChart.update();
                }
            }
            
            // Utility functions
            function refreshDashboard() {
                loadEnhancedDashboard();
                showNotification('Dashboard refreshed', 'info');
            }
            
            function clearForm() {
                document.getElementById('studentForm').reset();
                hideAlerts();
            }
            
            function hideAlerts() {
                document.getElementById('successAlert').style.display = 'none';
                document.getElementById('errorAlert').style.display = 'none';
            }
            
            function hideModalAlerts() {
                document.getElementById('editSuccessAlert').style.display = 'none';
                document.getElementById('editErrorAlert').style.display = 'none';
            }
            
            function showAlert(element, message) {
                element.textContent = message;
                element.style.display = 'block';
            }
            
            // Modal control functions
            function closeEditModal() {
                document.getElementById('editModal').style.display = 'none';
                currentEditStudentId = null;
            }
            
            function closeDeleteModal() {
                document.getElementById('deleteModal').style.display = 'none';
                currentDeleteStudentId = null;
            }
            
            function showImportModal() {
                document.getElementById('importModal').style.display = 'block';
            }
            
            function closeImportModal() {
                document.getElementById('importModal').style.display = 'none';
                document.getElementById('csvImportForm').reset();
            }
            
            // Close modals when clicking outside
            window.onclick = function(event) {
                const modals = ['editModal', 'deleteModal', 'importModal'];
                modals.forEach(modalId => {
                    const modal = document.getElementById(modalId);
                    if (event.target === modal) {
                        modal.style.display = 'none';
                    }
                });
            }
            
            // Show notification function
            function showNotification(message, type = 'info') {
                const notification = document.createElement('div');
                notification.className = `notification ${type}`;
                notification.textContent = message;
                notification.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    padding: 15px 20px;
                    border-radius: 8px;
                    color: white;
                    z-index: 10000;
                    font-weight: 500;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    animation: slideIn 0.3s ease;
                    max-width: 300px;
                    background: ${type === 'success' ? '#4CAF50' : 
                               type === 'error' ? '#f44336' : 
                               type === 'warning' ? '#ff9800' : '#2196F3'};
                `;
                
                document.body.appendChild(notification);
                
                setTimeout(() => {
                    notification.style.animation = 'slideOut 0.3s ease';
                    setTimeout(() => notification.remove(), 300);
                }, 4000);
            }
            
            // CSS animation for notifications
            const style = document.createElement('style');
            style.textContent = `
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes slideOut {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(100%); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
            
            // Initialize notification settings on load
            loadNotificationSettings();
        </script>
    </body>
    </html>
    """
    return render_template_string(dashboard_html)

# Enhanced API Endpoints

@app.route('/api/students', methods=['GET', 'POST'])
@login_required
def manage_students():
    """Manage students - GET all or POST new student"""
    
    if request.method == 'GET':
        try:
            students = Student.query.all()
            return jsonify({
                'success': True,
                'count': len(students),
                'students': [student.to_dict() for student in students]
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Database error: {str(e)}'
            }), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['rfid_uid', 'reg_no', 'name', 'class', 'parent_email']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        'success': False,
                        'error': f'Missing required field: {field}'
                    }), 400
            
            # Check if RFID UID already exists
            existing_student = Student.query.filter_by(rfid_uid=data['rfid_uid']).first()
            if existing_student:
                return jsonify({
                    'success': False,
                    'error': 'RFID UID already registered'
                }), 400
            
            # Check if registration number already exists
            existing_reg = Student.query.filter_by(reg_no=data['reg_no']).first()
            if existing_reg:
                return jsonify({
                    'success': False,
                    'error': 'Registration number already exists'
                }), 400
            
            # Create new student
            student = Student(
                rfid_uid=data['rfid_uid'],
                reg_no=data['reg_no'],
                name=data['name'],
                class_name=data['class'],
                parent_email=data['parent_email'],
                parent_phone=data.get('parent_phone')
            )
            
            db.session.add(student)
            db.session.commit()
            
            log_system_activity(
                'STUDENT_ADDED',
                f'Added student: {student.name} (ID: {student.id})',
                session.get('user_id')
            )
            
            return jsonify({
                'success': True,
                'message': 'Student registered successfully',
                'student': student.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': f'Error creating student: {str(e)}'
            }), 400

@app.route('/api/students/<int:student_id>', methods=['PUT'])
@login_required
def update_student(student_id):
    """Update student information"""
    try:
        data = request.get_json()
        student = Student.query.get(student_id)
        
        if not student:
            return jsonify({
                'success': False,
                'error': 'Student not found'
            }), 404
        
        # Check if new RFID UID conflicts with another student
        if 'rfid_uid' in data and data['rfid_uid'] != student.rfid_uid:
            existing_student = Student.query.filter_by(rfid_uid=data['rfid_uid']).first()
            if existing_student:
                return jsonify({
                    'success': False,
                    'error': 'RFID UID already registered to another student'
                }), 400
        
        # Check if new registration number conflicts
        if 'reg_no' in data and data['reg_no'] != student.reg_no:
            existing_reg = Student.query.filter_by(reg_no=data['reg_no']).first()
            if existing_reg:
                return jsonify({
                    'success': False,
                    'error': 'Registration number already exists'
                }), 400
        
        # Update student fields
        old_data = student.to_dict()
        
        if 'rfid_uid' in data:
            student.rfid_uid = data['rfid_uid']
        if 'reg_no' in data:
            student.reg_no = data['reg_no']
        if 'name' in data:
            student.name = data['name']
        if 'class' in data:
            student.class_name = data['class']
        if 'parent_email' in data:
            student.parent_email = data['parent_email']
        if 'parent_phone' in data:
            student.parent_phone = data['parent_phone']
        
        student.last_updated = datetime.utcnow()
        db.session.commit()
        
        log_system_activity(
            'STUDENT_UPDATED',
            f'Updated student: {student.name} (ID: {student_id})',
            session.get('user_id')
        )
        
        print(f"✅ Student updated: {student.name} (ID: {student_id})")
        
        return jsonify({
            'success': True,
            'message': 'Student updated successfully',
            'student': student.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error updating student: {e}")
        return jsonify({
            'success': False,
            'error': f'Error updating student: {str(e)}'
        }), 400

@app.route('/api/students/<int:student_id>', methods=['DELETE'])
@login_required
def delete_student(student_id):
    """Delete student from system"""
    try:
        student = Student.query.get(student_id)
        
        if not student:
            return jsonify({
                'success': False,
                'error': 'Student not found'
            }), 404
        
        student_name = student.name
        student_reg = student.reg_no
        
        # Delete the student (attendance logs will remain for historical records)
        db.session.delete(student)
        db.session.commit()
        
        log_system_activity(
            'STUDENT_DELETED',
            f'Deleted student: {student_name} (Reg: {student_reg})',
            session.get('user_id')
        )
        
        print(f"✅ Student deleted: {student_name} (Reg: {student_reg})")
        
        return jsonify({
            'success': True,
            'message': f'Student {student_name} deleted successfully',
            'deleted_student': {
                'name': student_name,
                'reg_no': student_reg
            }
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error deleting student: {e}")
        return jsonify({
            'success': False,
            'error': f'Error deleting student: {str(e)}'
        }), 400

@app.route('/api/student', methods=['GET'])
@api_key_required
def get_student_by_uid():
    """Get student information by RFID UID - for Arduino"""
    uid = request.args.get('uid')
    if not uid:
        return jsonify({
            'success': False,
            'error': 'UID parameter required'
        }), 400
    
    try:
        student = Student.query.filter_by(rfid_uid=uid).first()
        
        if student:
            return jsonify({
                'found': True,
                'reg_no': student.reg_no,
                'name': student.name,
                'class': student.class_name,
                'parent_email': student.parent_email,
                'is_present': student.is_present,
                'entry_time': student.entry_time.strftime('%H:%M:%S') if student.entry_time else None,
                'exit_time': student.exit_time.strftime('%H:%M:%S') if student.exit_time else None
            })
        else:
            return jsonify({
                'found': False,
                'message': 'Student not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Database error: {str(e)}'
        }), 500

@app.route('/api/attendance/log', methods=['POST'])
@api_key_required
def enhanced_log_attendance():
    """Enhanced attendance logging with real-time updates and late detection"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['rfid_uid', 'reg_no', 'name', 'class', 'action', 'timestamp', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Parse time and date
        timestamp = datetime.strptime(data['timestamp'], '%H:%M:%S').time()
        attendance_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        # Check for late arrival (after 9:15 AM)
        school_start_time = dt_time(9, 15)  # 9:15 AM
        is_late = timestamp > school_start_time and data['action'] == 'ENTRY'
        
        # Create attendance log
        log = AttendanceLog(
            rfid_uid=data['rfid_uid'],
            reg_no=data['reg_no'],
            student_name=data['name'],
            class_name=data['class'],
            action=data['action'],
            timestamp=timestamp,
            date=attendance_date,
            is_late=is_late
        )
        
        db.session.add(log)
        
        # Update student status
        student = Student.query.filter_by(rfid_uid=data['rfid_uid']).first()
        if student:
            if data['action'] == 'ENTRY':
                student.is_present = True
                student.entry_time = timestamp
                student.exit_time = None
                
                # Send notifications for late arrival
                if is_late:
                    try:
                        msg = Message(
                            subject=f'Late Arrival Alert - {student.name}',
                            recipients=[student.parent_email],
                            body=f"""Dear Parent,

This is to inform you that your child {student.name} (Registration: {student.reg_no}) from class {student.class_name} arrived late at school today at {timestamp.strftime('%H:%M')}.

School starts at 9:00 AM, and your child arrived at {timestamp.strftime('%H:%M')}.

If there was an emergency or valid reason for the late arrival, please contact the school administration.

Best regards,
School Administration
Enhanced RFID Attendance System"""
                        )
                        mail.send(msg)
                        print(f"📧 Late arrival email sent to {student.parent_email}")
                    except Exception as e:
                        print(f"❌ Email notification error: {e}")
                
            elif data['action'] == 'EXIT':
                student.is_present = False
                student.exit_time = timestamp
            
            student.last_updated = datetime.utcnow()
        
        db.session.commit()
        
        # Emit real-time update via WebSocket
        socketio.emit('attendance_update', {
            'student_name': data['name'],
            'action': data['action'],
            'timestamp': data['timestamp'],
            'is_late': is_late,
            'class': data['class']
        })
        
        # Log system activity
        log_system_activity(
            'ATTENDANCE_LOGGED',
            f'Attendance logged: {data["name"]} - {data["action"]} at {data["timestamp"]}' + (' (LATE)' if is_late else ''),
            None  # Arduino doesn't have user session
        )
        
        print(f"✅ Enhanced attendance logged: {data['name']} - {data['action']} at {data['timestamp']}" + (" (LATE)" if is_late else ""))
        
        return jsonify({
            'success': True,
            'message': f'Attendance logged: {data["action"]}',
            'student_name': data['name'],
            'action': data['action'],
            'timestamp': data['timestamp'],
            'is_late': is_late,
            'warning': 'Late arrival detected' if is_late else None
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error logging attendance: {e}")
        return jsonify({
            'success': False,
            'error': f'Error logging attendance: {str(e)}'
        }), 400

@app.route('/api/attendance/unknown', methods=['POST'])
@api_key_required
def log_unknown_card():
    """Log unknown RFID card - for Arduino"""
    try:
        data = request.get_json()
        
        timestamp = datetime.strptime(data['timestamp'], '%H:%M:%S').time()
        attendance_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        unknown_card = UnknownCard(
            rfid_uid=data['rfid_uid'],
            timestamp=timestamp,
            date=attendance_date
        )
        
        db.session.add(unknown_card)
        db.session.commit()
        
        # Emit real-time alert
        socketio.emit('system_alert', {
            'message': f'Unknown RFID card detected: {data["rfid_uid"]}',
            'type': 'warning'
        })
        
        log_system_activity(
            'UNKNOWN_CARD',
            f'Unknown RFID card: {data["rfid_uid"]}',
            None
        )
        
        print(f"⚠️  Unknown card logged: {data['rfid_uid']}")
        
        return jsonify({
            'success': True,
            'message': 'Unknown card logged',
            'rfid_uid': data['rfid_uid'],
            'action_required': 'Register this card or report if suspicious'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Error logging unknown card: {str(e)}'
        }), 400

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    """Get attendance logs with enhanced filtering"""
    try:
        date_filter = request.args.get('date')
        student_id = request.args.get('student_id')
        class_filter = request.args.get('class')
        action_filter = request.args.get('action')
        limit = int(request.args.get('limit', 50))
        
        query = AttendanceLog.query
        
        if date_filter:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(AttendanceLog.date == filter_date)
        
        if student_id:
            query = query.filter(AttendanceLog.reg_no == student_id)
            
        if class_filter:
            query = query.filter(AttendanceLog.class_name == class_filter)
            
        if action_filter:
            query = query.filter(AttendanceLog.action == action_filter)
        
        logs = query.order_by(AttendanceLog.created_at.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'count': len(logs),
            'logs': [log.to_dict() for log in logs]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching logs: {str(e)}'
        }), 500

@app.route('/api/classes', methods=['GET'])
@login_required
def get_classes():
    """Get unique class names for filters"""
    try:
        classes = db.session.query(Student.class_name).distinct().all()
        class_names = [cls[0] for cls in classes if cls[0]]
        
        return jsonify({
            'success': True,
            'classes': sorted(class_names)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching classes: {str(e)}'
        }), 500

@app.route('/api/reports/daily', methods=['GET'])
def daily_report():
    """Get daily attendance report with late arrivals - SQLite compatible"""
    try:
        report_date = request.args.get('date')
        if not report_date:
            report_date = get_current_date().strftime('%Y-%m-%d')
        
        filter_date = datetime.strptime(report_date, '%Y-%m-%d').date()
        
        # Get all students
        all_students = Student.query.all()
        
        # Get attendance logs for the date
        logs = AttendanceLog.query.filter(
            AttendanceLog.date == filter_date
        ).all()
        
        # FIXED: Get late arrivals count using func.count()
        from sqlalchemy import func
        late_arrivals = db.session.query(func.count(AttendanceLog.id)).filter(
            AttendanceLog.date == filter_date,
            AttendanceLog.action == 'ENTRY',
            getattr(AttendanceLog, 'is_late', False) == True
        ).scalar() or 0
        
        # Process attendance data
        present_students = []
        absent_students = []
        
        for student in all_students:
            student_logs = [log for log in logs if log.rfid_uid == student.rfid_uid]
            
            if student_logs:
                entry_logs = [log for log in student_logs if log.action == 'ENTRY']
                exit_logs = [log for log in student_logs if log.action == 'EXIT']
                
                present_students.append({
                    'student': student.to_dict(),
                    'entry_time': entry_logs[0].timestamp.strftime('%H:%M:%S') if entry_logs else None,
                    'exit_time': exit_logs[-1].timestamp.strftime('%H:%M:%S') if exit_logs else None,
                    'total_entries': len(entry_logs),
                    'total_exits': len(exit_logs),
                    'is_late': getattr(entry_logs[0], 'is_late', False) if entry_logs else False
                })
            else:
                absent_students.append(student.to_dict())
        
        return jsonify({
            'success': True,
            'date': report_date,
            'summary': {
                'total_students': len(all_students),
                'present_count': len(present_students),
                'absent_count': len(absent_students),
                'attendance_rate': round((len(present_students) / len(all_students)) * 100, 2) if all_students else 0,
                'late_arrivals': late_arrivals
            },
            'present_students': present_students,
            'absent_students': absent_students,
            'late_arrivals': late_arrivals
        })
        
    except Exception as e:
        print(f"❌ Error in daily_report: {e}")
        return jsonify({
            'success': False,
            'error': f'Error generating report: {str(e)}'
        }), 500


@app.route('/api/analytics/weekly-trend', methods=['GET'])
@login_required
def weekly_trend():
    """Get weekly attendance trend data - SQLite compatible"""
    try:
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=7)
        
        labels = []
        attendance_rates = []
        
        for i in range(7):
            current_date = start_date + timedelta(days=i)
            labels.append(current_date.strftime('%m/%d'))
            
            # Get attendance for this date
            total_students = Student.query.count()
            
            # FIXED: SQLite-compatible distinct count using subquery
            from sqlalchemy import func
            present_count = db.session.query(func.count(func.distinct(AttendanceLog.rfid_uid))).filter(
                AttendanceLog.date == current_date,
                AttendanceLog.action == 'ENTRY'
            ).scalar() or 0
            
            rate = round((present_count / total_students) * 100, 1) if total_students > 0 else 0
            attendance_rates.append(rate)
        
        return jsonify({
            'success': True,
            'labels': labels,
            'attendance_rates': attendance_rates
        })
        
    except Exception as e:
        print(f"❌ Error in weekly_trend: {e}")
        return jsonify({
            'success': False,
            'error': f'Error generating weekly trend: {str(e)}'
        }), 500


@app.route('/api/analytics/advanced', methods=['GET'])
@login_required
def advanced_analytics():
    """Generate advanced analytics data"""
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        class_filter = request.args.get('class')
        analysis_type = request.args.get('type', 'daily')
        
        if not start_date or not end_date:
            return jsonify({
                'success': False,
                'error': 'Start and end dates are required'
            }), 400
        
        start_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_dt = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Generate trend data
        trends_data = generate_trends_data(start_dt, end_dt, class_filter, analysis_type)
        
        # Generate class comparison data
        class_comparison_data = generate_class_comparison(start_dt, end_dt)
        
        return jsonify({
            'success': True,
            'trends': trends_data,
            'class_comparison': class_comparison_data,
            'period': f'{start_date} to {end_date}'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error generating analytics: {str(e)}'
        }), 500

def generate_trends_data(start_date, end_date, class_filter, analysis_type):
    """Generate trends data for analytics - SQLite compatible"""
    try:
        from sqlalchemy import func
        labels = []
        present_data = []
        absent_data = []
        
        if analysis_type == 'daily':
            current_date = start_date
            while current_date <= end_date:
                labels.append(current_date.strftime('%m/%d'))
                
                # Query for total students
                query = Student.query
                if class_filter:
                    query = query.filter(Student.class_name == class_filter)
                
                total_students = query.count()
                
                # FIXED: SQLite-compatible distinct count
                present_query = db.session.query(func.count(func.distinct(AttendanceLog.rfid_uid))).filter(
                    AttendanceLog.date == current_date,
                    AttendanceLog.action == 'ENTRY'
                )
                
                if class_filter:
                    present_query = present_query.join(Student).filter(
                        Student.class_name == class_filter
                    )
                
                present_count = present_query.scalar() or 0
                absent_count = total_students - present_count
                
                present_data.append(present_count)
                absent_data.append(absent_count)
                
                current_date += timedelta(days=1)
                
        elif analysis_type == 'weekly':
            # Weekly aggregation logic
            current_date = start_date
            while current_date <= end_date:
                week_end = min(current_date + timedelta(days=6), end_date)
                labels.append(f'{current_date.strftime("%m/%d")}-{week_end.strftime("%m/%d")}')
                
                # Aggregate week data
                week_present = 0
                week_absent = 0
                days_count = 0
                
                temp_date = current_date
                while temp_date <= week_end:
                    query = Student.query
                    if class_filter:
                        query = query.filter(Student.class_name == class_filter)
                    
                    total_students = query.count()
                    
                    # FIXED: SQLite-compatible approach
                    present_query = db.session.query(func.count(func.distinct(AttendanceLog.rfid_uid))).filter(
                        AttendanceLog.date == temp_date,
                        AttendanceLog.action == 'ENTRY'
                    )
                    
                    if class_filter:
                        present_query = present_query.join(Student).filter(
                            Student.class_name == class_filter
                        )
                    
                    present_count = present_query.scalar() or 0
                    
                    week_present += present_count
                    week_absent += (total_students - present_count)
                    days_count += 1
                    
                    temp_date += timedelta(days=1)
                
                # Average for the week
                present_data.append(round(week_present / days_count, 1) if days_count > 0 else 0)
                absent_data.append(round(week_absent / days_count, 1) if days_count > 0 else 0)
                
                current_date = week_end + timedelta(days=1)
        
        return {
            'labels': labels,
            'present': present_data,
            'absent': absent_data
        }
        
    except Exception as e:
        print(f"Error generating trends data: {e}")
        return {
            'labels': [],
            'present': [],
            'absent': []
        }

def generate_class_comparison(start_date, end_date):
    """Generate class-wise comparison data - SQLite compatible"""
    try:
        from sqlalchemy import func
        classes = db.session.query(Student.class_name).distinct().all()
        class_names = [cls[0] for cls in classes if cls[0]]
        
        labels = []
        attendance_rates = []
        
        for class_name in class_names:
            labels.append(class_name)
            
            # Get total students in class
            total_students = Student.query.filter(Student.class_name == class_name).count()
            
            if total_students == 0:
                attendance_rates.append(0)
                continue
            
            # Get average attendance for the period
            total_present = 0
            days_count = 0
            
            current_date = start_date
            while current_date <= end_date:
                # FIXED: SQLite-compatible approach
                present_count = db.session.query(func.count(func.distinct(AttendanceLog.rfid_uid))).join(Student).filter(
                    AttendanceLog.date == current_date,
                    AttendanceLog.action == 'ENTRY',
                    Student.class_name == class_name
                ).scalar() or 0
                
                total_present += present_count
                days_count += 1
                
                current_date += timedelta(days=1)
            
            avg_attendance_rate = round((total_present / (total_students * days_count)) * 100, 1) if days_count > 0 else 0
            attendance_rates.append(avg_attendance_rate)
        
        return {
            'labels': labels,
            'data': attendance_rates
        }
        
    except Exception as e:
        print(f"Error generating class comparison: {e}")
        return {
            'labels': [],
            'data': []
        }


@app.route('/api/students/import-csv', methods=['POST'])
@login_required
def import_students_csv():
    """Import students from CSV file"""
    try:
        if 'csv_file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['csv_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.DictReader(stream)
        
        imported_count = 0
        errors = []
        
        for row_num, row in enumerate(csv_input, start=2):  # Start from 2 (accounting for header)
            try:
                # Validate required fields
                required_fields = ['rfid_uid', 'reg_no', 'name', 'class', 'parent_email']
                for field in required_fields:
                    if field not in row or not row[field].strip():
                        errors.append(f"Row {row_num}: Missing {field}")
                        continue
                
                # Check if student already exists
                if Student.query.filter_by(rfid_uid=row['rfid_uid'].strip()).first():
                    errors.append(f"Row {row_num}: RFID UID {row['rfid_uid']} already exists")
                    continue
                
                if Student.query.filter_by(reg_no=row['reg_no'].strip()).first():
                    errors.append(f"Row {row_num}: Registration number {row['reg_no']} already exists")
                    continue
                
                student = Student(
                    rfid_uid=row['rfid_uid'].strip(),
                    reg_no=row['reg_no'].strip(),
                    name=row['name'].strip(),
                    class_name=row['class'].strip(),
                    parent_email=row['parent_email'].strip(),
                    parent_phone=row.get('parent_phone', '').strip()
                )
                
                db.session.add(student)
                imported_count += 1
                
            except Exception as row_error:
                errors.append(f"Row {row_num}: {str(row_error)}")
        
        if imported_count > 0:
            db.session.commit()
        
        log_system_activity(
            'CSV_IMPORT',
            f'Imported {imported_count} students via CSV',
            session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully imported {imported_count} students',
            'imported_count': imported_count,
            'errors': errors[:10] if errors else None,  # Limit errors shown
            'total_errors': len(errors)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Import failed: {str(e)}'
        }), 400

@app.route('/api/reports/export-excel', methods=['GET'])
@login_required
def export_excel():
    """Export attendance data to Excel"""
    try:
        # Get data
        students = Student.query.all()
        logs = AttendanceLog.query.order_by(AttendanceLog.created_at.desc()).limit(5000).all()
        
        # Create Excel file in memory
        output = io.BytesIO()
        
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Students sheet
            students_data = pd.DataFrame([{
                'RFID_UID': s.rfid_uid,
                'Registration_Number': s.reg_no,
                'Name': s.name,
                'Class': s.class_name,
                'Parent_Email': s.parent_email,
                'Parent_Phone': s.parent_phone or '',
                'Is_Present': 'Yes' if s.is_present else 'No',
                'Entry_Time': s.entry_time.strftime('%H:%M:%S') if s.entry_time else '',
                'Exit_Time': s.exit_time.strftime('%H:%M:%S') if s.exit_time else '',
                'Last_Updated': s.last_updated.strftime('%Y-%m-%d %H:%M:%S') if s.last_updated else ''
            } for s in students])
            students_data.to_excel(writer, sheet_name='Students', index=False)
            
            # Attendance logs sheet
            logs_data = pd.DataFrame([{
                'Date': l.date.strftime('%Y-%m-%d'),
                'Time': l.timestamp.strftime('%H:%M:%S'),
                'RFID_UID': l.rfid_uid,
                'Registration_Number': l.reg_no,
                'Student_Name': l.student_name,
                'Class': l.class_name,
                'Action': l.action,
                'Is_Late': 'Yes' if hasattr(l, 'is_late') and l.is_late else 'No',
                'Logged_At': l.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for l in logs])
            logs_data.to_excel(writer, sheet_name='Attendance_Logs', index=False)
            
            # Summary sheet
            today = get_current_date()
            daily_summary = []
            
            for i in range(7):  # Last 7 days
                check_date = today - timedelta(days=i)
                total_students = len(students)
                present_count = AttendanceLog.query.filter(
                    AttendanceLog.date == check_date,
                    AttendanceLog.action == 'ENTRY'
                ).distinct(AttendanceLog.rfid_uid).count()
                
                daily_summary.append({
                    'Date': check_date.strftime('%Y-%m-%d'),
                    'Total_Students': total_students,
                    'Present': present_count,
                    'Absent': total_students - present_count,
                    'Attendance_Rate': round((present_count / total_students) * 100, 2) if total_students > 0 else 0
                })
            
            summary_df = pd.DataFrame(daily_summary)
            summary_df.to_excel(writer, sheet_name='Weekly_Summary', index=False)
        
        output.seek(0)
        
        log_system_activity(
            'DATA_EXPORT',
            'Exported attendance data to Excel',
            session.get('user_id')
        )
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'attendance_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Export failed: {str(e)}'
        }), 500

@app.route('/api/system/backup', methods=['POST'])
@login_required
def backup_system():
    """Create comprehensive system backup"""
    try:
        backup_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'version': '2.0.0',
                'created_by': session.get('username'),
                'total_students': Student.query.count(),
                'total_logs': AttendanceLog.query.count()
            },
            'students': [s.to_dict() for s in Student.query.all()],
            'attendance_logs': [l.to_dict() for l in AttendanceLog.query.all()],
            'unknown_cards': [u.to_dict() for u in UnknownCard.query.all()],
            'system_logs': [sl.to_dict() for sl in SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(1000).all()]
        }
        
        backup_filename = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        backup_path = os.path.join('backups', backup_filename)
        
        # Ensure backup directory exists
        os.makedirs('backups', exist_ok=True)
        
        with open(backup_path, 'w') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        log_system_activity(
            'SYSTEM_BACKUP',
            f'Created backup: {backup_filename}',
            session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'message': 'Backup created successfully',
            'filename': backup_filename,
            'size': f'{os.path.getsize(backup_path) / 1024:.2f} KB'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Backup failed: {str(e)}'
        }), 500

@app.route('/api/system/stats', methods=['GET'])
@login_required
def system_stats():
    """Get comprehensive system statistics"""
    try:
        # Calculate database size (approximation for SQLite)
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        db_size = "N/A"
        
        if os.path.exists(db_path):
            size_bytes = os.path.getsize(db_path)
            if size_bytes < 1024:
                db_size = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                db_size = f"{size_bytes / 1024:.2f} KB"
            else:
                db_size = f"{size_bytes / (1024 * 1024):.2f} MB"
        
        # Get last backup info
        backup_dir = 'backups'
        last_backup = None
        if os.path.exists(backup_dir):
            backup_files = [f for f in os.listdir(backup_dir) if f.startswith('backup_') and f.endswith('.json')]
            if backup_files:
                backup_files.sort(reverse=True)
                last_backup_file = os.path.join(backup_dir, backup_files[0])
                last_backup = datetime.fromtimestamp(os.path.getmtime(last_backup_file)).isoformat()
        
        # Count API requests today (from system logs)
        today = datetime.now().date()
        api_requests = SystemLog.query.filter(
            db.func.date(SystemLog.timestamp) == today,
            SystemLog.action.like('%API%')
        ).count()
        
        return jsonify({
            'success': True,
            'total_students': Student.query.count(),
            'total_records': AttendanceLog.query.count() + Student.query.count() + SystemLog.query.count(),
            'db_size': db_size,
            'uptime': calculate_uptime(),
            'last_backup': last_backup,
            'api_requests_today': api_requests,
            'unknown_cards': UnknownCard.query.count(),
            'system_logs': SystemLog.query.count(),
            'active_students': Student.query.filter(Student.is_present == True).count()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching system stats: {str(e)}'
        }), 500

@app.route('/api/notifications/send-absent-alerts', methods=['POST'])
@login_required
def send_absent_alerts():
    """Send email alerts for absent students"""
    try:
        data = request.get_json() or {}
        report_date = data.get('date', get_current_date().strftime('%Y-%m-%d'))
        filter_date = datetime.strptime(report_date, '%Y-%m-%d').date()
        
        # Get absent students
        all_students = Student.query.all()
        logs = AttendanceLog.query.filter(
            AttendanceLog.date == filter_date,
            AttendanceLog.action == 'ENTRY'
        ).all()
        
        present_uids = set(log.rfid_uid for log in logs)
        absent_students = [s for s in all_students if s.rfid_uid not in present_uids]
        
        sent_count = 0
        errors = []
        
        for student in absent_students:
            try:
                msg = Message(
                    subject=f'Attendance Alert - {student.name} Absent on {report_date}',
                    recipients=[student.parent_email],
                    body=f"""Dear Parent,

This is to inform you that your child {student.name} (Registration: {student.reg_no}) from class {student.class_name} was marked absent from school on {report_date}.

If your child was present or if there was a valid reason for absence, please contact the school administration immediately.

Student Details:
- Name: {student.name}
- Registration Number: {student.reg_no}
- Class: {student.class_name}
- Date: {report_date}

For any queries, please contact the school office.

Best regards,
School Administration
Enhanced RFID Attendance System

---
This is an automated message from the school attendance system.
"""
                )
                mail.send(msg)
                sent_count += 1
                print(f"📧 Absent alert sent to {student.parent_email} for {student.name}")
                
            except Exception as email_error:
                error_msg = f"Failed to send to {student.parent_email}: {str(email_error)}"
                errors.append(error_msg)
                print(f"❌ Email error: {email_error}")
        
        log_system_activity(
            'ABSENT_ALERTS_SENT',
            f'Sent {sent_count} absent alerts for {report_date}',
            session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'message': f'Absent alerts processed for {len(absent_students)} students',
            'total_absent': len(absent_students),
            'emails_sent': sent_count,
            'failed_emails': len(errors),
            'errors': errors[:5] if errors else None  # Show max 5 errors
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error sending alerts: {str(e)}'
        }), 400

@app.route('/api/system/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    """Regenerate API key for Arduino authentication"""
    try:
        new_api_key = secrets.token_urlsafe(32)
        
        # In a real implementation, you would store this in your config or database
        # For now, we'll just return it
        
        log_system_activity(
            'API_KEY_REGENERATED',
            'API key was regenerated',
            session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'message': 'API key regenerated successfully',
            'new_key': new_api_key[:8] + '...',  # Show only first 8 chars for security
            'note': 'Update your Arduino code with the new API key'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error regenerating API key: {str(e)}'
        }), 500

# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected: {request.sid}')
    emit('status', {
        'message': 'Connected to Enhanced RFID Attendance System',
        'timestamp': datetime.now().isoformat(),
        'features': ['real-time updates', 'live notifications', 'instant alerts']
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'Client disconnected: {request.sid}')

@socketio.on('join_room')
def handle_join_room(data):
    """Handle room joining for targeted updates"""
    room = data.get('room', 'general')
    join_room(room)
    emit('joined_room', {'room': room, 'status': 'success'})

@socketio.on('ping')
def handle_ping():
    """Handle ping for connection testing"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# Login template with enhanced styling
login_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - Enhanced RFID Attendance System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .login-header {
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2em;
        }
        
        .login-header p {
            color: #666;
            font-size: 1em;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
            background: #f9f9f9;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #2196F3;
            background: white;
            box-shadow: 0 0 0 3px rgba(33, 150, 243, 0.1);
        }
        
        .btn {
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: 500;
            margin-top: 10px;
            transition: transform 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(33, 150, 243, 0.3);
        }
        
        .error {
            color: #f44336;
            background: #ffebee;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            border-left: 4px solid #f44336;
        }
        
        .system-info {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #666;
            line-height: 1.5;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 15px;
            text-align: left;
        }
        
        .feature {
            font-size: 11px;
            color: #888;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
            
            .login-header h1 {
                font-size: 1.5em;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🎓 Enhanced RFID System</h1>
            <p>Student Attendance Management</p>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" placeholder="Enter your username" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" placeholder="Enter your password" class="form-control" required>
            </div>
            <button type="submit" class="btn">🔐 Login to Dashboard</button>
        </form>
        
        <div class="system-info">
            <strong>Default Credentials:</strong><br>
            Username: <code>admin</code><br>
            Password: <code>admin123</code>
            
            <div class="features">
                <div class="feature">✅ Real-time Updates</div>
                <div class="feature">📊 Advanced Analytics</div>
                <div class="feature">📧 Email Notifications</div>
                <div class="feature">📱 Mobile Responsive</div>
                <div class="feature">🔒 Secure Authentication</div>
                <div class="feature">📈 Detailed Reports</div>
                <div class="feature">🌓 Dark Mode Support</div>
                <div class="feature">📤 Data Import/Export</div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'available_endpoints': [
            '/api/students',
            '/api/attendance/log',
            '/api/reports/daily',
            '/dashboard',
            '/login'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Please contact system administrator'
    }), 500

# Initialize scheduled tasks
def init_scheduler():
    """Initialize scheduled tasks"""
    def daily_backup():
        """Create daily automatic backup"""
        with app.app_context():
            try:
                # Create backup
                backup_data = {
                    'metadata': {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'automatic_daily',
                        'version': '2.0.0'
                    },
                    'students': [s.to_dict() for s in Student.query.all()],
                    'recent_logs': [l.to_dict() for l in AttendanceLog.query.filter(
                        AttendanceLog.date >= datetime.now().date() - timedelta(days=7)
                    ).all()]
                }
                
                backup_filename = f'auto_backup_{datetime.now().strftime("%Y%m%d")}.json'
                backup_path = os.path.join('backups', 'auto', backup_filename)
                
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                
                with open(backup_path, 'w') as f:
                    json.dump(backup_data, f, indent=2, default=str)
                
                print(f"✅ Automatic daily backup created: {backup_filename}")
                
            except Exception as e:
                print(f"❌ Automatic backup failed: {e}")
    
    # Schedule daily backup at 2 AM
    schedule.every().day.at("02:00").do(daily_backup)
    
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

if __name__ == '__main__':
    print("🚀 Starting Enhanced Arduino RFID Attendance System...")
    print("=" * 60)
    print("📍 Dashboard: http://localhost:5000/dashboard")
    print("🔌 Arduino API: http://your-ip:5000/api/")
    print("🔐 Login: http://localhost:5000/login")
    print("📊 Features: Real-time updates, Analytics, Notifications")
    print("🌐 WebSocket: Enabled for live updates")
    print("=" * 60)
    
    # Create database tables
    create_tables()
    
    # Initialize scheduler for automatic tasks
    init_scheduler()
    
    # Run Flask app with SocketIO support
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=False,  # Set to False for production
        allow_unsafe_werkzeug=True  # For development only
    )
