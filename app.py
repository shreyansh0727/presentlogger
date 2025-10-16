import os
import threading
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_file,render_template
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit
from config import config
from database import MongoDB, get_db
from models import (Student, AttendanceLog, UnknownCard, AdminUser, 
                   ApiKey, SystemLog, Heartbeat, SchoolSettings)
from datetime import datetime, date, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import time
import requests

EMAIL_API_URL = "https://email-service-474903.uc.r.appspot.com/send-email"
EMAIL_API_KEY = "jhfhhfh87373899874djwjwhqrmvnbi8976jj"

def send_email_microservice(to, subject, html, cc=None, bcc=None):
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": EMAIL_API_KEY
    }
    payload = {
        "to": to,
        "subject": subject,
        "html": html,
        "cc": cc if cc else [],
        "bcc": bcc if bcc else []
    }
    response = requests.post(EMAIL_API_URL, headers=headers, json=payload)
    return response.status_code, response.json()
# ==================== APP INITIALIZATION ====================

def create_app(config_name=None):
    """Application factory"""
    app = Flask(__name__)
    
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    MongoDB.init_app(app)
    
    cors_origins = app.config['CORS_ORIGINS']
    if app.config['DEBUG']:
        cors_origins = ['*']
    
    CORS(app, origins=cors_origins)
    mail = Mail(app)
    socketio = SocketIO(
        app, 
        cors_allowed_origins=cors_origins,
        async_mode='threading',
        logger=False,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25
    )
    
    app.mail = mail
    app.socketio = socketio
    
    return app

app = create_app()
mail = app.mail
socketio = app.socketio

IST = pytz.timezone('Asia/Kolkata')
system_start_time = datetime.now()

# ==================== HELPER FUNCTIONS ====================

def get_current_time():
    return datetime.now(IST).time()

def get_current_date():
    return datetime.now(IST).date()

def calculate_uptime():
    uptime = datetime.now() - system_start_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m"

def log_system_activity(action, details=None, user_id=None):
    try:
        SystemLog.create(action, details, user_id, request.remote_addr if request else None)
    except Exception as e:
        print(f"Error logging activity: {e}")

# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key or not ApiKey.validate_key(api_key):
            return jsonify({'success': False, 'error': 'Invalid or missing API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== INITIALIZATION ====================

def create_default_admin():
    try:
        if not AdminUser.find_by_username('admin'):
            AdminUser.create('admin', 'admin@school.com', generate_password_hash('admin123'), 'admin')
            print("✅ Default admin created (username: admin, password: admin123)")
    except Exception as e:
        print(f"Error creating admin: {e}")

def create_initial_api_key():
    try:
        if not ApiKey.get_active_key():
            key = secrets.token_urlsafe(32)
            ApiKey.create(key, 'Initial Arduino Key')
            print(f"✅ Initial API key: {key}")
    except Exception as e:
        print(f"Error creating API key: {e}")

with app.app_context():
    create_default_admin()
    create_initial_api_key()

# ==================== API ROUTES ====================
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

@app.route('/info')
def info_page():
    """Project information page"""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user = AdminUser.find_by_username(username)
        
        if user and user.get('is_active') and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            AdminUser.update_last_login(user['id'])
            log_system_activity('USER_LOGIN', f"User {username} logged in", user['id'])
            
            if request.is_json:
                return jsonify({'success': True, 'redirect': '/dashboard'})
            return redirect(url_for('dashboard'))
        
        if request.is_json:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    log_system_activity('USER_LOGOUT', f"User {session.get('username')} logged out", session.get('user_id'))
    session.clear()
    return redirect(url_for('login'))

# ==================== STUDENT MANAGEMENT ====================

@app.route('/api/students', methods=['GET', 'POST'])
@login_required
def manage_students():
    if request.method == 'GET':
        try:
            students = Student.find_all()
            return jsonify({'success': True, 'count': len(students), 'students': students})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            required = ['rfid_uid', 'reg_no', 'name', 'class', 'parent_email']
            for field in required:
                if field not in data:
                    return jsonify({'success': False, 'error': f'Missing: {field}'}), 400
            
            if Student.find_by_rfid(data['rfid_uid']):
                return jsonify({'success': False, 'error': 'RFID UID exists'}), 400
            
            if Student.find_by_reg_no(data['reg_no']):
                return jsonify({'success': False, 'error': 'Registration number exists'}), 400
            
            student = Student.create(data['rfid_uid'], data['reg_no'], data['name'], 
                                    data['class'], data['parent_email'], data.get('parent_phone'))
            
            log_system_activity('STUDENT_ADDED', f"Added {student['name']}", session.get('user_id'))
            return jsonify({'success': True, 'message': 'Student registered', 'student': student}), 201
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/students/<student_id>', methods=['PUT', 'DELETE'])
@login_required
def modify_student(student_id):
    if request.method == 'PUT':
        try:
            data = request.get_json()
            from bson import ObjectId
            collection = Student.get_collection()
            result = collection.update_one({'_id': ObjectId(student_id)}, {'$set': data})
            
            if result.modified_count > 0:
                log_system_activity('STUDENT_UPDATED', f"Updated ID: {student_id}", session.get('user_id'))
                return jsonify({'success': True, 'message': 'Student updated'})
            return jsonify({'success': False, 'error': 'Student not found'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    elif request.method == 'DELETE':
        try:
            if Student.delete_by_id(student_id):
                log_system_activity('STUDENT_DELETED', f"Deleted ID: {student_id}", session.get('user_id'))
                return jsonify({'success': True, 'message': 'Student deleted'})
            return jsonify({'success': False, 'error': 'Student not found'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

# ==================== ATTENDANCE LOGGING ====================

@app.route('/api/student', methods=['GET'])
@api_key_required
def get_student_by_uid():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({'success': False, 'error': 'UID required'}), 400
    
    try:
        student = Student.find_by_rfid(uid)
        if student:
            return jsonify({
                'found': True,
                'reg_no': student['reg_no'],
                'name': student['name'],
                'class': student['class_name'],
                'parent_email': student['parent_email'],
                'is_present': student['is_present']
            })
        return jsonify({'found': False}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/attendance/log', methods=['POST'])
@api_key_required
def log_attendance():
    try:
        data = request.get_json()
        required = ['rfid_uid', 'reg_no', 'name', 'class', 'action', 'timestamp', 'date']
        for field in required:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing: {field}'}), 400
        
        # Parse timestamp
        timestamp = datetime.strptime(data['timestamp'], '%H:%M:%S').time()
        timestamp_str = data['timestamp']  # ✅ ADDED: Keep string version for MongoDB
        
        # Get school settings for late calculation
        settings = SchoolSettings.get_settings()
        school_start_time = datetime.strptime(settings.get('school_start_time', '09:00:00'), '%H:%M:%S').time()
        late_threshold = settings.get('late_threshold_minutes', 15)
        
        # Calculate if late
        is_late = False
        late_by_minutes = 0
        
        if data['action'] == 'ENTRY':
            # Convert times to minutes for comparison
            arrival_minutes = timestamp.hour * 60 + timestamp.minute
            start_minutes = school_start_time.hour * 60 + school_start_time.minute
            late_threshold_minutes = start_minutes + late_threshold
            
            if arrival_minutes > late_threshold_minutes:
                is_late = True
                late_by_minutes = arrival_minutes - start_minutes
        
        # Create attendance log
        log = AttendanceLog.create(
            rfid_uid=data['rfid_uid'],
            reg_no=data['reg_no'],
            student_name=data['name'],
            class_name=data['class'],
            action=data['action'],
            timestamp=data['timestamp'],
            log_date=data['date'],
            is_late=is_late,
            device_info=data.get('device_info', {})
        )
        
        # Update student presence
        if data['action'] == 'ENTRY':
            Student.update_presence(data['rfid_uid'], True, entry_time=timestamp_str)  # ✅ CHANGED
            
            # Send late arrival email if enabled and student is late
            if is_late:
                try:
                    student = Student.find_by_rfid(data['rfid_uid'])
                    if student and student.get('parent_email'):
                        send_late_arrival_email(student, data['timestamp'], late_by_minutes)
                except Exception as e:
                    print(f"❌ Failed to send late arrival email: {e}")
                    
        elif data['action'] == 'EXIT':
            Student.update_presence(data['rfid_uid'], False, exit_time=timestamp_str)  # ✅ CHANGED
        
        # Emit real-time update via SocketIO
        socketio.emit('attendance_update', {
            'student_name': data['name'],
            'action': data['action'],
            'timestamp': data['timestamp'],
            'is_late': is_late
        })
        
        # Log system activity
        log_system_activity('ATTENDANCE_LOGGED', f"{data['name']} - {data['action']}", None)
        
        return jsonify({
            'success': True,
            'message': f'Attendance logged: {data["action"]}',
            'is_late': is_late,
            'late_by_minutes': late_by_minutes if is_late else 0
        })
        
    except Exception as e:
        print(f"❌ Attendance log error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/attendance/unknown', methods=['POST'])
@api_key_required
def log_unknown_card():
    try:
        data = request.get_json()
        UnknownCard.create(data['rfid_uid'], data['timestamp'], data['date'], data.get('device_info', {}))
        
        socketio.emit('system_alert', {
            'message': f'Unknown card: {data["rfid_uid"]}',
            'type': 'warning'
        })
        
        return jsonify({'success': True, 'message': 'Unknown card logged'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/system/heartbeat', methods=['POST'])
@api_key_required
def heartbeat():
    try:
        data = request.get_json()
        Heartbeat.create(data.get('device_type', 'unknown'), data.get('mac_address'),
                        data.get('uptime'), data.get('daily_scans'), 
                        data.get('wifi_rssi'), data.get('timestamp'))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

# ==================== REPORTS & ANALYTICS ====================

@app.route('/api/reports/daily', methods=['GET'])
def daily_report():
    try:
        report_date = request.args.get('date', get_current_date().strftime('%Y-%m-%d'))
        all_students = Student.find_all()
        logs = AttendanceLog.find_by_date(report_date)
        
        present_students = []
        for student in all_students:
            student_logs = [log for log in logs if log['rfid_uid'] == student['rfid_uid']]
            if student_logs:
                entry = [l for l in student_logs if l['action'] == 'ENTRY']
                exit_logs = [l for l in student_logs if l['action'] == 'EXIT']
                present_students.append({
                    **student,
                    'entry_time': entry[0]['timestamp'] if entry else None,
                    'exit_time': exit_logs[-1]['timestamp'] if exit_logs else None,
                    'is_late': entry[0].get('is_late', False) if entry else False
                })
        
        absent_students = [s for s in all_students if s['rfid_uid'] not in [p['rfid_uid'] for p in present_students]]
        late = AttendanceLog.get_late_arrivals(report_date)
        
        return jsonify({
            'success': True,
            'date': report_date,
            'summary': {
                'total_students': len(all_students),
                'present_count': len(present_students),
                'absent_count': len(absent_students),
                'attendance_rate': round((len(present_students)/len(all_students))*100,2) if all_students else 0,
                'late_arrivals': len(late)
            },
            'present_students': present_students,
            'absent_students': absent_students
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/stats', methods=['GET'])
@login_required
def system_stats():
    try:
        from database import MongoDB
        health = MongoDB.health_check()
        today = get_current_date().strftime('%Y-%m-%d')
        
        total_students = len(Student.find_all())
        present = len(Student.find_all({'is_present': True}))
        
        logs = AttendanceLog.find_by_date(today)
        entries = len([l for l in logs if l['action'] == 'ENTRY'])
        late = len([l for l in logs if l.get('is_late', False)])
        
        unknown = len(UnknownCard.find_all(100))
        
        return jsonify({
            'success': True,
            'system': {'uptime': calculate_uptime(), 'database_health': health},
            'today': {
                'date': today,
                'total_students': total_students,
                'present': present,
                'absent': total_students - present,
                'attendance_rate': round((present/total_students)*100,2) if total_students else 0,
                'entries': entries,
                'late_arrivals': late
            },
            'alerts': {'unknown_cards': unknown, 'late_arrivals': late}
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/weekly-trend', methods=['GET'])
@login_required
def weekly_trend():
    try:
        today = get_current_date()
        week_data = []
        
        for i in range(6, -1, -1):
            date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
            logs = AttendanceLog.find_by_date(date)
            unique = set([l['rfid_uid'] for l in logs if l['action'] == 'ENTRY'])
            late = len([l for l in logs if l.get('is_late', False)])
            total = len(Student.find_all())
            
            week_data.append({
                'date': date,
                'day': (today - timedelta(days=i)).strftime('%A'),
                'present_count': len(unique),
                'late_count': late,
                'attendance_rate': round((len(unique)/total)*100,2) if total else 0
            })
        
        return jsonify({
            'success': True,
            'data': week_data,
            'labels': [d['day'] for d in week_data],
            'attendance_rates': [d['attendance_rate'] for d in week_data]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/classes', methods=['GET'])
@login_required
def get_classes():
    try:
        collection = Student.get_collection()
        classes = collection.distinct('class_name')
        
        class_data = []
        for class_name in sorted(classes):
            total = collection.count_documents({'class_name': class_name})
            present = collection.count_documents({'class_name': class_name, 'is_present': True})
            class_data.append({
                'name': class_name,
                'student_count': total,
                'present_count': present,
                'attendance_rate': round((present/total)*100,2) if total else 0
            })
        
        return jsonify({'success': True, 'count': len(class_data), 'classes': class_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    try:
        log_date = request.args.get('date')
        limit = int(request.args.get('limit', 50))
        
        if log_date:
            logs = AttendanceLog.find_by_date(log_date)
        else:
            collection = AttendanceLog.get_collection()
            logs = list(collection.find().sort('created_at', -1).limit(limit))
            logs = [AttendanceLog.serialize_doc(l) for l in logs]
        
        return jsonify({'success': True, 'count': len(logs), 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/unknown-cards', methods=['GET'])
@login_required
def get_unknown_cards():
    try:
        limit = int(request.args.get('limit', 100))
        cards = UnknownCard.find_all(limit)
        return jsonify({'success': True, 'count': len(cards), 'cards': cards})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== API KEY MANAGEMENT ====================

@app.route('/api/system/current-api-key', methods=['GET'])
@login_required
def get_current_api_key():
    try:
        key = ApiKey.get_active_key()
        if key:
            return jsonify({
                'success': True,
                'has_key': True,
                'api_key_info': {
                    'id': key['id'],
                    'key_preview': f"{key['key'][:8]}{'*'*24}",
                    'created_at': key['created_at'],
                    'last_used': key.get('last_used'),
                    'usage_count': key.get('usage_count', 0)
                }
            })
        return jsonify({'success': True, 'has_key': False})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    try:
        new_key = secrets.token_urlsafe(32)
        key = ApiKey.create(new_key, 'Arduino Device Key', session.get('user_id'))
        
        log_system_activity('API_KEY_REGENERATED', f"New key ID: {key['id']}", session.get('user_id'))
        
        return jsonify({
            'success': True,
            'message': 'API key regenerated',
            'api_key_info': {
                'id': key['id'],
                'key_preview': f"{new_key[:8]}{'*'*24}",
                'full_key': new_key,
                'created_at': key['created_at']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('status', {'message': 'Connected', 'timestamp': datetime.now().isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ==================== LOGIN TEMPLATE ====================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Attendance System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root[data-theme="light"] {
            --bg: #f8fafc;
            --card: rgba(255, 255, 255, 0.7);
            --text: #1e293b;
            --text-light: #64748b;
            --accent: #6366f1;
            --border: rgba(148, 163, 184, 0.2);
            --input: rgba(255, 255, 255, 0.8);
        }

        :root[data-theme="dark"] {
            --bg: #0f172a;
            --card: rgba(30, 41, 59, 0.7);
            --text: #f1f5f9;
            --text-light: #94a3b8;
            --accent: #818cf8;
            --border: rgba(148, 163, 184, 0.1);
            --input: rgba(15, 23, 42, 0.8);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            transition: background 0.3s;
        }

        .container {
            width: 100%;
            max-width: 380px;
            position: relative;
        }

        .theme-toggle {
            position: absolute;
            top: -50px;
            right: 0;
            display: flex;
            gap: 6px;
            background: var(--card);
            padding: 4px;
            border-radius: 50px;
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
        }

        .theme-btn {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border: none;
            background: transparent;
            color: var(--text-light);
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .theme-btn:hover {
            color: var(--accent);
        }

        .theme-btn.active {
            background: var(--accent);
            color: white;
        }

        .card {
            background: var(--card);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 32px 28px;
            border: 1px solid var(--border);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
        }

        .header {
            text-align: center;
            margin-bottom: 28px;
        }

        .logo {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 16px;
            font-size: 1.75rem;
            color: white;
            box-shadow: 0 8px 16px rgba(99, 102, 241, 0.3);
        }

        .header h1 {
            color: var(--text);
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 4px;
        }

        .header p {
            color: var(--text-light);
            font-size: 0.875rem;
        }

        .alert {
            padding: 12px 14px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 10px;
            color: #dc2626;
            font-size: 0.875rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: var(--text);
            font-size: 0.875rem;
            font-weight: 500;
        }

        .input-wrapper {
            position: relative;
        }

        .input-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-light);
            font-size: 0.95rem;
        }

        input {
            width: 100%;
            padding: 12px 14px 12px 42px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: var(--input);
            color: var(--text);
            font-size: 0.95rem;
            transition: all 0.2s;
            backdrop-filter: blur(10px);
        }

        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        input::placeholder {
            color: var(--text-light);
            opacity: 0.6;
        }

        .toggle-password {
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-light);
            cursor: pointer;
            padding: 4px;
        }

        .btn-submit {
            width: 100%;
            padding: 13px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }

        .btn-submit:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(99, 102, 241, 0.4);
        }

        .info {
            margin-top: 20px;
            padding: 14px;
            background: var(--input);
            border-radius: 10px;
            border: 1px solid var(--border);
            backdrop-filter: blur(10px);
        }

        .info h3 {
            font-size: 0.8rem;
            color: var(--text-light);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .cred {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 0.875rem;
        }

        .cred span {
            color: var(--text-light);
        }

        .cred code {
            background: var(--accent);
            color: white;
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .footer {
            text-align: center;
            margin-top: 16px;
            color: var(--text-light);
            font-size: 0.8rem;
        }

        @media (max-width: 480px) {
            .card {
                padding: 28px 24px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="theme-toggle">
            <button class="theme-btn active" onclick="setTheme('light')" data-theme="light">
                <i class="fas fa-sun"></i>
            </button>
            <button class="theme-btn" onclick="setTheme('dark')" data-theme="dark">
                <i class="fas fa-moon"></i>
            </button>
        </div>

        <div class="card">
            <div class="header">
                <div class="logo">
                    <i class="fas fa-lock"></i>
                </div>
                <h1>Welcome</h1>
                <p>Sign in to continue</p>
            </div>

            {% if error %}
            <div class="alert">
                <i class="fas fa-circle-exclamation"></i>
                <span>{{ error }}</span>
            </div>
            {% endif %}

            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <div class="input-wrapper">
                        <i class="input-icon fas fa-user"></i>
                        <input type="text" name="username" placeholder="admin" required autocomplete="username">
                    </div>
                </div>

                <div class="form-group">
                    <label>Password</label>
                    <div class="input-wrapper">
                        <i class="input-icon fas fa-key"></i>
                        <input type="password" id="pass" name="password" placeholder="••••••••" required autocomplete="current-password">
                        <button type="button" class="toggle-password" onclick="togglePass()">
                            <i class="fas fa-eye" id="eye"></i>
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn-submit">
                    <i class="fas fa-arrow-right"></i>
                    <span>Sign In</span>
                </button>
            </form>

            <div class="info">
                <h3>Default Login</h3>
                <div class="cred">
                    <span>Username</span>
                    <code>admin</code>
                </div>
                <div class="cred">
                    <span>Password</span>
                    <code>admin123</code>
                </div>
                <div class="cred">
                    <span>**If the default password is not accepted, try contacting the admin.  
</span>
                </div>
            </div>

            <div class="footer">
                © 2025 Attendance System
            </div>
        </div>
    </div>

    <script>
        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
            document.querySelector(`[data-theme="${theme}"]`).classList.add('active');
        }

        function togglePass() {
            const p = document.getElementById('pass');
            const e = document.getElementById('eye');
            if (p.type === 'password') {
                p.type = 'text';
                e.className = 'fas fa-eye-slash';
            } else {
                p.type = 'password';
                e.className = 'fas fa-eye';
            }
        }

        window.addEventListener('DOMContentLoaded', () => {
            setTheme(localStorage.getItem('theme') || 'light');
        });

        document.querySelector('form').addEventListener('submit', e => {
            const btn = document.querySelector('.btn-submit');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
            btn.disabled = true;
        });
    </script>
</body>
</html>


'''


# ==================== ADMIN PASSWORD CHANGE ====================

@app.route('/api/admin/change-password', methods=['POST'])
@login_required
def change_password():
    """Change admin password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'error': 'New passwords do not match'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        # Get current user
        user = AdminUser.find_by_username(session.get('username'))
        
        if not user or not check_password_hash(user['password_hash'], current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        
        # Update password
        from bson import ObjectId
        collection = AdminUser.get_collection()
        new_hash = generate_password_hash(new_password)
        
        result = collection.update_one(
            {'_id': ObjectId(user['id'])},
            {'$set': {'password_hash': new_hash}}
        )
        
        if result.modified_count > 0:
            log_system_activity('PASSWORD_CHANGED', f"User {user['username']} changed password", user['id'])
            return jsonify({'success': True, 'message': 'Password changed successfully'})
        
        return jsonify({'success': False, 'error': 'Password update failed'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== STUDENT EDIT ENDPOINT ====================

@app.route('/api/students/<student_id>/edit', methods=['GET', 'PUT'])
@login_required
def edit_student(student_id):
    """Get or update student details"""
    if request.method == 'GET':
        try:
            from bson import ObjectId
            collection = Student.get_collection()
            student = collection.find_one({'_id': ObjectId(student_id)})
            
            if student:
                return jsonify({
                    'success': True,
                    'student': Student.serialize_doc(student)
                })
            return jsonify({'success': False, 'error': 'Student not found'}), 404
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            from bson import ObjectId
            collection = Student.get_collection()
            
            # Update fields
            update_data = {}
            allowed_fields = ['name', 'class_name', 'parent_email', 'parent_phone', 'rfid_uid', 'reg_no']
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if not update_data:
                return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
            
            update_data['last_updated'] = datetime.utcnow()
            
            result = collection.update_one(
                {'_id': ObjectId(student_id)},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                log_system_activity('STUDENT_UPDATED', f"Updated student ID: {student_id}", session.get('user_id'))
                return jsonify({'success': True, 'message': 'Student updated successfully'})
            
            return jsonify({'success': False, 'error': 'No changes made'}), 400
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Unknown Cards Management ====================

@app.route('/api/unknown-cards/<card_id>', methods=['DELETE'])
@login_required
def delete_unknown_card(card_id):
    """Delete an unknown card by ID"""
    from bson import ObjectId
    try:
        # Try deleting by ObjectId
        result = UnknownCard.get_collection().delete_one({'_id': ObjectId(card_id)})
        
        if result.deleted_count > 0:
            log_system_activity('UNKNOWN_CARD_DELETED', f'Card ID: {card_id}', session.get('user_id'))
            return jsonify({'success': True, 'message': 'Unknown card deleted'})
        
        return jsonify({'success': False, 'error': 'Card not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/unknown-cards/<card_id>/register', methods=['POST'])
@login_required
def register_student_from_unknown(card_id):
    """Register a new student from an unknown card"""
    from bson import ObjectId
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['reg_no', 'name', 'class_name', 'parent_email']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing field: {field}'}), 400
        
        # Get unknown card
        card = UnknownCard.get_collection().find_one({'_id': ObjectId(card_id)})
        if not card:
            return jsonify({'success': False, 'error': 'Unknown card not found'}), 404
        
        rfid_uid = card.get('rfid_uid')
        
        # Check if student already exists with this RFID
        existing = Student.find_by_rfid(rfid_uid)
        if existing:
            return jsonify({'success': False, 'error': 'This RFID is already registered'}), 409
        
        # Check if reg_no already exists
        existing_reg = Student.find_by_reg_no(data['reg_no'])
        if existing_reg:
            return jsonify({'success': False, 'error': 'Registration number already exists'}), 409
        
        # Create new student
        student = Student.create(
            rfid_uid=rfid_uid,
            reg_no=data['reg_no'],
            name=data['name'],
            class_name=data['class_name'],
            parent_email=data['parent_email'],
            parent_phone=data.get('parent_phone', '')
        )
        
        # Delete the unknown card entry
        UnknownCard.get_collection().delete_one({'_id': ObjectId(card_id)})
        
        log_system_activity('STUDENT_REGISTERED', f"From unknown card: {student['name']}", session.get('user_id'))
        
        socketio.emit('student_added', student, namespace='/')
        
        return jsonify({
            'success': True,
            'message': 'Student registered successfully',
            'student': student
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def send_late_arrival_email(student, arrival_time, late_by_minutes):
    """Send email for late arrival using microservice API"""
    settings = SchoolSettings.get_settings()
    if not settings.get('late_arrival_email') or not settings.get('email_notifications_enabled'):
        return

    if not student.get('parent_email'):
        print(f"⚠️ No parent email for {student.get('name')}")
        return

    subject = f"Late Arrival Alert - {student['name']}"
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; border: 2px solid #f59e0b; border-radius: 10px; padding: 20px;">
            <h2 style="color: #f59e0b;">⚠️ Late Arrival Notification</h2>
            <p>Dear Parent,</p>
            <p>This is to inform you that <strong>{student['name']}</strong> (Reg. No: {student['reg_no']}) arrived late to school today.</p>
            
            <div style="background: #fef3c7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Details:</strong></p>
                <ul>
                    <li>Student: {student['name']}</li>
                    <li>Class: {student.get('class_name', 'N/A')}</li>
                    <li>Registration No: {student['reg_no']}</li>
                    <li>Arrival Time: {arrival_time}</li>
                    <li>School Start Time: {settings.get('school_start_time', '09:00:00')}</li>
                    <li>Late By: {late_by_minutes} minutes</li>
                    <li>Date: {datetime.now().strftime('%Y-%m-%d')}</li>
                </ul>
            </div>
            
            <p>Please ensure your child arrives on time to avoid missing important lessons.</p>
            
            <p style="color: #6b7280; font-size: 0.875rem; margin-top: 30px;">
                This is an automated notification from the School Attendance System.
            </p>
        </div>
    </body>
    </html>
    """

    payload = {
        "to": student['parent_email'],
        "subject": subject,
        "html": html
    }
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": EMAIL_API_KEY
    }

    try:
        response = requests.post(EMAIL_API_URL, json=payload, headers=headers)
        if response.status_code == 200 and response.json().get("success"):
            print(f"✅ Late arrival email sent to {student['parent_email']} ({student['name']})")
        else:
            print(f"❌ Failed to send late arrival email: {response.text}")
    except Exception as e:
        print(f"❌ Email microservice error: {e}")


def send_monthly_report_email(student, report_data):
    """Send monthly attendance report via microservice API"""
    settings = SchoolSettings.get_settings()
    if not settings.get('monthly_report_email') or not settings.get('email_notifications_enabled'):
        return

    if not student.get('parent_email'):
        print(f"⚠️ No parent email for {student.get('name')}")
        return

    subject = f"Monthly Attendance Report - {student['name']}"
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; border: 2px solid #3b82f6; border-radius: 10px; padding: 20px;">
            <h2 style="color: #3b82f6;">📊 Monthly Attendance Report</h2>
            <p>Dear Parent,</p>
            <p>Here is the monthly attendance summary for <strong>{student['name']}</strong>.</p>
            <div style="background: #dbeafe; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Student Information:</strong></p>
                <ul>
                    <li>Name: {student['name']}</li>
                    <li>Class: {student['class_name']}</li>
                    <li>Registration No: {student['reg_no']}</li>
                </ul>
                <p><strong>Attendance Summary:</strong></p>
                <ul>
                    <li>Total School Days: {report_data['total_days']}</li>
                    <li>Days Present: {report_data['present_days']}</li>
                    <li>Days Absent: {report_data['absent_days']}</li>
                    <li>Late Arrivals: {report_data['late_count']}</li>
                    <li>Attendance Rate: {report_data['attendance_rate']}%</li>
                </ul>
            </div>
            <p style="color: #6b7280; font-size: 0.875rem; margin-top: 30px;">
                This is an automated monthly report from the School Attendance System.
            </p>
        </div>
    </body>
    </html>
    """

    payload = {
        "to": student['parent_email'],
        "subject": subject,
        "html": html
    }
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": EMAIL_API_KEY
    }

    try:
        response = requests.post(EMAIL_API_URL, json=payload, headers=headers)
        result = response.json()
        if response.status_code == 200 and result.get("success", False):
            print(f"✅ Monthly report sent to {student['parent_email']}")
        else:
            print(f"❌ Failed to send monthly report: {result.get('error', response.text)}")
    except Exception as e:
        print(f"❌ Error sending monthly report: {e}")


def send_absence_alert_email(student, absence_days):
    """Send alert for consecutive absences via microservice API"""
    settings = SchoolSettings.get_settings()
    if not settings.get('absence_alert_email') or not settings.get('email_notifications_enabled'):
        return

    if not student.get('parent_email'):
        print(f"⚠️ No parent email for {student.get('name')}")
        return

    subject = f"Absence Alert - {student['name']} ({absence_days} consecutive days)"
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; border: 2px solid #ef4444; border-radius: 10px; padding: 20px;">
            <h2 style="color: #ef4444;">🚨 Consecutive Absence Alert</h2>
            <p>Dear Parent,</p>
            <p>This is an urgent notification regarding <strong>{student['name']}</strong>'s attendance.</p>
            <div style="background: #fee2e2; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Alert Details:</strong></p>
                <ul>
                    <li>Student: {student['name']}</li>
                    <li>Class: {student['class_name']}</li>
                    <li>Registration No: {student['reg_no']}</li>
                    <li>Consecutive Days Absent: <strong style="color: #ef4444;">{absence_days} days</strong></li>
                    <li>Alert Date: {datetime.now().strftime('%Y-%m-%d')}</li>
                </ul>
            </div>
            <p><strong>Action Required:</strong></p>
            <p>Your child has been absent for {absence_days} consecutive days. Please contact the school immediately to inform us about the reason for absence.</p>
            <p>If this absence is due to illness or emergency, please provide appropriate documentation.</p>
            <p style="color: #6b7280; font-size: 0.875rem; margin-top: 30px;">
                This is an automated alert from the School Attendance System.
            </p>
        </div>
    </body>
    </html>
    """

    payload = {
        "to": student['parent_email'],
        "subject": subject,
        "html": html
    }
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": EMAIL_API_KEY
    }

    try:
        response = requests.post(EMAIL_API_URL, json=payload, headers=headers)
        result = response.json()
        if response.status_code == 200 and result.get("success", False):
            print(f"✅ Absence alert sent to {student['parent_email']} ({absence_days} days)")
        else:
            print(f"❌ Failed to send absence alert: {result.get('error', response.text)}")
    except Exception as e:
        print(f"❌ Error sending absence alert: {e}")

def check_consecutive_absences():
    """Check for students with consecutive absences"""
    settings = SchoolSettings.get_settings()
    alert_days = settings.get('absence_alert_days', 3)
    
    students = Student.find_all()
    today = datetime.now(IST).date()
    
    for student in students:
        # Get last N days attendance
        logs = AttendanceLog.find_by_student(
            student['reg_no'],
            start_date=(today - timedelta(days=alert_days)).isoformat(),
            end_date=today.isoformat()
        )
        
        # Check if absent for all days
        if len(logs) == 0:
            # No attendance records = consecutive absence
            send_absence_alert_email(student, alert_days)


def send_monthly_reports():
    """Send monthly reports to all students"""
    students = Student.find_all()
    
    # Get previous month data
    today = datetime.now(IST).date()
    first_day = today.replace(day=1)
    last_month_end = first_day - timedelta(days=1)
    last_month_start = last_month_end.replace(day=1)
    
    for student in students:
        # Calculate attendance for last month
        logs = AttendanceLog.find_by_student(
            student['reg_no'],
            start_date=last_month_start.isoformat(),
            end_date=last_month_end.isoformat()
        )
        
        entry_logs = [log for log in logs if log.get('action') == 'ENTRY']
        late_logs = [log for log in entry_logs if log.get('is_late')]
        
        # Calculate working days in month
        total_days = (last_month_end - last_month_start).days + 1
        present_days = len(entry_logs)
        absent_days = total_days - present_days
        attendance_rate = round((present_days / total_days * 100), 2) if total_days > 0 else 0
        
        report_data = {
            'total_days': total_days,
            'present_days': present_days,
            'absent_days': absent_days,
            'late_count': len(late_logs),
            'attendance_rate': attendance_rate,
            'month': last_month_start.strftime('%B %Y')
        }
        
        send_monthly_report_email(student, report_data)

        # ==================== School Settings API Routes ====================

@app.route('/api/settings/school', methods=['GET'])
@login_required
def get_school_settings():
    """Get school settings"""
    try:
        settings = SchoolSettings.get_settings()
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/settings/school', methods=['PUT'])
@login_required
def update_school_settings():
    """Update school settings"""
    try:
        data = request.get_json()
        
        allowed_fields = [
            'school_start_time',
            'late_threshold_minutes',
            'email_notifications_enabled',
            'late_arrival_email',
            'monthly_report_email',
            'absence_alert_days',
            'absence_alert_email',
            'monthly_report_day'
        ]
        
        updates = {k: v for k, v in data.items() if k in allowed_fields}
        
        if SchoolSettings.update_settings(updates):
            log_system_activity('SETTINGS_UPDATED', f'School settings updated', session.get('user_id'))
            return jsonify({'success': True, 'message': 'Settings updated'})
        
        return jsonify({'success': False, 'error': 'Update failed'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/notifications/test-email', methods=['POST'])
@login_required
def test_email_notification():
    """Send test email via cloud email microservice"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'}), 400
        
        subject = "Test Email - School Attendance System"
        html = """
        <html>
        <body style="font-family: Arial; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; border: 2px solid #10b981; padding: 20px; border-radius: 10px;">
                <h2 style="color: #10b981;">✅ Email Test Successful!</h2>
                <p>This is a test email from your School Attendance System.</p>
                <p>If you received this, your email notifications are configured correctly.</p>
            </div>
        </body>
        </html>
        """

        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": EMAIL_API_KEY
        }
        payload = {
            "to": email,
            "subject": subject,
            "html": html
        }
        
        response = requests.post(EMAIL_API_URL, json=payload, headers=headers)
        result = response.json()
        if response.status_code == 200 and result.get("success", False):
            return jsonify({'success': True, 'message': 'Test email sent'})
        else:
            return jsonify({'success': False, 'error': result.get('error', response.text)}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
# ==================== Scheduled Tasks ====================

def schedule_notifications():
    """Schedule periodic notification tasks"""
    import schedule
    
    try:
        settings = SchoolSettings.get_settings()
        report_day = settings.get('monthly_report_day', 1)
        
        # Check consecutive absences daily at 6 PM IST
        schedule.every().day.at("18:00").do(check_consecutive_absences)
        
        # Send monthly reports on specified day at 8 AM IST
        schedule.every().day.at("08:00").do(lambda: send_monthly_reports_if_today(report_day))
        
        print("✅ Notification scheduler started")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Sleep for 60 seconds
            
    except Exception as e:
        print(f"❌ Scheduler error: {e}")


def send_monthly_reports_if_today(report_day):
    """Send monthly reports only on the configured day"""
    today = datetime.now(IST).day
    if today == report_day:
        print(f"📊 Sending monthly reports (day {report_day})...")
        send_monthly_reports()
    else:
        print(f"⏭️ Skipping monthly reports (today: {today}, report day: {report_day})")


# Start notification scheduler in background thread
try:
    notification_thread = threading.Thread(target=schedule_notifications, daemon=True)
    notification_thread.start()
    print("✅ Background scheduler thread started")
except Exception as e:
    print(f"⚠️ Failed to start scheduler: {e}")

# ==================== DASHBOARD (Import from attached file) ====================
@app.route('/dashboard')
@login_required
def dashboard():
    """Enhanced Admin Dashboard"""
    return render_template('dashboard.html')


# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=app.config['DEBUG'],allow_unsafe_werkzeug=True)






