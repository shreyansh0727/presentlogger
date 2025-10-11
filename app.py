import os
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_file,render_template
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit
from config import config
from database import MongoDB, get_db
from models import (Student, AttendanceLog, UnknownCard, AdminUser, 
                   ApiKey, SystemLog, Heartbeat)
from datetime import datetime, date, time as dt_time, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
from dotenv import load_dotenv
load_dotenv()
# ==================== APP INITIALIZATION ====================

def create_app(config_name=None):
    """Application factory"""
    app = Flask(__name__)
    
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    MongoDB.init_app(app)
    
    CORS(app, origins='*', supports_credentials=True)
    mail = Mail(app)
    
    # Initialize SocketIO - THREADING MODE (no gevent)
    socketio = SocketIO(
        app, 
        cors_allowed_origins='*',
        async_mode='threading',  # Use threading instead of gevent
        logger=False,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25
    )
    
    app.mail = mail
    app.socketio = socketio
    
    return app, socketio

app, socketio = create_app()
mail = app.mail

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
        
        # Check MongoDB API keys
        if api_key and ApiKey.validate_key(api_key):
            return f(*args, **kwargs)
        
        # FALLBACK: Check config VALID_API_KEYS (for Arduino compatibility)
        if api_key and api_key in app.config['API_KEYS']:
            return f(*args, **kwargs)
        
        return jsonify({'success': False, 'error': 'Invalid or missing API key'}), 401
    
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
@app.route('/')
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
        
        timestamp = datetime.strptime(data['timestamp'], '%H:%M:%S').time()
        is_late = False
        
        if data['action'] == 'ENTRY':
            late_time = datetime.strptime(app.config['LATE_ARRIVAL_TIME'], '%H:%M:%S').time()
            is_late = timestamp > late_time
        
        log = AttendanceLog.create(data['rfid_uid'], data['reg_no'], data['name'], 
                                   data['class'], data['action'], data['timestamp'], 
                                   data['date'], is_late, data.get('device_info', {}))
        
        if data['action'] == 'ENTRY':
            Student.update_presence(data['rfid_uid'], True, entry_time=timestamp)
        elif data['action'] == 'EXIT':
            Student.update_presence(data['rfid_uid'], False, exit_time=timestamp)
        
        socketio.emit('attendance_update', {
            'student_name': data['name'],
            'action': data['action'],
            'timestamp': data['timestamp'],
            'is_late': is_late
        })
        
        log_system_activity('ATTENDANCE_LOGGED', f"{data['name']} - {data['action']}", None)
        
        return jsonify({
            'success': True,
            'message': f'Attendance logged: {data["action"]}',
            'is_late': is_late
        })
    except Exception as e:
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
        # DEACTIVATE ALL OLD KEYS FIRST
        collection = ApiKey.get_collection()
        collection.update_many(
            {'is_active': True},
            {'$set': {'is_active': False, 'deactivated_at': datetime.utcnow()}}
        )
        
        # Generate new key
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
<html>
<head>
    <title>Login - Attendance System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 400px;
            width: 100%;
        }
        h1 { color: #667eea; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        input:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        }
        .error { color: #f44336; background: #ffebee; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .info { margin-top: 20px; padding: 15px; background: #e3f2fd; border-radius: 8px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Admin Login</h1>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="info">
            <strong>Default:</strong><br>
            Username: <code>admin</code><br>
            Password: <code>admin123</code>
        </div>
    </div>
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

# ==================== DASHBOARD (Import from attached file) ====================
@app.route('/dashboard')
@login_required
def dashboard():
    """Enhanced Admin Dashboard"""
    return render_template('dashboard.html')


# ==================== RUN APPLICATION ====================


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # Run with Flask-SocketIO's built-in server
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=False,
        use_reloader=False,
        log_output=True,
        allow_unsafe_werkzeug=True
    )
