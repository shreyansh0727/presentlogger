from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from flask_mail import Mail, Message
from models import db, Student, AttendanceLog, UnknownCard
from config import Config
import schedule
import time
import threading
from datetime import datetime, date, time as dt_time
import pytz
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
CORS(app)
mail = Mail(app)

# Timezone setup
IST = pytz.timezone('Asia/Kolkata')

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
            
            # Add sample data if tables are empty
            if Student.query.count() == 0:
                add_sample_students()
                
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        print("💡 Make sure the database directory exists and is writable")

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

def get_current_time():
    """Get current time in IST"""
    return datetime.now(IST).time()

def get_current_date():
    """Get current date in IST"""
    return datetime.now(IST).date()

# API Routes

@app.route('/', methods=['GET'])
def index():
    """API Information"""
    return jsonify({
        'name': 'Arduino RFID Attendance System API',
        'version': '1.0.0',
        'description': 'REST API for IoT-based student attendance tracking',
        'status': 'active',
        'database_status': 'connected',
        'endpoints': {
            'students': '/api/students',
            'attendance': '/api/attendance/log',
            'logs': '/api/logs',
            'dashboard': '/dashboard',
            'reports': '/api/reports/daily'
        },
        'arduino_integration': 'enabled',
        'timezone': 'Asia/Kolkata'
    })

@app.route('/dashboard')
def dashboard():
    """Enhanced Admin Dashboard with Edit/Delete"""
    dashboard_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Arduino RFID Attendance System - Admin Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container { 
                max-width: 1400px; 
                margin: 0 auto; 
                background: white; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            
            .header { 
                background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
                color: white; 
                padding: 25px; 
                text-align: center;
            }
            
            .header h1 { font-size: 2.5em; margin-bottom: 10px; }
            .header p { font-size: 1.1em; opacity: 0.9; }
            
            .nav-tabs {
                display: flex;
                background: #f8f9fa;
                border-bottom: 1px solid #ddd;
                flex-wrap: wrap;
            }
            
            .nav-tab {
                flex: 1;
                min-width: 150px;
                padding: 15px;
                text-align: center;
                background: #f8f9fa;
                border: none;
                cursor: pointer;
                font-size: 16px;
                font-weight: 500;
                transition: all 0.3s;
            }
            
            .nav-tab.active {
                background: white;
                border-bottom: 3px solid #2196F3;
                color: #2196F3;
            }
            
            .nav-tab:hover {
                background: #e9ecef;
            }
            
            .tab-content {
                display: none;
                padding: 30px;
            }
            
            .tab-content.active {
                display: block;
            }
            
            .card { 
                background: white; 
                padding: 25px; 
                margin: 20px 0; 
                border: 1px solid #e0e0e0; 
                border-radius: 10px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }
            
            .card h3 {
                margin-bottom: 15px;
                color: #333;
                font-size: 1.4em;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                text-align: center;
                border-left: 4px solid #2196F3;
            }
            
            .stat-number {
                font-size: 2.5em;
                font-weight: bold;
                color: #2196F3;
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
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
            
            .form-group {
                margin-bottom: 20px;
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
                font-size: 14px;
                transition: border-color 0.3s;
            }
            
            .form-control:focus {
                outline: none;
                border-color: #2196F3;
                box-shadow: 0 0 0 3px rgba(33, 150, 243, 0.1);
            }
            
            .btn { 
                background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
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
                background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            }
            
            .btn-warning {
                background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%);
            }
            
            .btn-danger {
                background: linear-gradient(135deg, #f44336 0%, #da190b 100%);
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
            
            th, td { 
                padding: 15px 12px; 
                text-align: left; 
                border-bottom: 1px solid #e0e0e0; 
            }
            
            th { 
                background: #f8f9fa;
                font-weight: 600;
                color: #333;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 1px;
            }
            
            tr:hover {
                background: #f8f9fa;
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
            
            .loading {
                display: inline-block;
                margin-left: 10px;
            }
            
            .spinner {
                border: 2px solid #f3f3f3;
                border-top: 2px solid #2196F3;
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
            
            .arduino-config {
                background: #f0f0f0;
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                margin-top: 15px;
                border-left: 4px solid #2196F3;
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
            
            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #e0e0e0;
            }
            
            .modal-header h3 {
                margin: 0;
                color: #333;
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
            
            @media (max-width: 768px) {
                .grid-2 {
                    grid-template-columns: 1fr;
                }
                
                .stats-grid {
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
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎓 Arduino RFID Attendance System</h1>
                <p>Comprehensive Student Attendance Management Dashboard</p>
            </div>
            
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('overview')">📊 Overview</button>
                <button class="nav-tab" onclick="showTab('students')">👥 Students</button>
                <button class="nav-tab" onclick="showTab('attendance')">📝 Attendance</button>
                <button class="nav-tab" onclick="showTab('reports')">📈 Reports</button>
                <button class="nav-tab" onclick="showTab('arduino')">🔧 Arduino Setup</button>
            </div>
            
            <!-- Overview Tab -->
            <div id="overview" class="tab-content active">
                <div class="stats-grid">
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
                        <div class="stat-number" id="attendanceRate">0%</div>
                        <div class="stat-label">Attendance Rate</div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>📊 System Status</h3>
                    <p><strong>Server Status:</strong> <span class="status online">ONLINE</span></p>
                    <p><strong>Database:</strong> <span class="status online">CONNECTED</span></p>
                    <p><strong>Arduino Integration:</strong> <span class="status online">READY</span></p>
                    <p><strong>Last Updated:</strong> <span id="timestamp">Loading...</span></p>
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
                    </div>
                </div>
            </div>
            
            <!-- Attendance Tab -->
            <div id="attendance" class="tab-content">
                <div class="card">
                    <h3>📝 Recent Attendance Logs</h3>
                    <div class="form-group">
                        <label for="dateFilter">Filter by Date:</label>
                        <input type="date" class="form-control" id="dateFilter" style="width: auto; display: inline-block;">
                        <button class="btn" onclick="loadAttendanceLogs()" style="margin-left: 10px;">🔍 Filter</button>
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
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="6" style="text-align: center; padding: 40px;">
                                        <div class="spinner"></div>
                                        Loading attendance logs...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
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
                    </div>
                    
                    <div id="reportContent">
                        <p style="text-align: center; padding: 40px; color: #666;">
                            Select a date and click "Generate Report" to view attendance data
                        </p>
                    </div>
                </div>
            </div>
            
            <!-- Arduino Setup Tab -->
            <div id="arduino" class="tab-content">
                <div class="card">
                    <h3>🎯 API Endpoints for Arduino</h3>
                    <table>
                        <tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
                        <tr><td>GET</td><td>/api/student?uid=XXX</td><td>Get student by RFID UID</td></tr>
                        <tr><td>POST</td><td>/api/attendance/log</td><td>Log attendance entry/exit</td></tr>
                        <tr><td>POST</td><td>/api/attendance/unknown</td><td>Log unknown RFID card</td></tr>
                        <tr><td>GET</td><td>/api/reports/daily</td><td>Daily attendance report</td></tr>
                    </table>
                </div>
                
                <div class="card">
                    <h3>📱 Arduino Configuration</h3>
                    <p><strong>Server IP:</strong> <span id="serverIP">Getting IP...</span></p>
                    <p><strong>Port:</strong> 5000</p>
                    <p><strong>Protocol:</strong> HTTP REST API</p>
                    <p><strong>Format:</strong> JSON</p>
                    
                    <div class="arduino-config">
                        Arduino Code Configuration:<br>
                        char serverAddress[] = "<span id="configIP">192.168.1.XXX</span>";  // Your computer's IP<br>
                        int serverPort = 5000;<br><br>
                        
                        // Test connection:<br>
                        curl http://<span id="testIP">your-ip</span>:5000/api/students
                    </div>
                    
                    <button class="btn" onclick="testConnection()" style="margin-top: 15px;">🧪 Test API Connection</button>
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
                    <p style="color: #f44336; font-weight: 500;">⚠️ This action cannot be undone. All attendance records for this student will remain in the system.</p>
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
        
        <script>
            // Global variables
            let students = [];
            let attendanceLogs = [];
            let currentEditStudentId = null;
            let currentDeleteStudentId = null;
            
            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', function() {
                updateTimestamp();
                setInterval(updateTimestamp, 1000);
                loadDashboardData();
                setTodayDate();
                getServerIP();
            });
            
            // Tab switching
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
                if (tabName === 'students') {
                    loadStudents();
                } else if (tabName === 'attendance') {
                    loadAttendanceLogs();
                } else if (tabName === 'overview') {
                    loadDashboardData();
                }
            }
            
            // Update timestamp
            function updateTimestamp() {
                document.getElementById('timestamp').textContent = new Date().toLocaleString();
            }
            
            // Set today's date in date inputs
            function setTodayDate() {
                const today = new Date().toISOString().split('T')[0];
                document.getElementById('dateFilter').value = today;
                document.getElementById('reportDate').value = today;
            }
            
            // Load dashboard overview data
            async function loadDashboardData() {
                try {
                    const [studentsRes, reportRes] = await Promise.all([
                        fetch('/api/students'),
                        fetch('/api/reports/daily')
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
                    }
                } catch (error) {
                    console.error('Error loading dashboard data:', error);
                }
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
                }
            }
            
            // Display students in table
            function displayStudents() {
                const tbody = document.querySelector('#studentsTable tbody');
                
                if (students.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No students registered yet</td></tr>';
                    return;
                }
                
                tbody.innerHTML = students.map(student => `
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
            
            // Add student form submission
            document.getElementById('studentForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const loading = document.getElementById('addStudentLoading');
                const successAlert = document.getElementById('successAlert');
                const errorAlert = document.getElementById('errorAlert');
                
                // Hide alerts
                successAlert.style.display = 'none';
                errorAlert.style.display = 'none';
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
                        successAlert.textContent = '✅ Student added successfully!';
                        successAlert.style.display = 'block';
                        document.getElementById('studentForm').reset();
                        loadStudents();
                        loadDashboardData();
                    } else {
                        errorAlert.textContent = '❌ Error: ' + result.error;
                        errorAlert.style.display = 'block';
                    }
                } catch (error) {
                    errorAlert.textContent = '❌ Network error: ' + error.message;
                    errorAlert.style.display = 'block';
                } finally {
                    loading.style.display = 'none';
                }
            });
            
            // Edit student functionality
            function editStudent(studentId) {
                const student = students.find(s => s.id === studentId);
                if (!student) {
                    alert('Student not found');
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
                document.getElementById('editSuccessAlert').style.display = 'none';
                document.getElementById('editErrorAlert').style.display = 'none';
                
                // Show modal
                document.getElementById('editModal').style.display = 'block';
            }
            
            // Edit student form submission
            document.getElementById('editStudentForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const loading = document.getElementById('editStudentLoading');
                const successAlert = document.getElementById('editSuccessAlert');
                const errorAlert = document.getElementById('editErrorAlert');
                
                // Hide alerts
                successAlert.style.display = 'none';
                errorAlert.style.display = 'none';
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
                        successAlert.textContent = '✅ Student updated successfully!';
                        successAlert.style.display = 'block';
                        
                        // Close modal after 1 second
                        setTimeout(() => {
                            closeEditModal();
                            loadStudents();
                            loadDashboardData();
                        }, 1000);
                    } else {
                        errorAlert.textContent = '❌ Error: ' + result.error;
                        errorAlert.style.display = 'block';
                    }
                } catch (error) {
                    errorAlert.textContent = '❌ Network error: ' + error.message;
                    errorAlert.style.display = 'block';
                } finally {
                    loading.style.display = 'none';
                }
            });
            
            // Delete student functionality
            function deleteStudent(studentId) {
                const student = students.find(s => s.id === studentId);
                if (!student) {
                    alert('Student not found');
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
                        alert('✅ Student deleted successfully!');
                        closeDeleteModal();
                        loadStudents();
                        loadDashboardData();
                    } else {
                        alert('❌ Error: ' + result.error);
                    }
                } catch (error) {
                    alert('❌ Network error: ' + error.message);
                } finally {
                    loading.style.display = 'none';
                }
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
            
            // Close modals when clicking outside
            window.onclick = function(event) {
                const editModal = document.getElementById('editModal');
                const deleteModal = document.getElementById('deleteModal');
                
                if (event.target === editModal) {
                    closeEditModal();
                }
                
                if (event.target === deleteModal) {
                    closeDeleteModal();
                }
            }
            
            // Clear form
            function clearForm() {
                document.getElementById('studentForm').reset();
                document.getElementById('successAlert').style.display = 'none';
                document.getElementById('errorAlert').style.display = 'none';
            }
            
            // Load attendance logs
            async function loadAttendanceLogs() {
                try {
                    const dateFilter = document.getElementById('dateFilter').value;
                    const url = dateFilter ? `/api/logs?date=${dateFilter}&limit=100` : '/api/logs?limit=50';
                    
                    const response = await fetch(url);
                    const data = await response.json();
                    
                    if (data.success) {
                        displayAttendanceLogs(data.logs);
                    }
                } catch (error) {
                    console.error('Error loading attendance logs:', error);
                }
            }
            
            // Display attendance logs
            function displayAttendanceLogs(logs) {
                const tbody = document.querySelector('#attendanceTable tbody');
                
                if (logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No attendance logs found</td></tr>';
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
                    </tr>
                `).join('');
            }
            
            // Generate daily report
            async function generateDailyReport() {
                const reportDate = document.getElementById('reportDate').value;
                const reportContent = document.getElementById('reportContent');
                
                if (!reportDate) {
                    alert('Please select a date');
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
                            <div class="stats-grid" style="margin-bottom: 30px;">
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
                                    <h4 style="color: #4CAF50; margin-bottom: 15px;">✅ Present Students (${present.length})</h4>
                                    ${present.length > 0 ? `
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
                                    ` : '<p>No students were present on this date.</p>'}
                                </div>
                                
                                <div>
                                    <h4 style="color: #f44336; margin-bottom: 15px;">❌ Absent Students (${absent.length})</h4>
                                    ${absent.length > 0 ? `
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
                                    ` : '<p>All students were present on this date! 🎉</p>'}
                                </div>
                            </div>
                        `;
                    }
                } catch (error) {
                    reportContent.innerHTML = '<p style="color: red; text-align: center;">Error generating report: ' + error.message + '</p>';
                }
            }
            
            // Utility functions
            function refreshDashboard() {
                loadDashboardData();
                alert('Dashboard refreshed at ' + new Date().toLocaleString());
            }
            
            async function sendAbsentAlerts() {
                const today = new Date().toISOString().split('T')[0];
                try {
                    const response = await fetch('/api/notifications/send-absent-alerts', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ date: today })
                    });
                    const result = await response.json();
                    alert(result.success ? '✅ ' + result.message : '❌ Error: ' + result.error);
                } catch (error) {
                    alert('❌ Error sending alerts: ' + error.message);
                }
            }
            
            function exportData() {
                const today = new Date().toISOString().split('T')[0];
                window.open(`/api/reports/daily?date=${today}`, '_blank');
            }
            
            async function getServerIP() {
                try {
                    const ip = window.location.hostname;
                    document.getElementById('serverIP').textContent = ip;
                    document.getElementById('configIP').textContent = ip;
                    document.getElementById('testIP').textContent = ip;
                } catch (error) {
                    console.error('Error getting IP:', error);
                }
            }
            
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
        </script>
    </body>
    </html>
    """
    return render_template_string(dashboard_html)

@app.route('/api/students', methods=['GET', 'POST'])
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

# **NEW: UPDATE STUDENT ENDPOINT**
@app.route('/api/students/<int:student_id>', methods=['PUT'])
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

# **NEW: DELETE STUDENT ENDPOINT**
@app.route('/api/students/<int:student_id>', methods=['DELETE'])
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
def log_attendance():
    """Log attendance entry/exit - for Arduino"""
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
        
        # Create attendance log
        log = AttendanceLog(
            rfid_uid=data['rfid_uid'],
            reg_no=data['reg_no'],
            student_name=data['name'],
            class_name=data['class'],
            action=data['action'],
            timestamp=timestamp,
            date=attendance_date
        )
        
        db.session.add(log)
        
        # Update student status
        student = Student.query.filter_by(rfid_uid=data['rfid_uid']).first()
        if student:
            if data['action'] == 'ENTRY':
                student.is_present = True
                student.entry_time = timestamp
                student.exit_time = None
            elif data['action'] == 'EXIT':
                student.is_present = False
                student.exit_time = timestamp
            
            student.last_updated = datetime.utcnow()
        
        db.session.commit()
        
        print(f"✅ Attendance logged: {data['name']} - {data['action']} at {data['timestamp']}")
        
        return jsonify({
            'success': True,
            'message': f'Attendance logged: {data["action"]}',
            'student_name': data['name'],
            'action': data['action'],
            'timestamp': data['timestamp']
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error logging attendance: {e}")
        return jsonify({
            'success': False,
            'error': f'Error logging attendance: {str(e)}'
        }), 400

@app.route('/api/attendance/unknown', methods=['POST'])
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
        
        print(f"⚠️  Unknown card logged: {data['rfid_uid']}")
        
        return jsonify({
            'success': True,
            'message': 'Unknown card logged',
            'rfid_uid': data['rfid_uid']
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Error logging unknown card: {str(e)}'
        }), 400

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get attendance logs with filtering"""
    try:
        date_filter = request.args.get('date')
        student_id = request.args.get('student_id')
        limit = int(request.args.get('limit', 50))
        
        query = AttendanceLog.query
        
        if date_filter:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(AttendanceLog.date == filter_date)
        
        if student_id:
            query = query.filter(AttendanceLog.reg_no == student_id)
        
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

@app.route('/api/reports/daily', methods=['GET'])
def daily_report():
    """Get daily attendance report"""
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
                    'total_exits': len(exit_logs)
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
                'attendance_rate': round((len(present_students) / len(all_students)) * 100, 2) if all_students else 0
            },
            'present_students': present_students,
            'absent_students': absent_students
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error generating report: {str(e)}'
        }), 500

@app.route('/api/notifications/send-absent-alerts', methods=['POST'])
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
                    subject=f'Attendance Alert - {student.name}',
                    recipients=[student.parent_email],
                    body=f"""Dear Parent,

This is to inform you that your child {student.name} (Registration: {student.reg_no}) from class {student.class_name} was absent from school today ({report_date}).

If your child was present, please contact the school administration.

Best regards,
Arduino RFID Attendance System
School Administration
"""
                )
                mail.send(msg)
                sent_count += 1
                
            except Exception as email_error:
                errors.append(f"Failed to send to {student.parent_email}: {str(email_error)}")
                print(f"❌ Email error: {email_error}")
        
        return jsonify({
            'success': True,
            'message': f'Absent alerts processed for {len(absent_students)} students',
            'total_absent': len(absent_students),
            'emails_sent': sent_count,
            'errors': errors if errors else None
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error sending alerts: {str(e)}'
        }), 400

if __name__ == '__main__':
    print("🚀 Starting Arduino RFID Attendance System...")
    print("📍 Dashboard: http://localhost:5000/dashboard")
    print("🔌 Arduino endpoint: http://your-ip:5000")
    
    create_tables()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
