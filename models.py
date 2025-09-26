from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import pytz

db = SQLAlchemy()

class Student(db.Model):
    __tablename__ = 'students'
    
    id = db.Column(db.Integer, primary_key=True)
    rfid_uid = db.Column(db.String(20), unique=True, nullable=False, index=True)
    reg_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(20), nullable=False)
    parent_email = db.Column(db.String(100), nullable=False)
    parent_phone = db.Column(db.String(15), nullable=True)
    is_present = db.Column(db.Boolean, default=False)
    entry_time = db.Column(db.Time, nullable=True)
    exit_time = db.Column(db.Time, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rfid_uid': self.rfid_uid,
            'reg_no': self.reg_no,
            'name': self.name,
            'class': self.class_name,
            'parent_email': self.parent_email,
            'parent_phone': self.parent_phone,
            'is_present': self.is_present,
            'entry_time': self.entry_time.strftime('%H:%M:%S') if self.entry_time else None,
            'exit_time': self.exit_time.strftime('%H:%M:%S') if self.exit_time else None,
            'last_updated': self.last_updated.isoformat()
        }

class AttendanceLog(db.Model):
    __tablename__ = 'attendance_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    rfid_uid = db.Column(db.String(20), nullable=False, index=True)
    reg_no = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(20), nullable=False)
    action = db.Column(db.Enum('ENTRY', 'EXIT', 'UNKNOWN', name='attendance_actions'), nullable=False)
    timestamp = db.Column(db.Time, nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_late = db.Column(db.Boolean, default=False, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rfid_uid': self.rfid_uid,
            'reg_no': self.reg_no,
            'student_name': self.student_name,
            'class': self.class_name,
            'action': self.action,
            'timestamp': self.timestamp.strftime('%H:%M:%S'),
            'date': self.date.strftime('%Y-%m-%d'),
            'created_at': self.created_at.isoformat()
        }

class UnknownCard(db.Model):
    __tablename__ = 'unknown_cards'
    
    id = db.Column(db.Integer, primary_key=True)
    rfid_uid = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.Time, nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rfid_uid': self.rfid_uid,
            'timestamp': self.timestamp.strftime('%H:%M:%S'),
            'date': self.date.strftime('%Y-%m-%d'),
            'created_at': self.created_at.isoformat()
        }

# Add these to your models.py file

class AdminUser(db.Model):
    """Admin user model for authentication"""
    __tablename__ = 'admin_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SystemLog(db.Model):
    """System activity logs"""
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class ApiKey(db.Model):
    """API Key model for Arduino authentication"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), default='Arduino Device Key')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': f"{self.key[:8]}{'*' * (len(self.key) - 8)}",  # Masked key
            'name': self.name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count
        }
    
    def __repr__(self):
        return f'<ApiKey {self.key[:8]}...>'

    @staticmethod
    def get_active_key():
        """Get the current active API key"""
        return ApiKey.query.filter_by(is_active=True).first()
    
    @staticmethod
    def validate_key(provided_key):
        """Validate if provided key is valid and active"""
        key = ApiKey.query.filter_by(key=provided_key, is_active=True).first()
        if key:
            # Update usage statistics
            key.last_used = datetime.utcnow()
            key.usage_count += 1
            db.session.commit()
            return True
        return False
# Update AttendanceLog model to include late arrival tracking
# Add this field to your existing AttendanceLog model:
# is_late = db.Column(db.Boolean, default=False)

