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
