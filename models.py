from datetime import datetime, date, time
from bson import ObjectId
import pytz
from database import get_db

class MongoModel:
    """Base model class for MongoDB documents"""
    collection_name = None
    
    @classmethod
    def get_collection(cls):
        """Get MongoDB collection"""
        db = get_db()
        return db[cls.collection_name]
    
    @staticmethod
    def serialize_doc(doc):
        """Convert MongoDB document to JSON-serializable dict"""
        if doc is None:
            return None
        
        # Convert ObjectId to string
        if '_id' in doc:
            doc['id'] = str(doc['_id'])
            del doc['_id']
        
        # Convert datetime objects to ISO format strings
        for key, value in doc.items():
            if isinstance(value, datetime):
                doc[key] = value.isoformat()
            elif isinstance(value, date):
                doc[key] = value.isoformat()
            elif isinstance(value, time):
                doc[key] = value.strftime('%H:%M:%S')
            elif isinstance(value, ObjectId):
                doc[key] = str(value)
        
        return doc


class Student(MongoModel):
    """Student model for MongoDB"""
    collection_name = 'students'
    
    @staticmethod
    def create(rfid_uid, reg_no, name, class_name, parent_email, parent_phone=None):
        """Create a new student"""
        collection = Student.get_collection()
        
        student_doc = {
            'rfid_uid': rfid_uid,
            'reg_no': reg_no,
            'name': name,
            'class_name': class_name,
            'parent_email': parent_email,
            'parent_phone': parent_phone,
            'is_present': False,
            'entry_time': None,
            'exit_time': None,
            'last_updated': datetime.utcnow(),
            'created_at': datetime.utcnow()
        }
        
        result = collection.insert_one(student_doc)
        student_doc['_id'] = result.inserted_id
        return Student.serialize_doc(student_doc)
    
    @staticmethod
    def find_by_rfid(rfid_uid):
        """Find student by RFID UID"""
        collection = Student.get_collection()
        student = collection.find_one({'rfid_uid': rfid_uid})
        return Student.serialize_doc(student)
    
    @staticmethod
    def find_by_reg_no(reg_no):
        """Find student by registration number"""
        collection = Student.get_collection()
        student = collection.find_one({'reg_no': reg_no})
        return Student.serialize_doc(student)
    
    @staticmethod
    def find_all(filters=None):
        """Find all students with optional filters"""
        collection = Student.get_collection()
        students = collection.find(filters or {})
        return [Student.serialize_doc(s) for s in students]
    
    @staticmethod
    def update_presence(rfid_uid, is_present, entry_time=None, exit_time=None):
        """Update student presence status"""
        collection = Student.get_collection()
        
        update_data = {
            'is_present': is_present,
            'last_updated': datetime.utcnow()
        }
        
        if entry_time:
            update_data['entry_time'] = entry_time
        if exit_time:
            update_data['exit_time'] = exit_time
        
        result = collection.update_one(
            {'rfid_uid': rfid_uid},
            {'$set': update_data}
        )
        
        return result.modified_count > 0
    
    @staticmethod
    def delete_by_id(student_id):
        """Delete student by ID"""
        collection = Student.get_collection()
        result = collection.delete_one({'_id': ObjectId(student_id)})
        return result.deleted_count > 0
    
    @staticmethod
    def reset_all_presence():
        """Reset all students' presence to False (for new day)"""
        collection = Student.get_collection()
        result = collection.update_many(
            {},
            {'$set': {
                'is_present': False,
                'entry_time': None,
                'exit_time': None,
                'last_updated': datetime.utcnow()
            }}
        )
        return result.modified_count


class AttendanceLog(MongoModel):
    """Attendance log model for MongoDB"""
    collection_name = 'attendance_logs'
    
    @staticmethod
    def create(rfid_uid, reg_no, student_name, class_name, action, timestamp, log_date, is_late=False, device_info=None):
        """Create attendance log entry"""
        collection = AttendanceLog.get_collection()
        
        log_doc = {
            'rfid_uid': rfid_uid,
            'reg_no': reg_no,
            'student_name': student_name,
            'class_name': class_name,
            'action': action,  # 'ENTRY' or 'EXIT'
            'timestamp': timestamp if isinstance(timestamp, str) else timestamp.strftime('%H:%M:%S'),
            'date': log_date if isinstance(log_date, str) else log_date.isoformat(),
            'is_late': is_late,
            'device_info': device_info or {},
            'created_at': datetime.utcnow()
        }
        
        result = collection.insert_one(log_doc)
        log_doc['_id'] = result.inserted_id
        return AttendanceLog.serialize_doc(log_doc)
    
    @staticmethod
    def find_by_date(log_date):
        """Find all attendance logs for a specific date"""
        collection = AttendanceLog.get_collection()
        date_str = log_date if isinstance(log_date, str) else log_date.isoformat()
        logs = collection.find({'date': date_str}).sort('timestamp', -1)
        return [AttendanceLog.serialize_doc(log) for log in logs]
    
    @staticmethod
    def find_by_student(reg_no, start_date=None, end_date=None):
        """Find attendance logs for a specific student"""
        collection = AttendanceLog.get_collection()
        
        query = {'reg_no': reg_no}
        if start_date and end_date:
            query['date'] = {
                '$gte': start_date.isoformat() if not isinstance(start_date, str) else start_date,
                '$lte': end_date.isoformat() if not isinstance(end_date, str) else end_date
            }
        
        logs = collection.find(query).sort('date', -1)
        return [AttendanceLog.serialize_doc(log) for log in logs]
    
    @staticmethod
    def get_late_arrivals(log_date):
        """Get all late arrivals for a specific date"""
        collection = AttendanceLog.get_collection()
        date_str = log_date if isinstance(log_date, str) else log_date.isoformat()
        logs = collection.find({'date': date_str, 'is_late': True, 'action': 'ENTRY'})
        return [AttendanceLog.serialize_doc(log) for log in logs]
    
    @staticmethod
    def get_statistics(log_date):
        """Get attendance statistics for a date"""
        collection = AttendanceLog.get_collection()
        date_str = log_date if isinstance(log_date, str) else log_date.isoformat()
        
        pipeline = [
            {'$match': {'date': date_str}},
            {'$group': {
                '_id': '$action',
                'count': {'$sum': 1}
            }}
        ]
        
        results = list(collection.aggregate(pipeline))
        stats = {item['_id']: item['count'] for item in results}
        
        # Get late count
        late_count = collection.count_documents({'date': date_str, 'is_late': True})
        stats['LATE'] = late_count
        
        return stats


class UnknownCard(MongoModel):
    """Unknown RFID card log model"""
    collection_name = 'unknown_cards'
    
    @staticmethod
    def create(rfid_uid, timestamp, log_date, device_info=None):
        """Log unknown card scan"""
        collection = UnknownCard.get_collection()
        
        card_doc = {
            'rfid_uid': rfid_uid,
            'timestamp': timestamp if isinstance(timestamp, str) else timestamp.strftime('%H:%M:%S'),
            'date': log_date if isinstance(log_date, str) else log_date.isoformat(),
            'device_info': device_info or {},
            'created_at': datetime.utcnow()
        }
        
        result = collection.insert_one(card_doc)
        card_doc['_id'] = result.inserted_id
        return UnknownCard.serialize_doc(card_doc)
    
    @staticmethod
    def find_all(limit=100):
        """Get all unknown cards"""
        collection = UnknownCard.get_collection()
        cards = collection.find().sort('created_at', -1).limit(limit)
        return [UnknownCard.serialize_doc(card) for card in cards]
    
    @staticmethod
    def delete_by_id(card_id):
        """Delete unknown card entry"""
        collection = UnknownCard.get_collection()
        result = collection.delete_one({'_id': ObjectId(card_id)})
        return result.deleted_count > 0


class AdminUser(MongoModel):
    """Admin user model for authentication"""
    collection_name = 'admin_users'
    
    @staticmethod
    def create(username, email, password_hash, role='admin'):
        """Create admin user"""
        collection = AdminUser.get_collection()
        
        user_doc = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': role,
            'is_active': True,
            'created_at': datetime.utcnow(),
            'last_login': None
        }
        
        result = collection.insert_one(user_doc)
        user_doc['_id'] = result.inserted_id
        return AdminUser.serialize_doc(user_doc)
    
    @staticmethod
    def find_by_username(username):
        """Find user by username"""
        collection = AdminUser.get_collection()
        user = collection.find_one({'username': username})
        return AdminUser.serialize_doc(user)
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        collection = AdminUser.get_collection()
        user = collection.find_one({'email': email})
        return AdminUser.serialize_doc(user)
    
    @staticmethod
    def update_last_login(user_id):
        """Update user's last login time"""
        collection = AdminUser.get_collection()
        collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': datetime.utcnow()}}
        )


class ApiKey(MongoModel):
    """API key model for Arduino authentication"""
    collection_name = 'api_keys'
    
    @staticmethod
    def create(key, name='Arduino Device Key', created_by=None):
        """Create API key"""
        collection = ApiKey.get_collection()
        
        key_doc = {
            'key': key,
            'name': name,
            'created_at': datetime.utcnow(),
            'created_by': created_by,
            'is_active': True,
            'last_used': None,
            'usage_count': 0
        }
        
        result = collection.insert_one(key_doc)
        key_doc['_id'] = result.inserted_id
        return ApiKey.serialize_doc(key_doc)
    
    @staticmethod
    def validate_key(provided_key):
        """Validate API key and update usage"""
        collection = ApiKey.get_collection()
        
        key = collection.find_one({'key': provided_key, 'is_active': True})
        
        if key:
            # Update usage statistics
            collection.update_one(
                {'_id': key['_id']},
                {
                    '$set': {'last_used': datetime.utcnow()},
                    '$inc': {'usage_count': 1}
                }
            )
            return True
        return False
    
    @staticmethod
    def get_active_key():
        """Get first active API key"""
        collection = ApiKey.get_collection()
        key = collection.find_one({'is_active': True})
        return ApiKey.serialize_doc(key)
    
    @staticmethod
    def find_all():
        """Get all API keys"""
        collection = ApiKey.get_collection()
        keys = collection.find()
        return [ApiKey.serialize_doc(k) for k in keys]


class SystemLog(MongoModel):
    """System activity log model"""
    collection_name = 'system_logs'
    
    @staticmethod
    def create(action, details=None, user_id=None, ip_address=None):
        """Create system log entry"""
        collection = SystemLog.get_collection()
        
        log_doc = {
            'action': action,
            'details': details,
            'user_id': user_id,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow()
        }
        
        result = collection.insert_one(log_doc)
        return result.inserted_id
    
    @staticmethod
    def find_recent(limit=100):
        """Get recent system logs"""
        collection = SystemLog.get_collection()
        logs = collection.find().sort('timestamp', -1).limit(limit)
        return [SystemLog.serialize_doc(log) for log in logs]


class Heartbeat(MongoModel):
    """Device heartbeat model"""
    collection_name = 'heartbeats'
    
    @staticmethod
    def create(device_type, mac_address, uptime, daily_scans, wifi_rssi, timestamp):
        """Log device heartbeat"""
        collection = Heartbeat.get_collection()
        
        heartbeat_doc = {
            'device_type': device_type,
            'mac_address': mac_address,
            'uptime': uptime,
            'daily_scans': daily_scans,
            'wifi_rssi': wifi_rssi,
            'timestamp': timestamp,
            'server_timestamp': datetime.utcnow()
        }
        
        result = collection.insert_one(heartbeat_doc)
        return result.inserted_id
    
    @staticmethod
    def get_latest_by_device(mac_address):
        """Get latest heartbeat for a device"""
        collection = Heartbeat.get_collection()
        heartbeat = collection.find_one(
            {'mac_address': mac_address},
            sort=[('server_timestamp', -1)]
        )
        return Heartbeat.serialize_doc(heartbeat)


class SchoolSettings(MongoModel):
    """School configuration settings"""
    collection_name = 'school_settings'
    
    @staticmethod
    def get_settings():
        """Get current school settings"""
        collection = SchoolSettings.get_collection()
        settings = collection.find_one({})
        
        if not settings:
            # Create default settings
            default_settings = {
                'school_start_time': '09:00:00',
                'late_threshold_minutes': 15,
                'email_notifications_enabled': True,
                'late_arrival_email': True,
                'monthly_report_email': True,
                'absence_alert_days': 3,
                'absence_alert_email': True,
                'monthly_report_day': 1,  # 1st of each month
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            collection.insert_one(default_settings)
            return SchoolSettings.serialize_doc(default_settings)
        
        return SchoolSettings.serialize_doc(settings)
    
    @staticmethod
    def update_settings(updates):
        """Update school settings"""
        collection = SchoolSettings.get_collection()
        updates['updated_at'] = datetime.utcnow()
        
        result = collection.update_one(
            {},
            {'$set': updates},
            upsert=True
        )
        
        return result.modified_count > 0 or result.upserted_id is not None
