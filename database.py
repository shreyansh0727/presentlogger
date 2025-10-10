"""
MongoDB Database Connection and Management Module
Handles MongoDB connection, initialization, indexes, and utilities
"""

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import (
    ServerSelectionTimeoutError, 
    ConnectionFailure, 
    OperationFailure,
    DuplicateKeyError
)
from flask import current_app, g
import logging
from datetime import datetime, timedelta
import os

class MongoDB:
    """MongoDB connection manager with pooling and error handling"""
    
    client = None
    db = None
    _initialized = False
    
    @staticmethod
    def init_app(app):
        """
        Initialize MongoDB connection with Flask app context
        
        Args:
            app: Flask application instance
            
        Returns:
            MongoDB database instance
            
        Raises:
            Exception: If connection fails
        """
        try:
            # Get configuration
            mongodb_uri = app.config.get('MONGODB_URI')
            db_name = app.config.get('MONGODB_DB_NAME')
            
            if not mongodb_uri:
                raise ValueError("MONGODB_URI not configured in app config")
            
            if not db_name:
                raise ValueError("MONGODB_DB_NAME not configured in app config")
            
            app.logger.info(f"🔗 Connecting to MongoDB...")
            app.logger.info(f"📦 Database: {db_name}")
            
            # Create MongoDB client with connection pooling
            MongoDB.client = MongoClient(
                mongodb_uri,
                serverSelectionTimeoutMS=5000,      # 5 second timeout for server selection
                socketTimeoutMS=45000,              # 45 second socket timeout
                connectTimeoutMS=10000,             # 10 second connection timeout
                maxPoolSize=50,                     # Maximum 50 connections in pool
                minPoolSize=10,                     # Minimum 10 connections in pool
                maxIdleTimeMS=45000,                # Close idle connections after 45s
                retryWrites=True,                   # Retry writes on network errors
                retryReads=True,                    # Retry reads on network errors
                w='majority',                       # Write concern: majority
                journal=True,                       # Wait for journal confirmation
                appName='AttendanceSystem',         # Application name for monitoring
            )
            
            # Test connection
            MongoDB.client.server_info()
            app.logger.info("✅ MongoDB connection successful")
            
            # Get database
            MongoDB.db = MongoDB.client[db_name]
            
            # Verify database access
            MongoDB.db.command('ping')
            app.logger.info(f"✅ Database '{db_name}' accessible")
            
            # Create indexes
            MongoDB.create_indexes(app)
            
            # Set up connection cleanup on app teardown
            @app.teardown_appcontext
            def cleanup_db(exception=None):
                """Clean up database connections on app context teardown"""
                if exception:
                    app.logger.error(f"Error during app context: {exception}")
            
            MongoDB._initialized = True
            app.logger.info("✅ MongoDB initialization complete")
            
            return MongoDB.db
            
        except ServerSelectionTimeoutError as e:
            app.logger.error(f"❌ MongoDB server selection timeout: {str(e)}")
            app.logger.error("   Check if MongoDB server is running and accessible")
            raise Exception("MongoDB server not reachable") from e
            
        except ConnectionFailure as e:
            app.logger.error(f"❌ MongoDB connection failed: {str(e)}")
            app.logger.error("   Check MongoDB URI and network connectivity")
            raise Exception("Failed to connect to MongoDB") from e
            
        except OperationFailure as e:
            app.logger.error(f"❌ MongoDB operation failed: {str(e)}")
            app.logger.error("   Check MongoDB credentials and permissions")
            raise Exception("MongoDB authentication failed") from e
            
        except Exception as e:
            app.logger.error(f"❌ Unexpected error during MongoDB initialization: {str(e)}")
            raise
    
    @staticmethod
    def create_indexes(app):
        """
        Create database indexes for optimal query performance
        
        Args:
            app: Flask application instance for logging
        """
        try:
            db = MongoDB.db
            app.logger.info("📊 Creating database indexes...")
            
            # ==================== STUDENTS COLLECTION ====================
            app.logger.info("   Creating indexes for 'students' collection...")
            
            # Unique index on RFID UID (primary lookup field)
            db.students.create_index(
                [("rfid_uid", ASCENDING)],
                unique=True,
                name="idx_rfid_uid_unique"
            )
            
            # Unique index on registration number
            db.students.create_index(
                [("reg_no", ASCENDING)],
                unique=True,
                name="idx_reg_no_unique"
            )
            
            # Index on email for quick parent contact lookup
            db.students.create_index(
                [("parent_email", ASCENDING)],
                name="idx_parent_email"
            )
            
            # Compound index for class-based queries
            db.students.create_index(
                [("class_name", ASCENDING), ("name", ASCENDING)],
                name="idx_class_name"
            )
            
            # Index on presence status for quick attendance checks
            db.students.create_index(
                [("is_present", ASCENDING)],
                name="idx_is_present"
            )
            
            app.logger.info("   ✅ Students indexes created")
            
            # ==================== ATTENDANCE LOGS COLLECTION ====================
            app.logger.info("   Creating indexes for 'attendance_logs' collection...")
            
            # Compound index for date-based queries (most common)
            db.attendance_logs.create_index(
                [("date", DESCENDING), ("timestamp", DESCENDING)],
                name="idx_date_timestamp"
            )
            
            # Index on RFID UID for student attendance history
            db.attendance_logs.create_index(
                [("rfid_uid", ASCENDING)],
                name="idx_rfid_uid"
            )
            
            # Index on registration number
            db.attendance_logs.create_index(
                [("reg_no", ASCENDING)],
                name="idx_reg_no"
            )
            
            # Index on action type (ENTRY/EXIT)
            db.attendance_logs.create_index(
                [("action", ASCENDING)],
                name="idx_action"
            )
            
            # Compound index for late arrival queries
            db.attendance_logs.create_index(
                [("date", DESCENDING), ("is_late", ASCENDING)],
                name="idx_date_late"
            )
            
            # Compound index for class-based reports
            db.attendance_logs.create_index(
                [("class_name", ASCENDING), ("date", DESCENDING)],
                name="idx_class_date"
            )
            
            # Index on created_at for audit trails
            db.attendance_logs.create_index(
                [("created_at", DESCENDING)],
                name="idx_created_at"
            )
            
            app.logger.info("   ✅ Attendance logs indexes created")
            
            # ==================== UNKNOWN CARDS COLLECTION ====================
            app.logger.info("   Creating indexes for 'unknown_cards' collection...")
            
            # Index on RFID UID for unknown card tracking
            db.unknown_cards.create_index(
                [("rfid_uid", ASCENDING)],
                name="idx_rfid_uid"
            )
            
            # Compound index for date-based queries
            db.unknown_cards.create_index(
                [("date", DESCENDING), ("timestamp", DESCENDING)],
                name="idx_date_timestamp"
            )
            
            # Index on created_at for recent unknown cards
            db.unknown_cards.create_index(
                [("created_at", DESCENDING)],
                name="idx_created_at"
            )
            
            app.logger.info("   ✅ Unknown cards indexes created")
            
            # ==================== ADMIN USERS COLLECTION ====================
            app.logger.info("   Creating indexes for 'admin_users' collection...")
            
            # Unique index on username
            db.admin_users.create_index(
                [("username", ASCENDING)],
                unique=True,
                name="idx_username_unique"
            )
            
            # Unique index on email
            db.admin_users.create_index(
                [("email", ASCENDING)],
                unique=True,
                name="idx_email_unique"
            )
            
            # Index on active status
            db.admin_users.create_index(
                [("is_active", ASCENDING)],
                name="idx_is_active"
            )
            
            app.logger.info("   ✅ Admin users indexes created")
            
            # ==================== API KEYS COLLECTION ====================
            app.logger.info("   Creating indexes for 'api_keys' collection...")
            
            # Unique index on API key (for fast validation)
            db.api_keys.create_index(
                [("key", ASCENDING)],
                unique=True,
                name="idx_key_unique"
            )
            
            # Compound index for active key lookup
            db.api_keys.create_index(
                [("is_active", ASCENDING), ("key", ASCENDING)],
                name="idx_active_key"
            )
            
            # Index on last used for monitoring
            db.api_keys.create_index(
                [("last_used", DESCENDING)],
                name="idx_last_used"
            )
            
            app.logger.info("   ✅ API keys indexes created")
            
            # ==================== SYSTEM LOGS COLLECTION ====================
            app.logger.info("   Creating indexes for 'system_logs' collection...")
            
            # Index on timestamp for recent logs
            db.system_logs.create_index(
                [("timestamp", DESCENDING)],
                name="idx_timestamp"
            )
            
            # Index on action type for filtering
            db.system_logs.create_index(
                [("action", ASCENDING)],
                name="idx_action"
            )
            
            # Index on user_id for user activity tracking
            db.system_logs.create_index(
                [("user_id", ASCENDING)],
                name="idx_user_id"
            )
            
            app.logger.info("   ✅ System logs indexes created")
            
            # ==================== HEARTBEATS COLLECTION ====================
            app.logger.info("   Creating indexes for 'heartbeats' collection...")
            
            # Index on MAC address for device tracking
            db.heartbeats.create_index(
                [("mac_address", ASCENDING)],
                name="idx_mac_address"
            )
            
            # Index on server timestamp (with TTL for auto-cleanup)
            db.heartbeats.create_index(
                [("server_timestamp", DESCENDING)],
                expireAfterSeconds=604800,  # Auto-delete after 7 days
                name="idx_server_timestamp_ttl"
            )
            
            # Compound index for latest device status
            db.heartbeats.create_index(
                [("mac_address", ASCENDING), ("server_timestamp", DESCENDING)],
                name="idx_mac_timestamp"
            )
            
            app.logger.info("   ✅ Heartbeats indexes created (with 7-day TTL)")
            
            app.logger.info("✅ All database indexes created successfully")
            
        except DuplicateKeyError as e:
            app.logger.warning(f"⚠️  Index already exists: {e}")
        except Exception as e:
            app.logger.error(f"❌ Error creating indexes: {str(e)}")
            raise
    
    @staticmethod
    def get_db():
        """
        Get database instance (Flask g context aware)
        
        Returns:
            MongoDB database instance
            
        Raises:
            Exception: If MongoDB not initialized
        """
        if MongoDB.db is None:
            raise Exception("MongoDB not initialized. Call init_app() first.")
        return MongoDB.db
    
    @staticmethod
    def close_connection():
        """Close MongoDB connection and cleanup resources"""
        if MongoDB.client:
            try:
                MongoDB.client.close()
                logging.info("✅ MongoDB connection closed successfully")
                MongoDB.client = None
                MongoDB.db = None
                MongoDB._initialized = False
            except Exception as e:
                logging.error(f"❌ Error closing MongoDB connection: {str(e)}")
    
    @staticmethod
    def health_check():
        """
        Check MongoDB connection health
        
        Returns:
            dict: Health status information
        """
        try:
            if MongoDB.db is None:
                return {
                    'status': 'disconnected',
                    'healthy': False,
                    'message': 'Database not initialized'
                }
            
            # Ping database
            start_time = datetime.now()
            MongoDB.db.command('ping')
            latency = (datetime.now() - start_time).total_seconds() * 1000
            
            # Get server info
            server_info = MongoDB.client.server_info()
            
            # Get database stats
            db_stats = MongoDB.db.command('dbStats')
            
            return {
                'status': 'connected',
                'healthy': True,
                'latency_ms': round(latency, 2),
                'server_version': server_info.get('version'),
                'database_name': MongoDB.db.name,
                'collections_count': len(MongoDB.db.list_collection_names()),
                'data_size_mb': round(db_stats.get('dataSize', 0) / (1024 * 1024), 2),
                'storage_size_mb': round(db_stats.get('storageSize', 0) / (1024 * 1024), 2),
                'indexes_count': db_stats.get('indexes', 0)
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'healthy': False,
                'error': str(e)
            }
    
    @staticmethod
    def get_collection_stats():
        """
        Get statistics for all collections
        
        Returns:
            dict: Collection statistics
        """
        try:
            stats = {}
            collections = ['students', 'attendance_logs', 'unknown_cards', 
                          'admin_users', 'api_keys', 'system_logs', 'heartbeats']
            
            for collection_name in collections:
                collection = MongoDB.db[collection_name]
                stats[collection_name] = {
                    'document_count': collection.count_documents({}),
                    'indexes': len(collection.index_information()),
                    'size_mb': round(
                        MongoDB.db.command('collStats', collection_name).get('size', 0) / (1024 * 1024),
                        2
                    )
                }
            
            return stats
            
        except Exception as e:
            logging.error(f"Error getting collection stats: {str(e)}")
            return {}
    
    @staticmethod
    def backup_collections(backup_dir='backups'):
        """
        Create JSON backup of all collections
        
        Args:
            backup_dir: Directory to store backups
            
        Returns:
            str: Backup file path or None on error
        """
        try:
            import json
            from bson import ObjectId
            
            # Create backup directory if it doesn't exist
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(backup_dir, f'backup_{timestamp}.json')
            
            backup_data = {}
            collections = ['students', 'attendance_logs', 'unknown_cards', 
                          'admin_users', 'api_keys', 'system_logs']
            
            for collection_name in collections:
                collection = MongoDB.db[collection_name]
                documents = list(collection.find())
                
                # Convert ObjectId to string for JSON serialization
                for doc in documents:
                    if '_id' in doc:
                        doc['_id'] = str(doc['_id'])
                
                backup_data[collection_name] = documents
            
            # Write backup file
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            logging.info(f"✅ Backup created: {backup_file}")
            return backup_file
            
        except Exception as e:
            logging.error(f"❌ Backup failed: {str(e)}")
            return None


# Helper function for easy database access
def get_db():
    """
    Get MongoDB database instance
    
    Returns:
        MongoDB database instance
    """
    return MongoDB.get_db()


# Context manager for database operations
class db_context:
    """Context manager for database operations with error handling"""
    
    def __enter__(self):
        self.db = MongoDB.get_db()
        return self.db
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logging.error(f"Database operation error: {exc_val}")
        return False  # Don't suppress exceptions


# Utility functions
def create_test_data():
    """Create test data for development (DO NOT USE IN PRODUCTION)"""
    try:
        from models import Student, AdminUser
        import secrets
        
        # Create test students
        test_students = [
            {
                'rfid_uid': 'AA:BB:CC:DD:EE:01',
                'reg_no': 'STU001',
                'name': 'Test Student 1',
                'class_name': 'Class 10A',
                'parent_email': 'parent1@test.com'
            },
            {
                'rfid_uid': 'AA:BB:CC:DD:EE:02',
                'reg_no': 'STU002',
                'name': 'Test Student 2',
                'class_name': 'Class 10B',
                'parent_email': 'parent2@test.com'
            }
        ]
        
        for student_data in test_students:
            try:
                Student.create(**student_data)
                logging.info(f"✅ Created test student: {student_data['name']}")
            except:
                logging.info(f"   Student already exists: {student_data['name']}")
        
        logging.info("✅ Test data created successfully")
        
    except Exception as e:
        logging.error(f"❌ Error creating test data: {str(e)}")


def reset_daily_attendance():
    """Reset all student presence status (run at midnight)"""
    try:
        from models import Student
        
        count = Student.reset_all_presence()
        logging.info(f"✅ Reset presence for {count} students")
        return count
        
    except Exception as e:
        logging.error(f"❌ Error resetting daily attendance: {str(e)}")
        return 0
