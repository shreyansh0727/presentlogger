import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration class"""
    
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_DIR = os.path.join(BASE_DIR, 'database')
    
    # Create database directory if it doesn't exist
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hdgfygffuyf673773')
    
    # ==================== DATABASE CONFIGURATION ====================
    
    # MongoDB Configuration - READ FROM ENVIRONMENT IN PRODUCTION
    MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME', 'attendance')
    
    # MongoDB Connection Settings
    MONGODB_SETTINGS = {
        'host': MONGODB_URI,
        'db': MONGODB_DB_NAME,
        'connect': True,
        'serverSelectionTimeoutMS': 5000,
        'socketTimeoutMS': 45000,
        'maxPoolSize': 50,
        'minPoolSize': 10,
        'retryWrites': True,
        'w': 'majority'
    }
    
    # Database Mode Selection
    USE_MONGODB = os.environ.get('USE_MONGODB', 'true').lower() == 'true'
    
    # ==================== EMAIL CONFIGURATION ====================
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER', 'thepotterypatch.shop@gmail.com')
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS', 'tsuaacddqsztpibx')
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER', 'thepotterypatch.shop@gmail.com')
    
    # ==================== TIMEZONE & TIME SETTINGS ====================
    TIMEZONE = 'Asia/Kolkata'
    LATE_ARRIVAL_TIME = os.environ.get('LATE_ARRIVAL_TIME', '09:00:00')
    
    # ==================== ARDUINO/IoT DEVICE SETTINGS ====================
    ARDUINO_TIMEOUT = 30
    HEARTBEAT_INTERVAL = 30
    MAX_HEARTBEAT_MISS = 3
    
    # ==================== API SECURITY ====================
    API_KEY_HEADER = 'X-API-Key'
    API_KEYS_STRING = os.environ.get('API_KEYS', 'EUVAP9gi-c2N5giBzpg_CcUQ70UWb4Vf6zk4NMlz9V4')
    VALID_API_KEYS = [key.strip() for key in API_KEYS_STRING.split(',') if key.strip()]
    
    # ==================== SESSION CONFIGURATION ====================
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_TYPE = 'filesystem'
    
    # ==================== CORS SETTINGS ====================
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization', 'X-API-Key']
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    
    # ==================== FILE UPLOAD SETTINGS ====================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}
    
    # ==================== PAGINATION ====================
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', 50))
    MAX_ITEMS_PER_PAGE = 200
    
    # ==================== LOGGING ====================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'attendance.log')
    LOG_MAX_BYTES = 10 * 1024 * 1024
    LOG_BACKUP_COUNT = 10
    
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    # ==================== RENDER.COM SETTINGS ====================
    PORT = int(os.environ.get('PORT', 5000))
    IS_RENDER = os.environ.get('RENDER') == 'true'
    
    # ==================== RATE LIMITING ====================
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'false').lower() == 'true'
    RATELIMIT_DEFAULT = '200 per day, 50 per hour'
    
    # ==================== NOTIFICATION SETTINGS ====================
    ENABLE_EMAIL_NOTIFICATIONS = os.environ.get('ENABLE_EMAIL_NOTIFICATIONS', 'false').lower() == 'true'
    NOTIFY_ON_LATE_ARRIVAL = True
    NOTIFY_ON_UNKNOWN_CARD = True
    NOTIFY_PARENTS_ON_ENTRY = False
    NOTIFY_PARENTS_ON_EXIT = False
    
    # ==================== ADMIN SETTINGS ====================
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@school.com')
    SCHOOL_NAME = os.environ.get('SCHOOL_NAME', 'RFID Attendance System')
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration"""
        env = os.environ.get('FLASK_ENV', 'development')
        print("\n" + "="*60)
        print(f"🚀 Starting Attendance System - {env.upper()} Mode")
        print("="*60)
        
        if Config.USE_MONGODB:
            print("✅ Database: MongoDB")
            mongo_status = "✅ Configured" if os.environ.get('MONGODB_URI') else "⚠️ Using localhost"
            print(f"✅ MongoDB: {mongo_status}")
        
        print(f"🌍 Timezone: {Config.TIMEZONE}")
        print(f"⏰ Late cutoff: {Config.LATE_ARRIVAL_TIME}")
        print(f"🔑 API keys: {len(Config.VALID_API_KEYS)}")
        print(f"📧 Email: {'Enabled' if Config.ENABLE_EMAIL_NOTIFICATIONS else 'Disabled'}")
        print("="*60 + "\n")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        print("🔧 Development mode: Debug enabled")


class ProductionConfig(Config):
    """Production configuration for Render deployment"""
    DEBUG = False
    TESTING = False
    USE_MONGODB = True
    
    # Production security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PREFERRED_URL_SCHEME = 'https'
    RATELIMIT_ENABLED = True
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        
        # Ensure MongoDB URI is set
        if not os.environ.get('MONGODB_URI'):
            print("❌ ERROR: MONGODB_URI not set in environment!")
            raise ValueError("MONGODB_URI environment variable must be set in production!")
        
        # Production logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            # File handler
            try:
                file_handler = RotatingFileHandler(
                    Config.LOG_FILE,
                    maxBytes=Config.LOG_MAX_BYTES,
                    backupCount=Config.LOG_BACKUP_COUNT
                )
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s %(levelname)s: %(message)s [%(pathname)s:%(lineno)d]'
                ))
                file_handler.setLevel(logging.INFO)
                app.logger.addHandler(file_handler)
                app.logger.setLevel(logging.INFO)
                app.logger.info('🚀 Production startup successful')
            except Exception as e:
                print(f"⚠️ Could not set up file logging: {e}")
        
        print("✅ Production mode initialized")


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    WTF_CSRF_ENABLED = False
    MONGODB_DB_NAME = 'attendance_test'
    ENABLE_EMAIL_NOTIFICATIONS = False
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        print("🧪 Testing mode enabled")


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Get configuration object by name"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    return config.get(config_name, config['default'])
