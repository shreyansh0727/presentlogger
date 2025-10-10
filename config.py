import os
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()
class Config:
    """Base configuration class"""
    
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_DIR = os.path.join(BASE_DIR, 'database')
    
    # Create database directory if it doesn't exist (for SQLite fallback)
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)
        print(f"✅ Created database directory: {DATABASE_DIR}")
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hdgfygffuyf673773'
    
    # ==================== DATABASE CONFIGURATION ====================
    
    # MongoDB Configuration (Primary for production)
    MONGODB_URI = 'mongodb+srv://shreyanshm90051_db_user:3UJXot9assv0FTM2@attendance.uuztefq.mongodb.net/?retryWrites=true&w=majority&appName=attendance'
    MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME') or 'attendance'
    
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
    
    # SQLAlchemy Configuration (Fallback for local development)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                             f'sqlite:///{os.path.join(DATABASE_DIR, "attendance.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database Mode Selection
    USE_MONGODB = os.environ.get('USE_MONGODB', 'true').lower() == 'true'
    
    # ==================== EMAIL CONFIGURATION ====================
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER') or 'thepotterypatch.shop@gmail.com'
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS') or 'tsuaacddqsztpibx'
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER') or 'thepotterypatch.shop@gmail.com'
    
    # ==================== TIMEZONE & TIME SETTINGS ====================
    TIMEZONE = 'Asia/Kolkata'
    LATE_ARRIVAL_TIME = os.environ.get('LATE_ARRIVAL_TIME', '09:00:00')  # HH:MM:SS format
    
    # ==================== ARDUINO/IoT DEVICE SETTINGS ====================
    ARDUINO_TIMEOUT = 30  # seconds before device is considered offline
    HEARTBEAT_INTERVAL = 30  # Expected heartbeat interval from Arduino
    MAX_HEARTBEAT_MISS = 3  # Number of missed heartbeats before alert
    
    # ==================== API SECURITY ====================
    API_KEY_HEADER = 'X-API-Key'
    
    # Multiple API keys support (comma-separated in environment)
    API_KEYS_STRING = os.environ.get('API_KEYS', 'EUVAP9gi-c2N5giBzpg_CcUQ70UWb4Vf6zk4NMlz9V4')
    VALID_API_KEYS = [key.strip() for key in API_KEYS_STRING.split(',') if key.strip()]
    
    # ==================== SESSION CONFIGURATION ====================
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_TYPE = 'filesystem'  # or 'mongodb' for production
    
    # ==================== CORS SETTINGS ====================
    CORS_ORIGINS = '*'
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization', 'X-API-Key']
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    
    # ==================== FILE UPLOAD SETTINGS ====================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}
    
    # ==================== PAGINATION ====================
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', 50))
    MAX_ITEMS_PER_PAGE = 200
    
    # ==================== LOGGING ====================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'attendance.log')
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 10
    
    # Create logs directory
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print(f"✅ Created logs directory: {LOG_DIR}")
    
    # ==================== RENDER.COM SETTINGS ====================
    PORT = int(os.environ.get('PORT', 5000))
    IS_RENDER = os.environ.get('RENDER') == 'true'
    
    # ==================== RATE LIMITING ====================
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'false').lower() == 'true'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200 per day, 50 per hour')
    RATELIMIT_STORAGE_URL = MONGODB_URI if USE_MONGODB else 'memory://'
    
    # ==================== NOTIFICATION SETTINGS ====================
    ENABLE_EMAIL_NOTIFICATIONS = os.environ.get('ENABLE_EMAIL_NOTIFICATIONS', 'true').lower() == 'true'
    NOTIFY_ON_LATE_ARRIVAL = True
    NOTIFY_ON_UNKNOWN_CARD = True
    NOTIFY_PARENTS_ON_ENTRY = os.environ.get('NOTIFY_PARENTS_ON_ENTRY', 'false').lower() == 'true'
    NOTIFY_PARENTS_ON_EXIT = os.environ.get('NOTIFY_PARENTS_ON_EXIT', 'false').lower() == 'true'
    
    # ==================== CACHE SETTINGS ====================
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')  # simple, redis, memcached
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # ==================== ADMIN SETTINGS ====================
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@school.com')
    SCHOOL_NAME = os.environ.get('SCHOOL_NAME', 'My School')
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration"""
        # Print startup configuration
        env = os.environ.get('FLASK_ENV', 'development')
        print("\n" + "="*60)
        print(f"🚀 Starting Attendance System - {env.upper()} Mode")
        print("="*60)
        
        if Config.USE_MONGODB:
            print("✅ Database: MongoDB")
            if os.environ.get('MONGODB_URI'):
                print("✅ MongoDB URI: Configured from environment")
            else:
                print("⚠️  MongoDB URI: Using default (localhost)")
        else:
            print("✅ Database: SQLite")
            print(f"📁 Database file: {Config.SQLALCHEMY_DATABASE_URI}")
        
        print(f"🌍 Timezone: {Config.TIMEZONE}")
        print(f"⏰ Late arrival cutoff: {Config.LATE_ARRIVAL_TIME}")
        print(f"🔑 Active API keys: {len(Config.VALID_API_KEYS)}")
        print(f"📧 Email notifications: {'Enabled' if Config.ENABLE_EMAIL_NOTIFICATIONS else 'Disabled'}")
        print(f"🌐 CORS origins: {', '.join(Config.CORS_ORIGINS)}")
        print("="*60 + "\n")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Development-specific overrides
    SESSION_COOKIE_SECURE = False
    USE_MONGODB = os.environ.get('USE_MONGODB', 'false').lower() == 'true'
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        print("🔧 Development mode: Debug enabled")


class ProductionConfig(Config):
    """Production configuration for Render deployment"""
    DEBUG = False
    TESTING = False
    
    # Force MongoDB in production
    USE_MONGODB = True
    
    # Production security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Force HTTPS
    PREFERRED_URL_SCHEME = 'https'
    
    # Enable rate limiting in production
    RATELIMIT_ENABLED = True
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        
        # Production-specific initialization
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Ensure MongoDB URI is set
        if not os.environ.get('MONGODB_URI'):
            raise ValueError("❌ MONGODB_URI environment variable must be set in production!")
        
        # Set up file logging
        if not app.debug:
            file_handler = RotatingFileHandler(
                Config.LOG_FILE,
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=Config.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('🚀 Attendance system production startup')


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    WTF_CSRF_ENABLED = False
    
    # Use test database
    MONGODB_DB_NAME = 'attendance_system_test'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(Config.DATABASE_DIR, "test_attendance.db")}'
    
    # Disable email in tests
    ENABLE_EMAIL_NOTIFICATIONS = False
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        print("🧪 Testing mode enabled")


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


# Helper function to get current config
def get_config(config_name=None):
    """Get configuration object by name"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    return config.get(config_name, config['default'])
