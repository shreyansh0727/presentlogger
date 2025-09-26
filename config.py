import os
from datetime import timedelta

class Config:
    # Ensure database directory exists
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_DIR = os.path.join(BASE_DIR, 'database')
    
    # Create database directory if it doesn't exist
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)
        print(f"✅ Created database directory: {DATABASE_DIR}")
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hdgfygffuyf673773'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(DATABASE_DIR, "attendance.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER') or 'thepotterypatch.shop@gmail.com'
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS') or 'tsuaacddqsztpibx'
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER') or 'thepotterypatch.shop@gmail.com'
    
    # Timezone
    TIMEZONE = 'Asia/Kolkata'
    
    # Arduino Settings
    ARDUINO_TIMEOUT = 30  # seconds

