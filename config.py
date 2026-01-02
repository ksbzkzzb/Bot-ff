import os
from datetime import timedelta

class Config:
    # إعدادات أساسية
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # إعدادات قاعدة البيانات
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///panel.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # إعدادات الجلسة
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # إعدادات الرفع
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # إعدادات البريد (إذا أردت إضافة البريد الإلكتروني لاحقاً)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # إعدادات المطور
    DEVELOPER_ACCESS_KEY = os.environ.get('DEVELOPER_KEY', 'master-dev-key-2024')
    
    # أنواع الاشتراكات
    SUBSCRIPTION_PLANS = {
        'trial': {'days': 1, 'max_users': 1, 'price': 0},
        'week': {'days': 7, 'max_users': 1, 'price': 5},
        'month': {'days': 30, 'max_users': 1, 'price': 15},
        'premium': {'days': 90, 'max_users': 3, 'price': 40},
        'developer': {'days': 365, 'max_users': 100, 'price': 999}
    }
    
    # إعدادات اللعبة
    GAME_REGIONS = ['ME', 'EU', 'NA', 'AS', 'SA']
    BOT_STATUSES = ['active', 'inactive', 'banned', 'error']
    
    # إعدادات السجلات
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/panel.log'
    
    # إعدادات الأمان
    PASSWORD_MIN_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 900  # 15 دقيقة بالثواني
