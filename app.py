from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import hashlib
import secrets
import json
import os
from functools import wraps
import logging

# إعدادات التطبيق
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///panel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# إعدادات قاعدة البيانات
db = SQLAlchemy(app)

# إعدادات تسجيل الدخول
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- نماذج قاعدة البيانات ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    is_developer = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

class ActivationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False)
    max_users = db.Column(db.Integer, nullable=False, default=1)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')
    notes = db.Column(db.Text)
    
    # العلاقات
    creator = db.relationship('User', backref='created_codes')
    activations = db.relationship('Activation', backref='activation_code', lazy=True)

class Activation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    code_id = db.Column(db.Integer, db.ForeignKey('activation_code.id'))
    activated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='active')
    
    # العلاقات
    user = db.relationship('User', backref='activations')

class BotAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    uid = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(100))
    status = db.Column(db.String(20), default='inactive')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime)
    connection_data = db.Column(db.Text)  # JSON format
    
    # العلاقات
    user = db.relationship('User', backref='bot_accounts')

class ConnectionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(50))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # العلاقات
    user = db.relationship('User', backref='connection_logs')

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- دوال المساعدة ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def developer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_developer:
            flash('هذه الصفحة للمطورين فقط!', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def check_activation_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_developer:
            # التحقق من صلاحية الاشتراك
            activation = Activation.query.filter_by(
                user_id=current_user.id, 
                status='active'
            ).filter(Activation.expires_at > datetime.utcnow()).first()
            
            if not activation:
                flash('انتهت صلاحية اشتراكك!', 'danger')
                return redirect(url_for('activate_account'))
        
        return f(*args, **kwargs)
    return decorated_function

def generate_activation_code():
    """إنشاء كود تفعيل فريد"""
    return f"FF-{secrets.token_hex(8).upper()}"

def log_activity(user_id, action, details=""):
    """تسجيل نشاط المستخدم"""
    ip_address = request.remote_addr
    log = ConnectionLog(
        user_id=user_id,
        ip_address=ip_address,
        action=action,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def system_log(log_type, message, details=""):
    """تسجيل حدث في النظام"""
    log = SystemLog(
        log_type=log_type,
        message=message,
        details=details
    )
    db.session.add(log)
    db.session.commit()

# --- المسارات (Routes) ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.status == 'active':
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_activity(user.id, 'تسجيل دخول', f'المستخدم {username} قام بتسجيل الدخول')
            flash('تم تسجيل الدخول بنجاح!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة!', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if User.query.filter_by(username=username).first():
            flash('اسم المستخدم موجود مسبقاً!', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        system_log('register', f'مستخدم جديد {username} قام بالتسجيل')
        flash('تم إنشاء الحساب بنجاح! قم بتسجيل الدخول', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'تسجيل خروج', f'المستخدم {current_user.username} قام بتسجيل الخروج')
    logout_user()
    flash('تم تسجيل الخروج بنجاح!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@check_activation_required
def dashboard():
    # إحصائيات
    stats = {
        'total_bots': BotAccount.query.filter_by(user_id=current_user.id).count(),
        'active_bots': BotAccount.query.filter_by(user_id=current_user.id, status='active').count(),
        'total_codes': Activation.query.filter_by(user_id=current_user.id).count(),
        'active_until': None
    }
    
    # الحصول على تاريخ انتهاء الصلاحية
    activation = Activation.query.filter_by(
        user_id=current_user.id, 
        status='active'
    ).filter(Activation.expires_at > datetime.utcnow()).first()
    
    if activation:
        stats['active_until'] = activation.expires_at
    
    # آخر النشاطات
    recent_logs = ConnectionLog.query.filter_by(user_id=current_user.id).order_by(
        ConnectionLog.timestamp.desc()
    ).limit(10).all()
    
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs)

@app.route('/activate', methods=['GET', 'POST'])
@login_required
def activate_account():
    if request.method == 'POST':
        code = request.form.get('code').strip().upper()
        
        activation_code = ActivationCode.query.filter_by(code=code, status='active').first()
        
        if not activation_code:
            flash('كود التفعيل غير صالح!', 'danger')
            return redirect(url_for('activate_account'))
        
        # التحقق من عدد المستخدمين
        user_count = Activation.query.filter_by(code_id=activation_code.id, status='active').count()
        if user_count >= activation_code.max_users:
            flash('تم الوصول للحد الأقصى للمستخدمين لهذا الكود!', 'danger')
            return redirect(url_for('activate_account'))
        
        # التحقق من عدم التفعيل المسبق
        existing = Activation.query.filter_by(
            user_id=current_user.id, 
            code_id=activation_code.id,
            status='active'
        ).filter(Activation.expires_at > datetime.utcnow()).first()
        
        if existing:
            flash('لقد قمت بتفعيل هذا الكود مسبقاً!', 'warning')
            return redirect(url_for('dashboard'))
        
        # إنشاء التفعيل
        expires_at = datetime.utcnow() + timedelta(days=activation_code.duration_days)
        
        activation = Activation(
            user_id=current_user.id,
            code_id=activation_code.id,
            expires_at=expires_at
        )
        
        db.session.add(activation)
        db.session.commit()
        
        log_activity(current_user.id, 'تفعيل اشتراك', f'كود: {code} - المدة: {activation_code.duration_days} يوم')
        system_log('activation', f'المستخدم {current_user.username} قام بتفعيل الكود {code}')
        
        flash(f'تم التفعيل بنجاح! صلاحيتك تنتهي في {expires_at.strftime("%Y-%m-%d %H:%M")}', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('activate.html')

# --- لوحة المطور ---

@app.route('/developer')
@login_required
@developer_required
def developer_dashboard():
    stats = {
        'total_users': User.query.count(),
        'total_activations': Activation.query.count(),
        'active_codes': ActivationCode.query.filter_by(status='active').count(),
        'total_bots': BotAccount.query.count()
    }
    
    recent_activations = Activation.query.order_by(Activation.activated_at.desc()).limit(10).all()
    recent_codes = ActivationCode.query.order_by(ActivationCode.created_at.desc()).limit(10).all()
    
    return render_template('developer/dashboard.html', 
                         stats=stats, 
                         recent_activations=recent_activations,
                         recent_codes=recent_codes)

@app.route('/developer/codes', methods=['GET', 'POST'])
@login_required
@developer_required
def manage_codes():
    if request.method == 'POST':
        duration_days = int(request.form.get('duration_days'))
        max_users = int(request.form.get('max_users'))
        notes = request.form.get('notes', '')
        
        # إنشاء كود جديد
        code = generate_activation_code()
        expires_at = datetime.utcnow() + timedelta(days=365)  # الكود صالح لمدة سنة
        
        activation_code = ActivationCode(
            code=code,
            duration_days=duration_days,
            max_users=max_users,
            creator_id=current_user.id,
            expires_at=expires_at,
            notes=notes
        )
        
        db.session.add(activation_code)
        db.session.commit()
        
        system_log('code_creation', f'المطور {current_user.username} أنشأ الكود {code}')
        flash(f'تم إنشاء الكود: {code}', 'success')
        return redirect(url_for('manage_codes'))
    
    codes = ActivationCode.query.order_by(ActivationCode.created_at.desc()).all()
    return render_template('developer/codes.html', codes=codes)

@app.route('/developer/codes/<int:code_id>/delete')
@login_required
@developer_required
def delete_code(code_id):
    code = ActivationCode.query.get_or_404(code_id)
    code.status = 'inactive'
    db.session.commit()
    
    system_log('code_deletion', f'المطور {current_user.username} عطل الكود {code.code}')
    flash('تم تعطيل الكود بنجاح!', 'success')
    return redirect(url_for('manage_codes'))

@app.route('/developer/users')
@login_required
@developer_required
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('developer/users.html', users=users)

@app.route('/developer/logs')
@login_required
@developer_required
def view_logs():
    system_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(100).all()
    connection_logs = ConnectionLog.query.order_by(ConnectionLog.timestamp.desc()).limit(100).all()
    
    return render_template('developer/logs.html', 
                         system_logs=system_logs, 
                         connection_logs=connection_logs)

# --- إدارة البوتات ---

@app.route('/bots')
@login_required
@check_activation_required
def manage_bots():
    bots = BotAccount.query.filter_by(user_id=current_user.id).order_by(
        BotAccount.created_at.desc()
    ).all()
    
    return render_template('bots.html', bots=bots)

@app.route('/bots/add', methods=['GET', 'POST'])
@login_required
@check_activation_required
def add_bot():
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
        nickname = request.form.get('nickname', '')
        
        bot = BotAccount(
            user_id=current_user.id,
            uid=uid,
            password=password,
            nickname=nickname
        )
        
        db.session.add(bot)
        db.session.commit()
        
        log_activity(current_user.id, 'إضافة بوت', f'UID: {uid}')
        flash('تم إضافة البوت بنجاح!', 'success')
        return redirect(url_for('manage_bots'))
    
    return render_template('add_bot.html')

@app.route('/bots/<int:bot_id>/delete')
@login_required
@check_activation_required
def delete_bot(bot_id):
    bot = BotAccount.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id and not current_user.is_developer:
        flash('غير مصرح لك!', 'danger')
        return redirect(url_for('manage_bots'))
    
    db.session.delete(bot)
    db.session.commit()
    
    log_activity(current_user.id, 'حذف بوت', f'UID: {bot.uid}')
    flash('تم حذف البوت بنجاح!', 'success')
    return redirect(url_for('manage_bots'))

# --- ميزات السورس الرئيسي ---

@app.route('/features/invite')
@login_required
@check_activation_required
def invite_feature():
    return render_template('features/invite.html')

@app.route('/features/join')
@login_required
@check_activation_required
def join_feature():
    return render_template('features/join.html')

@app.route('/features/messages')
@login_required
@check_activation_required
def messages_feature():
    return render_template('features/messages.html')

@app.route('/features/squad')
@login_required
@check_activation_required
def squad_feature():
    return render_template('features/squad.html')

@app.route('/features/player-info')
@login_required
@check_activation_required
def player_info_feature():
    return render_template('features/player_info.html')

# --- API للميزات ---

@app.route('/api/bots/start', methods=['POST'])
@login_required
@check_activation_required
def start_bots():
    data = request.json
    bot_ids = data.get('bot_ids', [])
    
    # هنا سيتم دمج كود تشغيل البوتات من السورس الأصلي
    # مؤقتاً نعيد رسالة نجاح
    return jsonify({
        'success': True,
        'message': f'تم بدء تشغيل {len(bot_ids)} بوت',
        'started': bot_ids
    })

@app.route('/api/bots/stop', methods=['POST'])
@login_required
@check_activation_required
def stop_bots():
    data = request.json
    bot_ids = data.get('bot_ids', [])
    
    return jsonify({
        'success': True,
        'message': f'تم إيقاف {len(bot_ids)} بوت',
        'stopped': bot_ids
    })

@app.route('/api/invite/send', methods=['POST'])
@login_required
@check_activation_required
def send_invite():
    data = request.json
    player_id = data.get('player_id')
    message = data.get('message', '')
    
    # هنا سيتم دمج كود إرسال الدعوة من السورس الأصلي
    log_activity(current_user.id, 'إرسال دعوة', f'لـ Player ID: {player_id}')
    
    return jsonify({
        'success': True,
        'message': f'تم إرسال دعوة إلى {player_id}',
        'timestamp': datetime.utcnow().isoformat()
    })

# --- خدمة الخلفية لفحص الصلاحيات ---

def check_expired_activations():
    """فحص المستخدمين المنتهية صلاحيتهم"""
    with app.app_context():
        expired = Activation.query.filter(
            Activation.status == 'active',
            Activation.expires_at <= datetime.utcnow()
        ).all()
        
        for activation in expired:
            activation.status = 'expired'
            
            # تسجيل الخروج للمستخدم إذا كان متصل
            user = activation.user
            if user:
                system_log('expiration', 
                          f'انتهت صلاحية المستخدم {user.username}',
                          f'الكود: {activation.activation_code.code}')
        
        if expired:
            db.session.commit()
            print(f"[{datetime.utcnow()}] تم تحديث {len(expired)} مستخدم منتهي الصلاحية")

# --- تهيئة قاعدة البيانات وإنشاء مستخدم مطور افتراضي ---

def init_database():
    with app.app_context():
        db.create_all()
        
        # إنشاء مستخدم مطور إذا لم يكن موجود
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_developer=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            
            print("تم إنشاء مستخدم المطور:")
            print("اسم المستخدم: admin")
            print("كلمة المرور: admin123")
            print("⚠️ يرجى تغيير كلمة المرور فوراً!")

if __name__ == '__main__':
    init_database()
    
    # بدء خدمة فحص الصلاحيات في خيط منفصل
    import threading
    import time
    
    def background_checker():
        while True:
            try:
                check_expired_activations()
            except Exception as e:
                print(f"خطأ في فحص الصلاحيات: {e}")
            time.sleep(3600)  # فحص كل ساعة
    
    checker_thread = threading.Thread(target=background_checker)
    checker_thread.daemon = True
    checker_thread.start()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
