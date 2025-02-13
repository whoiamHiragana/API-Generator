"""
API Generator with Authentication
Для запуска:
1. Установите зависимости: 
   pip install flask flask-sqlalchemy flask-migrate flask-cors flask-bcrypt flask-jwt-extended python-dotenv

2. Создайте файл .env с переменными окружения:
   JWT_SECRET_KEY=your-super-secret-key
   DATABASE_URL=sqlite:///api_generator.db
   RATE_LIMIT=100 per day

3. Инициализируйте БД:
   flask db init
   flask db migrate
   flask db upgrade

4. Запустите приложение:
   flask run
"""
import io
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
from sqlalchemy import Index
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Конфигурация из переменных окружения
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///api_generator.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY=os.getenv('JWT_SECRET_KEY'),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
    PROPAGATE_EXCEPTIONS=True
)

# Инициализация расширений
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[os.getenv('RATE_LIMIT', '100 per day')]
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120))  # Новое поле для email
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Хеширование пароля с проверкой сложности"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Расширенная модель ресурса
class Resource(db.Model):
    __tablename__ = 'resources'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)  # Новое поле
    is_deleted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('resources', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_deleted': self.is_deleted,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# Вспомогательные функции
def validate_request_data(required_fields, max_lengths=None):
    """
    Валидация входных данных
    :param required_fields: обязательные поля
    :param max_lengths: максимальные длины для полей {field: length}
    """
    data = request.get_json()
    if not data:
        abort(400, description="Request body must be JSON")

    missing = [field for field in required_fields if field not in data]
    if missing:
        abort(400, description=f"Missing required fields: {', '.join(missing)}")

    if max_lengths:
        for field, max_len in max_lengths.items():
            if field in data and len(str(data[field])) > max_len:
                abort(400, description=f"{field} exceeds maximum length of {max_len} characters")

    return data

# Логирование
@app.before_request
def log_request_info():
    """Логирование входящих запросов"""
    app.logger.debug(f'Request: {request.method} {request.path}')

# API Endpoints
@app.route('/api/v1/auth/register', methods=['POST'])
@limiter.limit("5 per minute")  # Защита от брутфорса
def register():
    """
    Регистрация пользователя
    Пример тела запроса:
    {
        "username": "user123",
        "password": "SecurePass123!",
        "email": "user@example.com"
    }
    """
    data = validate_request_data(
        ['username', 'password', 'email'],
        max_lengths={'username': 50, 'password': 128, 'email': 120}
    )

    # Проверка уникальности
    if User.query.filter(db.or_(User.username == data['username'], User.email == data['email'])).first():
        abort(409, description="Username or email already exists")

    try:
        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        abort(500, description="Server error during registration")

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Аутентификация пользователя"""
    data = validate_request_data(['username', 'password'])
    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.check_password(data['password']):
        abort(401, description="Invalid credentials")

    if not user.is_active:
        abort(403, description="Account deactivated")

    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': 'user'}
    )
    return jsonify({
        'access_token': access_token,
        'user_id': user.id,
        'username': user.username
    })

# Индексы для оптимизации запросов
Index('idx_resources_user_id', Resource.user_id)
Index('idx_users_username', User.username)

@app.route('/api/v1/resources/export', methods=['GET'])
@jwt_required()
def export_resources():
    """Экспорт ресурсов в CSV"""
    current_user_id = get_jwt_identity()
    resources = Resource.query.filter_by(user_id=current_user_id).all()

    # Генерация CSV
    csv_data = "id,name,description,created_at\n"
    for r in resources:
        csv_data += f"{r.id},{r.name},{r.description or ''},{r.created_at}\n"

    return send_file(
        io.BytesIO(csv_data.encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='resources.csv'
    )

# Обработка ошибок
@jwt.unauthorized_loader
def handle_unauthorized_error(err):
    return jsonify({'error': 'Missing or invalid token'}), 401

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': f"Rate limit exceeded: {e.description}"}), 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.getenv('FLASK_DEBUG', False))
