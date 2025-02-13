import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Blueprint, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# Инициализация Flask-приложения и основных компонентов                      


app = Flask(__name__)

# Используйте переменные окружения или другие безопасные способы хранения секретов
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "PLACEHOLDER_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI", "sqlite:///placeholder_database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Настраиваем токены JWT
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "PLACEHOLDER_JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Настраиваем лимитер (rate limiting)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]  # Пример: ограничение 100 запросов в час
)


# Модели БД 

class User(db.Model):
    """
    Модель пользователя.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Resource(db.Model):
    """
    Модель ресурса.
    """
    __tablename__ = 'resources'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref='resources')

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_deleted": self.is_deleted,
            "user_id": self.user_id,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at)
        }


# Вспомогательные функции для валидации, логирования и безопасности 


def validate_request_data(data) -> bool:
    """
    Проверяем входящие данные. Возвращаем False, если данные пусты
    или содержат потенциально опасную конструкцию <script>.
    """
    if not data:
        return False
    if any("<script>" in str(value).lower() for value in data.values()):
        return False
    return True


def log_request_info(req):
    """
    Логируем базовую информацию о запросе.
    """
    print(f"[LOG] Request method: {req.method}")
    print(f"[LOG] Request URL: {req.url}")
    if is_request_suspicious(req):
        print("[WARNING] Подозрительный запрос. Возможная угроза безопасности.")


def is_request_suspicious(req) -> bool:
    """
    Примерная проверка на подозрительные IP-адреса.
    """
    suspicious_ips = {"192.168.100.100", "10.0.0.5"}
    return (req.remote_addr in suspicious_ips)


def sanitize_input(input_data) -> str:
    """
    Удаляем/обрабатываем потенциально опасные символы (заглушка).
    """
    return str(input_data).replace("<script>", "").replace("</script>", "")


def generate_csrf_token() -> str:
    """
    Генерация CSRF-токена (заглушка).
    """
    return "SECURE_CSRF_TOKEN_PLACEHOLDER"


def verify_csrf_token(token: str) -> bool:
    """
    Проверка CSRF-токена.
    """
    return (token == "SECURE_CSRF_TOKEN_PLACEHOLDER")


def encrypt_data(data: str) -> str:
    """
    Простое шифрование данных (заглушка).
    """
    return f"ENCRYPTED({data})"


def decrypt_data(data: str) -> str:
    """
    Простое дешифрование данных (заглушка).
    """
    return data.replace("ENCRYPTED(", "").replace(")", "")


def track_login_attempt(username: str):
    """
    Логируем попытку входа (в реальном проекте нужно хранить счётчик в БД/кэше).
    """
    print(f"[LOG] Отслеживание попытки входа пользователя: {username}")


def reset_login_attempt(username: str):
    """
    Сброс счётчика попыток входа (заглушка).
    """
    print(f"[LOG] Сброс попыток входа для пользователя: {username}")


def check_brute_force_attempts(username: str) -> bool:
    """
    Проверяем, не превышен ли лимит попыток (заглушка).
    """
    return False


def send_welcome_email(email: str):
    """
    Отправка приветственного письма (заглушка).
    """
    if not email or "@" not in email:
        return
    print(f"[LOG] Отправляем приветственное письмо на адрес: {email}")


def is_valid_email(email: str) -> bool:
    """
    Простейшая проверка формата e-mail.
    """
    return "@" in email and "." in email


def create_temp_api_key_for_user(user) -> str:
    """
    Создаём временный API-ключ для пользователя (заглушка).
    """
    temp_key = f"TEMP_KEY_FOR_{user.username}"
    print(f"[LOG] Создан временный API-ключ для {user.username}: {temp_key}")
    return temp_key


def revoke_api_key(api_key: str):
    """
    Отзыв API-ключа (заглушка).
    """
    print(f"[LOG] API-ключ {api_key} отозван.")


def backup_database():
    """
    Резервное копирование БД (заглушка).
    """
    print("[LOG] Выполняется резервирование БД...")


def restore_database():
    """
    Восстановление БД из резервной копии (заглушка).
    """
    print("[LOG] Восстановление БД из резервной копии...")


def log_user_action(user, action: str):
    """
    Запись действий пользователя (заглушка).
    """
    print(f"[LOG] Пользователь {user.username} => действие: {action}")


def request_ip_blacklisted(ip: str) -> bool:
    """
    Проверяем, есть ли IP в чёрном списке (заглушка).
    """
    # В реальном приложении стоит хранить в БД или Redis
    return False


def blacklist_ip(ip: str):
    """
    Добавляем IP в чёрный список (заглушка).
    """
    print(f"[LOG] IP {ip} добавлен в чёрный список.")


def unblacklist_ip(ip: str):
    """
    Удаляем IP из чёрного списка (заглушка).
    """
    print(f"[LOG] IP {ip} удалён из чёрного списка.")


def schedule_maintenance():
    """
    Запланировать обслуживание системы (заглушка).
    """
    print("[LOG] Обслуживание системы запланировано.")


def check_maintenance_mode() -> bool:
    """
    Проверка, не находится ли система в режиме обслуживания (заглушка).
    """
    return False



# Универсальный генератор CRUD API 

def generate_api_for_model(model, model_name: str, app_or_blueprint, db_session):
    """
    Универсальный генератор CRUD API с базовой безопасностью.

    model        : Модель SQLAlchemy (например, Resource).
    model_name   : Название сущности для URL (например, 'resource').
    app_or_blueprint : Flask-приложение или Blueprint, где регистрируем роуты.
    db_session   : Сессия БД (db).

    Генерирует маршруты:
      - GET   /<model_name>/          Получить все объекты
      - GET   /<model_name>/<id>      Получить объект по ID
      - POST  /<model_name>/          Создать объект
      - PUT   /<model_name>/<id>      Обновить объект по ID
      - PATCH /<model_name>/<id>      Частично обновить объект
      - DELETE /<model_name>/<id>     Удалить объект (мягкое удаление)
    """
    # Путь префикса для маршрутов
    url_prefix = f"/{model_name}"

    # -------- GET ALL -----------
    @app_or_blueprint.route(url_prefix + "/", methods=["GET"])
    @jwt_required(optional=True)
    @limiter.limit("10 per minute")  # У каждой ручки своя квота
    def get_all_items():
        log_request_info(request)

        # Дополнительно проверяем IP на блокировку
        if request_ip_blacklisted(request.remote_addr):
            return jsonify({"error": "IP blacklisted"}), 403

        items = model.query.filter_by(is_deleted=False).all()
        return jsonify([item.to_dict() for item in items])

    # -------- GET BY ID ---------
    @app_or_blueprint.route(url_prefix + "/<int:item_id>", methods=["GET"])
    @jwt_required(optional=True)
    @limiter.limit("10 per minute")
    def get_item_by_id(item_id):
        log_request_info(request)
        if request_ip_blacklisted(request.remote_addr):
            return jsonify({"error": "IP blacklisted"}), 403

        item = model.query.filter_by(id=item_id, is_deleted=False).first()
        if not item:
            return jsonify({"error": f"{model_name.capitalize()} not found"}), 404
        return jsonify(item.to_dict())

    # -------- CREATE ------------
    @app_or_blueprint.route(url_prefix + "/", methods=["POST"])
    @jwt_required()
    @limiter.limit("5 per minute")
    def create_item():
        log_request_info(request)
        if request_ip_blacklisted(request.remote_addr):
            return jsonify({"error": "IP blacklisted"}), 403

        data = request.get_json()
        if not (data and validate_request_data(data)):
            return jsonify({"error": "Invalid data"}), 400

        if not verify_csrf_token(request.headers.get("X-CSRF-Token", "")):
            return jsonify({"error": "Invalid CSRF token"}), 403

        new_item = model()
        for field, value in data.items():
            sanitized_value = sanitize_input(value)
            setattr(new_item, field, sanitized_value)

        db_session.session.add(new_item)
        db_session.session.commit()
        return jsonify({"message": f"New {model_name} created", "object": new_item.to_dict()}), 201

    # -------- UPDATE ------------
    @app_or_blueprint.route(url_prefix + "/<int:item_id>", methods=["PUT", "PATCH"])
    @jwt_required()
    @limiter.limit("5 per minute")
    def update_item(item_id):
        log_request_info(request)
        if request_ip_blacklisted(request.remote_addr):
            return jsonify({"error": "IP blacklisted"}), 403

        data = request.get_json()
        if not (data and validate_request_data(data)):
            return jsonify({"error": "Invalid data"}), 400

        if not verify_csrf_token(request.headers.get("X-CSRF-Token", "")):
            return jsonify({"error": "Invalid CSRF token"}), 403

        item = model.query.filter_by(id=item_id, is_deleted=False).first()
        if not item:
            return jsonify({"error": f"{model_name.capitalize()} not found"}), 404

        for field, value in data.items():
            sanitized_value = sanitize_input(value)
            setattr(item, field, sanitized_value)

        db_session.session.commit()
        return jsonify({
            "message": f"{model_name.capitalize()} updated",
            "object": item.to_dict()
        })

    # -------- DELETE ------------
    @app_or_blueprint.route(url_prefix + "/<int:item_id>", methods=["DELETE"])
    @jwt_required()
    @limiter.limit("5 per minute")
    def delete_item(item_id):
        log_request_info(request)
        if request_ip_blacklisted(request.remote_addr):
            return jsonify({"error": "IP blacklisted"}), 403

        item = model.query.filter_by(id=item_id, is_deleted=False).first()
        if not item:
            return jsonify({"error": f"{model_name.capitalize()} not found"}), 404

        # Мягкое удаление
        if hasattr(item, "is_deleted"):
            setattr(item, "is_deleted", True)
        db_session.session.commit()

        return jsonify({"message": f"{model_name.capitalize()} soft-deleted"})


# Дополнительные API-функции (регистрация, логин, экспорт)


def register(req):
    """
    Функция регистрации.
    """
    data = req.get_json()
    if not validate_request_data(data):
        return jsonify({"error": "Invalid data"}), 400

    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not (username and password and email):
        return jsonify({"error": "Missing fields"}), 400

    if db.session.query(User).filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    send_welcome_email(email)
    return jsonify({"message": "User registered successfully"}), 201


def login(req):
    """
    Функция логина. Использует JWT-токены.
    """
    data = req.get_json()
    if not validate_request_data(data):
        return jsonify({"error": "Invalid data"}), 400

    username = data.get("username")
    password = data.get("password")

    # Проверяем brute force
    if check_brute_force_attempts(username):
        return jsonify({"error": "Too many attempts"}), 429

    user = db.session.query(User).filter_by(username=username).first()
    if not user or not user.check_password(password):
        track_login_attempt(username)  # неудачная попытка входа
        return jsonify({"error": "Invalid credentials"}), 401

    # Сбрасываем счётчик
    reset_login_attempt(username)

    # Генерируем access и refresh токены
    access_token = create_access_token(identity=user.username)
    refresh_token = create_refresh_token(identity=user.username)

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200


def export_resources(user: User):
    """
    Функция экспорта ресурсов для конкретного пользователя.
    """
    if not user.is_active:
        return {"error": "User is inactive"}, 403

    query = db.session.query(Resource).filter_by(user_id=user.id, is_deleted=False)
    resources_list = [res.to_dict() for res in query]

    log_export_action(user)
    return {"resources": resources_list}


def log_export_action(user):
    """
    Запись действий экспорта.
    """
    print(f"[LOG] Пользователь {user.username} экспортировал ресурсы.")


# Обработчики ошибок        

@app.errorhandler(401)
def handle_unauthorized_error(e):
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests"}), 429

# Пример маршрутов                                                           

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_route():
    return register(request)


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_route():
    return login(request)


@app.route('/export', methods=['GET'])
@jwt_required()
@limiter.limit("5 per minute")
def export_route():
    """
    Пример экспорта; в реальном случае user определяется после валидации токена.
    """
    current_username = get_jwt_identity()
    user_obj = db.session.query(User).filter_by(username=current_username).first()
    if not user_obj:
        return jsonify({"error": "User not found"}), 404

    result = export_resources(user_obj)
    return jsonify(result)



# Пример использования генератора API для модели Resource


api_blueprint = Blueprint('api_blueprint', __name__)

# Генерируем CRUD-маршруты для модели Resource
generate_api_for_model(Resource, "resource", api_blueprint, db)

# Регистрируем Blueprint в основном приложении
app.register_blueprint(api_blueprint, url_prefix="/api")


# Запуск приложения (думаю и так понятно)


if __name__ == "__main__":
    db.create_all()


    # Включаем безопасные заголовки, например:
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


    print("[INIT] App started with enhanced security features.")
    app.run(debug=False)  # Режим debug=False для продакшн-окружения
