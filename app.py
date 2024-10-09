from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_security import Security, SQLAlchemyUserDatastore
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import verify_jwt_in_request
from flask_security import roles_required
from models import db, AccessLog, AccessRequest, User, Role
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from redis import Redis
import json


app = Flask(__name__)
app.config.from_object('config.Config')



# Base de datos
db.init_app(app)

# JWT para autenticación
jwt = JWTManager(app)

# Límite de tasa para las solicitudes
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["30 per minute"])

# Seguridad de roles
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Registro de accesos
# Configuración del logger
logging.basicConfig(
    filename='logs/access.log',  # Nombre del archivo de log
    level=logging.INFO,  # Nivel de logging
    format='%(asctime)s - %(levelname)s - %(message)s'  # Formato del log
)

# Crear un handler para imprimir en consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Puedes ajustar el nivel aquí
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Añadir el handler a la aplicación
app.logger.addHandler(console_handler)

# Esto establece el nivel de log de la aplicación
app.logger.setLevel(logging.INFO)

# Lista negra para la invalidación de tokens
blacklist = set()

def log_access(response):
    """Registra el acceso de los usuarios."""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity() if get_jwt_identity() else 'guest'
    except RuntimeError:
        user_id = 'guest'
    
    logging.info(f"User {user_id} accessed {request.url} with status {response.status_code}")
    return response

@app.after_request
def after_request(response):
    return log_access(response)

def role_required(role):
    """Verifica si el usuario tiene el rol adecuado."""
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if user is None or role not in [r.name for r in user.roles]:
                return jsonify({"msg": "Acceso denegado: permisos insuficientes"}), 403

            return fn(*args, **kwargs)
        return decorator
    return wrapper

@app.route('/')
def home():
    return jsonify({'message': 'Bienvenido al sistema de control de acceso'})

@app.route('/register', methods=['POST'])
@jwt_required()
@role_required('admin')  # Restringir a solo administradores
def register():
    """Registra un nuevo usuario."""
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'message': 'Datos incompletos'}), 400

    # Verificar si el nombre de usuario ya existe
    existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
    if existing_user:
        return jsonify({'message': 'El nombre de usuario o el correo electrónico ya están en uso'}), 409

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario registrado exitosamente'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al registrar el usuario', 'error': str(e)}), 400

@app.route('/register_page')
@jwt_required()
@role_required('admin')
def register_page():
    """Muestra la página de registro de nuevos usuarios."""
    return render_template('register.html')

def log_login_attempt(email, success):
    """Logea el intento de inicio de sesión."""
    if success:
        app.logger.info(f'Inicio de sesión exitoso: {email}.')
    else:
        app.logger.warning(f'Intento de inicio de sesión fallido para: {email}.')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Inicia sesión para un usuario."""
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            app.logger.warning('Intento de inicio de sesión fallido: Campos vacíos.')
            flash('Por favor, ingresa ambos campos.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()

        if user:
            app.logger.info(f'Usuario encontrado: {user.username}. Intentando verificar contraseña.')
            if check_password_hash(user.password, password):
                access_token = create_access_token(identity=user.id)
                session['user_id'] = user.id
                session['username'] = user.username
                log_login_attempt(email, success=True)  # Log de éxito
                return jsonify(access_token=access_token), 200
            else:
                log_login_attempt(email, success=False)  # Log de fallo
                flash('Contraseña incorrecta', 'danger')
        else:
            log_login_attempt(email, success=False)  # Log de fallo
            flash('Usuario no encontrado', 'danger')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """Página de inicio del dashboard."""
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirigir si no está autenticado

    user = User.query.get(session['user_id'])
    is_admin = session.get('is_admin', False)  # Obtener el estado del rol

    return render_template('dashboard.html', user=user, is_admin=is_admin)

@app.route('/logout')
@jwt_required()
def logout():
    """Cierra sesión del usuario."""
    jti = get_jwt_identity()  # Obtener el ID del token JWT
    blacklist.add(jti)  # Añadir a la lista negra
    return jsonify({"msg": "Sesión cerrada exitosamente"}), 200

@app.route('/bitacora', methods=['GET'])
@jwt_required()
@roles_required('user')
def bitacora():
    """Obtiene los registros de acceso."""
    logs = AccessLog.query.all()
    return jsonify([log.event for log in logs])

@app.route('/solicitar_acceso', methods=['POST'])
@jwt_required()
@roles_required('user')
@limiter.limit("100 per hour")
def solicitar_acceso():
    """Crea una nueva solicitud de acceso."""
    data = request.get_json()
    if not data or not all(k in data for k in ('location', 'reason')):
        return jsonify({'message': 'Datos incompletos'}), 400

    # Crear la solicitud de acceso
    new_request = AccessRequest(user_id=get_jwt_identity(), location=data['location'], reason=data['reason'], status='pending')
    
    try:
        db.session.add(new_request)
        db.session.commit()
        return jsonify({'message': 'Solicitud creada exitosamente', 'request': new_request.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al crear la solicitud', 'error': str(e)}), 400

@app.route('/access_requests', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_requests():
    """Obtiene todas las solicitudes de acceso."""
    requests = AccessRequest.query.all()
    return jsonify([req.to_dict() for req in requests]), 200

@app.route('/access_requests/<int:id>', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_request(id):
    """Obtiene una solicitud de acceso específica."""
    access_request = AccessRequest.query.get_or_404(id)
    return jsonify(access_request.to_dict()), 200

@app.route('/access_requests', methods=['POST'])
@jwt_required()
@role_required('user')
def create_request():
    """Crea una nueva solicitud de acceso."""
    user_id = get_jwt_identity()
    data = request.get_json()

    new_request = AccessRequest(
        user_id=user_id,
        status=data.get('status', 'pending'),
        location=data['location'],
        reason=data['reason']
    )

    db.session.add(new_request)
    db.session.commit()

    return jsonify(new_request.to_dict()), 201

@app.route('/access_requests/<int:id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_request(id):
    """Actualiza una solicitud de acceso."""
    access_request = AccessRequest.query.get_or_404(id)
    data = request.get_json()

    if 'status' in data:
        access_request.status = data['status']
    if 'location' in data:
        access_request.location = data['location']
    if 'reason' in data:
        access_request.reason = data['reason']

    db.session.commit()
    
    return jsonify(access_request.to_dict()), 200

@app.route('/access_requests/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_request(id):
    """Elimina una solicitud de acceso."""
    access_request = AccessRequest.query.get_or_404(id)
    
    db.session.delete(access_request)
    db.session.commit()
    
    return jsonify({'message': 'Solicitud eliminada exitosamente'}), 200


@app.route('/load_users', methods=['POST'])
def load_users():
    """Carga usuarios desde un archivo JSON y los registra."""
    try:
        # Abre y carga el archivo JSON
        with open('usuarios.json', 'r') as file:
            users_data = json.load(file)

        for user_data in users_data:
            if not all(k in user_data for k in ('username', 'email', 'password')):
                return jsonify({'message': 'Datos incompletos en el archivo JSON'}), 400

            # Verificar si el nombre de usuario ya existe
            existing_user = User.query.filter((User.username == user_data['username']) | (User.email == user_data['email'])).first()
            if existing_user:
                return jsonify({'message': f'El nombre de usuario o el correo electrónico ya están en uso para: {user_data["username"]}'}), 409

            hashed_password = generate_password_hash(user_data['password'], method='sha256')
            new_user = User(username=user_data['username'], email=user_data['email'], password=hashed_password)

            db.session.add(new_user)

        db.session.commit()  # Guardar todos los usuarios en la base de datos
        return jsonify({'message': 'Usuarios registrados exitosamente'}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al cargar los usuarios', 'error': str(e)}), 400



if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Crear las tablas de la base de datos

        # Crear roles iniciales si no existen
        existing_role = db.session.query(Role).filter_by(name='admin').first()
        if not existing_role:
            admin_role = Role(name='admin', description='Administrator with full access')
            user_role = Role(name='user', description='Regular user with limited access')

            db.session.add(admin_role)
            db.session.add(user_role)
            db.session.commit()
            print("Roles 'admin' y 'user' creados.")
        else:
            print("Role 'admin' ya existe.")

        # Comprobar si los usuarios ya existen
        existing_admin_user = User.query.filter_by(username='admin').first()
        existing_regular_user = User.query.filter_by(username='user').first()

        if not existing_admin_user:
            hashed_admin_password = generate_password_hash('adminpassword', method='pbkdf2:sha256')
            admin_user = User(username='admin', email='admin@example.com', password=hashed_admin_password, active=True)
            admin_user.roles.append(Role.query.filter_by(name='admin').first())
            print(f"Usuario 'admin' creado exitosamente con hash: {hashed_admin_password}")

            db.session.add(admin_user)
              # Asegúrate de hacer el commit aquí

            print("Usuario 'admin' creado exitosamente.")
        else:
            print("El usuario 'admin' ya existe.")
            db.session.commit()
            
        if not existing_regular_user:
            # Crear un usuario regular
            hashed_user_password = generate_password_hash('userpassword', method='pbkdf2:sha256')
            regular_user = User(username='user', email='user@example.com', password=hashed_user_password, active=True)
            regular_user.roles.append(Role.query.filter_by(name='user').first())

            db.session.add(regular_user)
            print("Usuario 'user' creado exitosamente.")
        else:
            print("El usuario 'user' ya existe.")

        # Intentar hacer commit
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()  # Revertir cualquier cambio si ocurre un error
            print(f"Error al crear usuarios: {str(e)}")

    app.run(debug=True, host='0.0.0.0', port=5000)

