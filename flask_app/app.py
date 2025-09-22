"""
Main entry point for the Flask application.

This module sets up the Flask app with secure defaults and integrates
authentication, password reset and Supabase as the backing database.

Sensitive configuration values are loaded from environment variables via
python‑dotenv. See `.env.example` for the variables required to run the app.

The application uses:
  * Flask‑WTF for form handling and CSRF protection.
  * Flask‑Login to manage user sessions securely.
  * Flask‑Mail for sending password reset emails.
  * Flask‑Talisman to set useful HTTP security headers (Content Security
    Policy, HSTS, etc.).
  * Flask‑Limiter to throttle login attempts and mitigate brute force attacks.
  * Supabase as a Postgres backend via the supabase‑py client.

User passwords are never stored in plain text. They are hashed using
Werkzeug's `generate_password_hash()` function, which applies a random salt
before hashing so that identical passwords result in different hashes【775746537229351†L399-L407】.

Password reset links include a JWT token with an expiration timestamp
embedded. The token is signed using the application's `SECRET_KEY` and
contains the user's unique identifier and an expiration claim【418069725510074†L313-L324】.
When a token is presented back to the app, it is verified and expired
tokens are rejected. This prevents replay attacks and ensures that only
valid, unexpired tokens can be used to set a new password【418069725510074†L313-L324】.
"""

import os
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import jwt

# Supabase client
try:
    from supabase import create_client
except ImportError:
    # Provide a clear error message if the dependency is missing. The
    # application will still run but database operations will fail.
    create_client = None

from models import User
from forms import (
    RegistrationForm,
    LoginForm,
    ResetPasswordRequestForm,
    ResetPasswordForm,
)


def create_app():
    """Factory to create and configure the Flask application."""
    # Load environment variables from a `.env` file if present.
    load_dotenv()

    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(32))
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'localhost')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 25))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'false').lower() in ['true', '1', 'yes']
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@example.com')

    # Session cookie security
    app.config['SESSION_COOKIE_SECURE'] = True  # only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # disallow access via JavaScript
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # reduce CSRF risk

    # Initialize extensions
    csrf = CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    mail = Mail(app)

    # Security headers via Talisman
    talisman = Talisman(
        app,
        content_security_policy={
            'default-src': ["'self'"],
            'style-src': ["'self'", 'https://cdnjs.cloudflare.com'],
            'script-src': ["'self'", 'https://cdnjs.cloudflare.com'],
        },
    )

    # Rate limiting (e.g. limit login attempts per IP)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[os.getenv('RATELIMIT_DEFAULT', '60 per minute')],
    )

    limiter.init_app(app)

    # Supabase client
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')
    if create_client and supabase_url and supabase_key:
        User.supabase = create_client(supabase_url, supabase_key)
    else:
        User.supabase = None

    # User loader callback for Flask‑Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

    # Routes

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit('10 per minute')
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data.strip()
            email = form.email.data.strip().lower()
            password = form.password.data

            # Ensure user does not already exist
            if User.get_by_username(username) or User.get_by_email(email):
                flash('Nome de usuário ou e‑mail já registrado.', 'danger')
            else:
                hashed = generate_password_hash(password)
                user = User.create(username, email, hashed)
                if user:
                    flash('Cadastro realizado com sucesso. Faça o login.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Ocorreu um erro ao criar o usuário. Tente novamente.', 'danger')
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit('15 per minute')
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            username_or_email = form.username.data.strip()
            password = form.password.data
            remember = form.remember_me.data
            # Retrieve user by username or email
            user = User.get_by_username(username_or_email) or User.get_by_email(username_or_email)
            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=remember)
                return redirect(url_for('index'))
            else:
                flash('Credenciais inválidas.', 'danger')
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/reset_password_request', methods=['GET', 'POST'])
    def reset_password_request():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = ResetPasswordRequestForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            user = User.get_by_email(email)
            if user:
                send_password_reset_email(app, mail, user)
            # Always show the same message to avoid revealing whether the email exists
            flash('Se o endereço de e‑mail estiver registrado, um e‑mail de redefinição foi enviado.', 'info')
            return redirect(url_for('login'))
        return render_template('reset_password_request.html', form=form)

    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        user = User.verify_reset_password_token(token)
        if not user:
            flash('Token inválido ou expirado.', 'danger')
            return redirect(url_for('reset_password_request'))
        form = ResetPasswordForm()
        if form.validate_on_submit():
            password = form.password.data
            hashed = generate_password_hash(password)
            if User.update_password(user.id, hashed):
                flash('Sua senha foi atualizada. Faça o login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Ocorreu um erro ao atualizar a senha.', 'danger')
        return render_template('reset_password.html', form=form)

    return app


def send_password_reset_email(app: Flask, mail: Mail, user: User) -> None:
    """Send a password reset email to the given user.

    A JSON Web Token with a short expiration time is generated and embedded
    into the password reset link. The email is rendered from both a text and
    HTML template. You must configure your mail server via environment
    variables for this to work. The function will silently fail if mail
    sending is not configured.
    """
    try:
        token = user.get_reset_password_token()
        msg = Message('[Seu Site] Redefinição de senha', recipients=[user.email])
        msg.body = render_template('email/reset_password.txt', user=user, token=token)
        msg.html = render_template('email/reset_password.html', user=user, token=token)
        mail.send(msg)
    except Exception as exc:
        # Log the exception to stderr; in production use proper logging
        print(f'Erro ao enviar e‑mail de redefinição: {exc}')


if __name__ == '__main__':
    
    app = create_app()
    # Bind to all interfaces and use port 5000 by default
    app.run(host='0.0.0.0', port=5000, debug=False)