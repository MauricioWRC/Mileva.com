"""
Form definitions for the Flask application.

Using `FlaskForm` automatically provides CSRF protection. When the form is
rendered, a hidden field called `csrf_token` is included which contains a
token signed with the application's secret key【280942412369161†L11-L37】. The
server verifies this token on POST requests to ensure the form was submitted
from our application and not from an external site, helping to prevent
Cross‑Site Request Forgery (CSRF) attacks【280942412369161†L11-L37】.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    username = StringField('Nome de usuário', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('E‑mail', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirme a senha', validators=[DataRequired(), EqualTo('password', message='As senhas devem corresponder.')])
    submit = SubmitField('Registrar')


class LoginForm(FlaskForm):
    username = StringField('Usuário ou e‑mail', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    remember_me = BooleanField('Lembrar‑me')
    submit = SubmitField('Entrar')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('E‑mail', validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField('Solicitar redefinição')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova senha', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirme a nova senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Redefinir senha')