from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from app import app
from app import db, models, forms
from app.models import User
from app.forms import RegistrationForm, LoginForm
import bcrypt

# Главная страница
@app.route('/')
def home():
    return render_template('home.html')

# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Если пользователь уже авторизован, перенаправляем на главную

    form = RegistrationForm()
    if form.validate_on_submit():
        # Хешируем пароль
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # Создаём нового пользователя
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register')

# Страница авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Если пользователь уже авторизован, перенаправляем на главную

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user, remember=form.remember.data)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Неверный email или пароль.', 'danger')
    return render_template('login.html', form=form, title='Login')

# Выход из системы
@app.route('/logout')
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('home'))

# Страница профиля
@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')
