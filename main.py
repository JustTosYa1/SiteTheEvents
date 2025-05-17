from flask import (
    Flask, render_template_string, redirect, url_for, flash,
    jsonify, request, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField, StringField, PasswordField
from wtforms.validators import (
    DataRequired, EqualTo, Length, Regexp, ValidationError
)
from werkzeug.security import generate_password_hash, check_password_hash

# Инициализация приложения Flask и базы данных SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///the_events.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Список популярных городов для заполнения базы
POPULAR_CITIES = [
    "Москва", "Санкт-Петербург", "Новосибирск", "Екатеринбург", "Казань",
    "Нижний Новгород", "Челябинск", "Самара", "Омск", "Ростов-на-Дону"
]

# Словарь отелей по городам
HOTELS_BY_CITY = {
    "Москва": [
        "Отель Москва", "Отель Пекин", "Отель Ленинград",
        "Отель Сокол", "Отель Измайлово"
    ],
    "Санкт-Петербург": [
        "Отель Невский", "Отель Эрмитаж", "Отель Петроград",
        "Отель Аничков", "Отель Водник"
    ],
    "Новосибирск": [
        "Отель Сибирь", "Отель Центральный", "Отель Арена",
        "Отель Десятка", "Отель Снежинка"
    ],
    "Екатеринбург": [
        "Отель Урал", "Отель Эльмаш", "Отель Весна",
        "Отель Березка", "Отель Восток"
    ],
    "Казань": [
        "Отель Казань", "Отель Кремль", "Отель София",
        "Отель Вокзал", "Отель Бауманская"
    ],
    "Нижний Новгород": [
        "Отель Волга", "Отель Кремлевский", "Отель Чкалов",
        "Отель Ривьера", "Отель Вознесенский"
    ],
    "Челябинск": [
        "Отель Металлург", "Отель Южный", "Отель Звезда",
        "Отель Город", "Отель Динамо"
    ],
    "Самара": [
        "Отель Самара", "Отель Волжский", "Отель Ладья",
        "Отель Прибрежный", "Отель Премьер"
    ],
    "Омск": [
        "Отель Омск", "Отель Северный", "Отель Центральный",
        "Отель Карнавал", "Отель Лада"
    ],
    "Ростов-на-Дону": [
        "Отель Дон", "Отель Волна", "Отель Маяк",
        "Отель Кавказ", "Отель Пушкина"
    ]
}


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Модель города
class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    hotels = db.relationship('Hotel', backref='city', lazy=True)


# Модель отеля
class Hotel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)


# Модель бронирования отеля
class HotelBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hotel_id = db.Column(db.Integer, db.ForeignKey('hotel.id'), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hotel = db.relationship('Hotel', backref='bookings')
    city = db.relationship('City')
    user = db.relationship('User')


# Модель события (мероприятия)
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    city = db.relationship('City', backref='events')
    user = db.relationship('User')


# Модель билета (путешествие между городами)
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    departure_id = db.Column(
        db.Integer, db.ForeignKey('city.id'), nullable=False
    )
    arrival_id = db.Column(
        db.Integer, db.ForeignKey('city.id'), nullable=False
    )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    departure = db.relationship(
        'City', foreign_keys=[departure_id], backref='departure_tickets'
    )
    arrival = db.relationship(
        'City', foreign_keys=[arrival_id], backref='arrival_tickets'
    )
    user = db.relationship('User')


# Форма регистрации пользователя
class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField(
        'Пароль',
        validators=[
            DataRequired(),
            Length(min=8, message='Пароль должен содержать не менее 8 символов'),
            Regexp(r'.*[0-9].*', message='Пароль должен содержать хотя бы одну цифру'),
            Regexp(r'.*[A-Z].*', message='Пароль должен содержать хотя бы одну заглавную букву'),
            Regexp(r'.*[a-z].*', message='Пароль должен содержать хотя бы одну строчную букву')
        ]
    )
    confirm_password = PasswordField(
        'Повторите пароль',
        validators=[
            DataRequired(),
            EqualTo('password', message='Пароли должны совпадать')
        ]
    )
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Логин уже используется, выберите другой.')


# Форма входа в систему
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


# Форма для покупки билета
class TicketForm(FlaskForm):
    departure_id = SelectField(
        'Пункт старта', coerce=int, validators=[DataRequired()]
    )
    arrival_id = SelectField(
        'Пункт назначения', coerce=int, validators=[DataRequired()]
    )
    submit = SubmitField('Купить билет')


# Форма бронирования отеля
class HotelForm(FlaskForm):
    city_id = SelectField('Город', coerce=int, validators=[DataRequired()])
    hotel_id = SelectField('Отель', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Забронировать отель')


# Форма создания мероприятия
class EventForm(FlaskForm):
    event_name = StringField('Мероприятие', validators=[DataRequired()])
    city_id = SelectField('Город', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Добавить мероприятие')


# Форма смены имени пользователя
class ChangeUsernameForm(FlaskForm):
    old_username = StringField(
        'Старый логин (неизменяемый)', render_kw={'readonly': True}
    )
    new_username = StringField('Новый логин', validators=[DataRequired()])
    submit_username = SubmitField('Сохранить новый логин')

    def __init__(self, user_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id = user_id

    def validate_new_username(self, field):
        user = User.query.filter_by(username=field.data).first()
        my_user = User.query.get(self.user_id)
        if user and user.id != self.user_id:
            raise ValidationError('Логин уже используется, выберите другой.')
        if my_user and field.data == my_user.username:
            raise ValidationError('Новый логин должен отличаться от текущего.')


# Форма смены пароля
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired()])
    new_password = PasswordField(
        'Новый пароль',
        validators=[
            DataRequired(),
            Length(min=8, message='Пароль должен содержать не менее 8 символов'),
            Regexp(r'.*[0-9].*', message='Пароль должен содержать хотя бы одну цифру'),
            Regexp(r'.*[A-Z].*', message='Пароль должен содержать хотя бы одну заглавную букву'),
            Regexp(r'.*[a-z].*', message='Пароль должен содержать хотя бы одну строчную букву')
        ]
    )
    confirm_new_password = PasswordField(
        'Повторите новый пароль',
        validators=[
            EqualTo('new_password', message='Пароли должны совпадать')
        ]
    )
    submit_password = SubmitField('Сохранить новый пароль')

    def __init__(self, user_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id = user_id

    def validate_old_password(self, field):
        user = User.query.get(self.user_id)
        if not user or not user.check_password(field.data):
            raise ValidationError('Неверный старый пароль.')

    def validate_new_password(self, field):
        user = User.query.get(self.user_id)
        if user and user.check_password(field.data):
            raise ValidationError('Новый пароль должен отличаться от старого.')


def base_page(content, title="События"):  # Базовый шаблон для всех HTML-страниц
    return f"""
    <!DOCTYPE html>
    <html lang="{{{{ session.get('lang', 'ru') }}}}">
    <head>
      <meta charset="UTF-8">
      <title>{title}</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        body[data-bs-theme='dark'] {{
          background-color: #212529;
          color: #adb5bd;
        }}
        .theme-toggle {{
          margin-left: 1rem;
        }}
        #lang_form {{
          display: inline;
        }}
      </style>
      <script>
        function toggleTheme() {{
          var currentTheme = document.documentElement.getAttribute('data-bs-theme') || 'light';
          var newTheme = currentTheme === 'light' ? 'dark' : 'light';
          document.documentElement.setAttribute('data-bs-theme', newTheme);
          localStorage.setItem('theme', newTheme);
          var btn = document.getElementById('theme-toggle-btn');
          btn.textContent = newTheme === 'light' ? '🌞' : '🌙';
        }}
        window.onload = function() {{
          var savedTheme = localStorage.getItem('theme') || 'light';
          document.documentElement.setAttribute('data-bs-theme', savedTheme);
          var btn = document.getElementById('theme-toggle-btn');
          btn.textContent = savedTheme === 'light' ? '🌞' : '🌙';
        }};
      </script>
    </head>
    <body>
      <div class="container mt-4">
        <div class="d-flex mb-3 justify-content-between align-items-center flex-wrap">
          <a class="btn btn-link fs-1" href="{{{{ url_for('index') }}}}"><b>{{{{ 'Events' if session.get('lang','ru')=='en' else 'События' }}}}</b></a>
          <div class="mt-2 mt-md-0 d-flex align-items-center flex-wrap">
            <a class="btn btn-success me-1" href="{{{{ url_for('buy_ticket') }}}}">{{{{ 'Buy Ticket' if session.get('lang','ru')=='en' else 'Купить билет' }}}}</a>
            <a class="btn btn-primary me-1" href="{{{{ url_for('add_event') }}}}">{{{{ 'Add Event' if session.get('lang','ru')=='en' else 'Добавить мероприятие' }}}}</a>
            <a class="btn btn-secondary me-1" href="{{{{ url_for('add_hotel') }}}}">{{{{ 'Book Hotel' if session.get('lang','ru')=='en' else 'Забронировать отель' }}}}</a>
            {{% if session.get('user_id') %}}
              <a class="btn btn-outline-primary me-1" href="{{{{ url_for('profile') }}}}" title="{{{{ 'Settings' if session.get('lang','ru')=='en' else 'Настройки' }}}}">&#9881;&#65039;</a>
              <a class="btn btn-light border me-1" href="{{{{ url_for('logout') }}}}">{{{{ session.get('username', 'User') }}}} ({{{{ 'Logout' if session.get('lang','ru')=='en' else 'Выйти' }}}})</a>
            {{% else %}}
              <a class="btn btn-outline-primary me-1" href="{{{{ url_for('login') }}}}">{{{{ 'Login' if session.get('lang','ru')=='en' else 'Войти' }}}}</a>
            {{% endif %}}
            <button id="theme-toggle-btn" class="btn btn-outline-secondary theme-toggle" onclick="toggleTheme()" title="{{{{ 'Toggle Theme' if session.get('lang','ru')=='en' else 'Сменить тему' }}}}"></button>
            <form id="lang_form" method="POST" action="{{{{ url_for('set_language') }}}}">
              <select name="lang" onchange="this.form.submit()" class="form-select form-select-sm ms-2" aria-label="Language select">
                <option value="ru" {{{{ 'selected' if session.get('lang') == 'ru' else '' }}}}>Русский</option>
                <option value="en" {{{{ 'selected' if session.get('lang') == 'en' else '' }}}}>English</option>
              </select>
            </form>
          </div>
        </div>
        <hr>
        {{% with messages = get_flashed_messages(with_categories=true) %}}
          {{% for category, msg in messages %}}
            <div class="alert alert-{{{{ category }}}} alert-dismissible fade show">
              {{{{ msg }}}}
              <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {{% endfor %}}
        {{% endwith %}}
        {content}
      </div>
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """.replace('{{{{', '{{').replace('}}}}', '}}').replace('{{%', '{%').replace('%}}', '%}')


@app.route('/set_language', methods=['POST'])
def set_language():  # Смена языка интерфейса пользователя
    lang = request.form.get('lang', 'ru')
    if lang not in ['ru', 'en']:
        lang = 'ru'
    session['lang'] = lang
    return redirect(request.referrer or url_for('index'))


@app.route('/')
def index():  # Главная страница: список мероприятий, билетов и отелей пользователя
    user_id = session.get('user_id')
    events = Event.query.filter_by(user_id=user_id).all() if user_id else []
    hotel_bookings = HotelBooking.query.filter_by(
        user_id=user_id
    ).all() if user_id else []
    tickets = Ticket.query.filter_by(user_id=user_id).all() if user_id else []
    content = '''
      <div class="row">
        <div class="col-lg-6">
          <h2>{{ 'Events' if session.get('lang','ru')=='en' else 'Мероприятия' }}</h2>
          <table class="table table-bordered table-striped">
            <thead><tr><th>{{ 'Name' if session.get('lang','ru')=='en' else 'Название' }}</th><th>{{ 'City' if session.get('lang','ru')=='en' else 'Город' }}</th><th></th></tr></thead>
            <tbody>
            {% for event in events %}
              <tr>
                <td>{{ event.name }}</td>
                <td>{{ event.city.name }}</td>
                <td>
                  <form method="post" action="{{ url_for('delete_event', event_id=event.id) }}">
                    <button class="btn btn-sm btn-danger">{{ 'Delete' if session.get('lang','ru')=='en' else 'Удалить' }}</button>
                  </form>
                </td>
              </tr>
            {% else %}
              <tr><td colspan="3" class="text-center text-secondary">{{ 'No events' if session.get('lang','ru')=='en' else 'Не создано' }}</td></tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
        <div class="col-lg-6">
          <h2>{{ 'Hotels' if session.get('lang','ru')=='en' else 'Отели' }}</h2>
          <table class="table table-bordered table-hover">
            <thead><tr><th>{{ 'Hotel' if session.get('lang','ru')=='en' else 'Отель' }}</th><th>{{ 'City' if session.get('lang','ru')=='en' else 'Город' }}</th><th></th></tr></thead>
            <tbody>
            {% for hb in hotel_bookings %}
              <tr>
                <td>{{ hb.hotel.name }}</td>
                <td>{{ hb.city.name }}</td>
                <td>
                  <form method="post" action="{{ url_for('delete_hotel_booking', booking_id=hb.id) }}">
                    <button class="btn btn-sm btn-danger">{{ 'Delete' if session.get('lang','ru')=='en' else 'Удалить' }}</button>
                  </form>
                </td>
              </tr>
            {% else %}
              <tr><td colspan="3" class="text-center text-secondary">{{ 'Empty' if session.get('lang','ru')=='en' else 'Пусто' }}</td></tr>
            {% endfor %}
            </tbody>
          </table>
          <h2>{{ 'Tickets' if session.get('lang','ru')=='en' else 'Билеты' }}</h2>
          <table class="table table-bordered table-hover">
            <thead><tr><th>{{ 'From' if session.get('lang','ru')=='en' else 'Откуда' }}</th><th>{{ 'To' if session.get('lang','ru')=='en' else 'Куда' }}</th><th></th></tr></thead>
            <tbody>
            {% for t in tickets %}
              <tr>
                <td>{{ t.departure.name if t.departure else '-' }}</td>
                <td>{{ t.arrival.name if t.arrival else '-' }}</td>
                <td>
                  <form method="post" action="{{ url_for('delete_ticket', ticket_id=t.id) }}">
                    <button class="btn btn-sm btn-danger">{{ 'Delete' if session.get('lang','ru')=='en' else 'Удалить' }}</button>
                  </form>
                </td>
              </tr>
            {% else %}
              <tr><td colspan="3" class="text-center text-secondary">{{ 'No tickets' if session.get('lang','ru')=='en' else 'Нет билетов' }}</td></tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    '''
    return render_template_string(
        base_page(content),
        events=events,
        hotel_bookings=hotel_bookings,
        tickets=tickets
    )


@app.route('/register', methods=['GET', 'POST'])
def register():  # Регистрация нового пользователя
    form = RegistrationForm()
    content = '''
    <h2>{{ 'Register' if session.get('lang','ru')=='en' else 'Регистрация' }}</h2>
    <form method="POST">
      {{ form.hidden_tag() }}
      <div class="mb-3">{{ form.username.label(class="form-label") }}{{ form.username(class="form-control") }}{% for error in form.username.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}</div>
      <div class="mb-3">{{ form.password.label(class="form-label") }}{{ form.password(class="form-control") }}{% for error in form.password.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}</div>
      <div class="mb-3">{{ form.confirm_password.label(class="form-label") }}{{ form.confirm_password(class="form-control") }}{% for error in form.confirm_password.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}</div>
      <button type="submit" class="btn btn-primary">{{ 'Register' if session.get('lang','ru')=='en' else 'Зарегистрироваться' }}</button>
      <a href="{{ url_for('login') }}" class="btn btn-link">{{ 'Login' if session.get('lang','ru')=='en' else 'Войти' }}</a>
    </form>
    '''
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(
            'Registration successful!' if session.get('lang','ru') == 'en'
            else 'Регистрация прошла успешно!', 'success'
        )
        return redirect(url_for('login'))
    return render_template_string(base_page(content), form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():  # Авторизация пользователя
    form = LoginForm()
    content = '''
    <h2>{{ 'Login' if session.get('lang','ru')=='en' else 'Вход' }}</h2>
    <form method="POST">
      {{ form.hidden_tag() }}
      <div class="mb-3">{{ form.username.label(class="form-label") }}{{ form.username(class="form-control") }}</div>
      <div class="mb-3">{{ form.password.label(class="form-label") }}{{ form.password(class="form-control") }}</div>
      <button type="submit" class="btn btn-success">{{ 'Login' if session.get('lang','ru')=='en' else 'Войти' }}</button>
      <a href="{{ url_for('register') }}" class="btn btn-link">{{ 'Register' if session.get('lang','ru')=='en' else 'Регистрация' }}</a>
    </form>
    '''
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(
                f"Welcome, {user.username}!" if session.get('lang', 'ru') == 'en'
                else f'Добро пожаловать, {user.username}!', 'success'
            )
            return redirect(url_for('index'))
        flash(
            'Invalid username or password'
            if session.get('lang','ru') == 'en'
            else 'Неверный логин или пароль', 'danger'
        )
    return render_template_string(base_page(content), form=form)


@app.route('/profile', methods=['GET', 'POST'])
def profile():  # Страница пользователя: отображение и изменение логина/пароля
    user_id = session.get('user_id')
    if not user_id:
        flash(
            'Please log in to access the profile.'
            if session.get('lang', 'ru') == 'en'
            else 'Авторизуйтесь для доступа к профилю.', 'danger'
        )
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    mode = request.args.get('mode')
    form_username = ChangeUsernameForm(
        user_id=user_id,
        formdata=(request.form if (
            request.method == 'POST' and 'submit_username' in request.form
        ) else None)
    )
    form_password = ChangePasswordForm(
        user_id=user_id,
        formdata=(request.form if (
            request.method == 'POST' and 'submit_password' in request.form
        ) else None)
    )
    show_username = mode == 'change_username' or (
        request.method == 'POST' and 'submit_username' in request.form
    )
    show_password = mode == 'change_password' or (
        request.method == 'POST' and 'submit_password' in request.form
    )
    username_content = ''
    password_content = ''

    if show_username:
        form_username.old_username.data = user.username
        username_content = '''
        <form method="POST" class="mb-3">
            {{ form_username.hidden_tag() }}
            <div class="mb-3">
                {{ form_username.old_username.label(class="form-label") }}
                {{ form_username.old_username(class="form-control", readonly=true) }}
            </div>
            <div class="mb-3">
                {{ form_username.new_username.label(class="form-label") }}
                {{ form_username.new_username(class="form-control") }}
                {% for error in form_username.new_username.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}
            </div>
            <button type="submit" name="submit_username" class="btn btn-primary">{{ 'Save New Username' if session.get('lang','ru')=='en' else 'Сохранить новый логин' }}</button>
            <a href="{{ url_for('profile') }}" class="btn btn-secondary">{{ 'Back' if session.get('lang','ru')=='en' else 'Назад' }}</a>
        </form>
        '''
        if (
            form_username.validate_on_submit()
            and 'submit_username' in request.form
        ):
            user.username = form_username.new_username.data
            db.session.commit()
            session['username'] = user.username
            flash(
                'Username updated!' if session.get('lang', 'ru') == 'en'
                else 'Логин обновлен!', 'success'
            )
            return redirect(url_for('profile'))

    if show_password:
        password_content = '''
        <form method="POST" class="mb-3">
            {{ form_password.hidden_tag() }}
            <div class="mb-3">
                {{ form_password.old_password.label(class="form-label") }}
                {{ form_password.old_password(class="form-control") }}
                {% for error in form_password.old_password.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}
            </div>
            <div class="mb-3">
                {{ form_password.new_password.label(class="form-label") }}
                {{ form_password.new_password(class="form-control") }}
                {% for error in form_password.new_password.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}
            </div>
            <div class="mb-3">
                {{ form_password.confirm_new_password.label(class="form-label") }}
                {{ form_password.confirm_new_password(class="form-control") }}
                {% for error in form_password.confirm_new_password.errors %}<div class="text-danger">{{ error }}</div>{% endfor %}
            </div>
            <button type="submit" name="submit_password" class="btn btn-primary">{{ 'Save New Password' if session.get('lang','ru')=='en' else 'Сохранить новый пароль' }}</button>
            <a href="{{ url_for('profile') }}" class="btn btn-secondary">{{ 'Back' if session.get('lang','ru')=='en' else 'Назад' }}</a>
        </form>
        '''
        if (
            form_password.validate_on_submit()
            and 'submit_password' in request.form
        ):
            user.set_password(form_password.new_password.data)
            db.session.commit()
            flash(
                'Password updated!'
                if session.get('lang', 'ru') == 'en'
                else 'Пароль обновлен!', 'success'
            )
            return redirect(url_for('profile'))

    base_content = f'''
    <h2>{{{{ 'User Profile' if session.get('lang','ru')=='en' else 'Профиль пользователя' }}}}</h2>
    <div class="mb-3"><b>{{{{ 'Username:' if session.get('lang','ru')=='en' else 'Логин:' }}}}</b> {user.username}</div>
    <div class="mb-3">
        <a href="{{{{ url_for('profile', mode='change_username') }}}}" class="btn btn-outline-info me-2">{{{{ 'Change Username' if session.get('lang','ru')=='en' else 'Сменить логин' }}}}</a>
        <a href="{{{{ url_for('profile', mode='change_password') }}}}" class="btn btn-outline-warning">{{{{ 'Change Password' if session.get('lang','ru')=='en' else 'Сменить пароль' }}}}</a>
    </div>
    '''
    final_content = base_content
    if show_username:
        final_content += username_content
    if show_password:
        final_content += password_content
    return render_template_string(
        base_page(final_content),
        form_username=form_username, form_password=form_password
    )


@app.route('/buy_ticket', methods=['GET', 'POST'])
def buy_ticket():  # Покупка билета между городами
    form = TicketForm()
    cities = City.query.order_by(City.name).all()
    form.departure_id.choices = [(c.id, c.name) for c in cities]
    form.arrival_id.choices = form.departure_id.choices
    content = '''
    <h2>{{ 'Buy Ticket' if session.get('lang','ru')=='en' else 'Купить билет' }}</h2>
    <form method="POST" class="mb-4">
      {{ form.hidden_tag() }}
      <div class="mb-3">{{ form.departure_id.label(class="form-label") }}{{ form.departure_id(class="form-select") }}</div>
      <div class="mb-3">{{ form.arrival_id.label(class="form-label") }}{{ form.arrival_id(class="form-select") }}</div>
      <button type="submit" class="btn btn-primary">{{ 'Buy' if session.get('lang','ru')=='en' else 'Купить' }}</button>
    </form>
    <a href="{{ url_for('index') }}" class="btn btn-secondary">{{ 'Back' if session.get('lang','ru')=='en' else 'Назад' }}</a>
    '''
    if form.validate_on_submit():
        if 'user_id' not in session:
            flash(
                'You must be logged in to perform this action'
                if session.get('lang','ru') == 'en'
                else 'Нельзя делать действия без авторизации', 'danger'
            )
            return render_template_string(base_page(content), form=form)
        if form.departure_id.data == form.arrival_id.data:
            flash(
                'Choose different cities!'
                if session.get('lang','ru') == 'en'
                else 'Выберите разные города!', 'danger'
            )
        else:
            db.session.add(Ticket(
                departure_id=form.departure_id.data,
                arrival_id=form.arrival_id.data,
                user_id=session['user_id']
            ))
            db.session.commit()
            flash(
                'Ticket purchased successfully!'
                if session.get('lang','ru') == 'en'
                else 'Билет успешно куплен!', 'success'
            )
            return redirect(url_for('index'))
    return render_template_string(base_page(content), form=form)


@app.route('/add_hotel', methods=['GET', 'POST'])
def add_hotel():  # Бронирование отеля пользователем
    form = HotelForm()
    cities = City.query.order_by(City.name).all()
    form.city_id.choices = [(c.id, c.name) for c in cities]
    selected_city = (
        form.city_id.data
        or (form.city_id.choices[0][0] if form.city_id.choices else None)
    )
    if request.method == 'POST' and 'city_id' in request.form:
        selected_city = int(request.form['city_id'])
        hotels = Hotel.query.filter_by(city_id=selected_city).order_by(
            Hotel.name
        ).all()
    else:
        hotels = Hotel.query.filter_by(
            city_id=selected_city
        ).order_by(Hotel.name).all() if selected_city else []
    form.hotel_id.choices = [(h.id, h.name) for h in hotels]
    content = '''
    <h2>{{ 'Hotel Booking' if session.get('lang','ru')=='en' else 'Бронирование отеля' }}</h2>
    <form method="POST" id="add-hotel-form" class="mb-4">
      {{ form.hidden_tag() }}
      <div class="mb-3">
        {{ form.city_id.label(class="form-label") }}
        {{ form.city_id(class="form-select", id="city_id", onchange="loadHotels(this.value)") }}
      </div>
      <div class="mb-3">
        {{ form.hotel_id.label(class="form-label") }}
        {{ form.hotel_id(class="form-select", id="hotel_id") }}
      </div>
      <button type="submit" class="btn btn-primary">{{ 'Book' if session.get('lang','ru')=='en' else 'Забронировать' }}</button>
    </form>
    <a href="{{ url_for('index') }}" class="btn btn-secondary">{{ 'Back' if session.get('lang','ru')=='en' else 'Назад' }}</a>
    <script>
      function loadHotels(cityId) {
        fetch('/hotels_for_city/' + cityId)
          .then(response => response.json())
          .then(data => {
            let hotelSelect = document.getElementById('hotel_id');
            hotelSelect.innerHTML = '';
            data.forEach(function(hotel) {
              let option = document.createElement('option');
              option.value = hotel.id;
              option.text = hotel.name;
              hotelSelect.appendChild(option);
            });
          });
      }
      document.addEventListener('DOMContentLoaded', function() {
        let citySelect = document.getElementById('city_id');
        if (citySelect) loadHotels(citySelect.value);
      });
    </script>
    '''
    if form.validate_on_submit():
        if 'user_id' not in session:
            flash(
                'You must be logged in to perform this action'
                if session.get('lang','ru') == 'en'
                else 'Нельзя делать действия без авторизации', 'danger'
            )
        else:
            hotel = Hotel.query.get(form.hotel_id.data)
            db.session.add(HotelBooking(
                hotel_id=hotel.id,
                city_id=hotel.city_id,
                user_id=session['user_id']
            ))
            db.session.commit()
            flash(
                f'Hotel "{hotel.name}" booked!'
                if session.get('lang','ru') == 'en'
                else f'Отель "{hotel.name}" забронирован!', 'success'
            )
            return redirect(url_for('index'))
    return render_template_string(base_page(content), form=form)


@app.route('/add_event', methods=['GET', 'POST'])
def add_event():  # Добавление нового мероприятия пользователем
    form = EventForm()
    form.city_id.choices = [
        (c.id, c.name) for c in City.query.order_by(City.name).all()
    ]
    content = '''
    <h2>{{ 'Add Event' if session.get('lang','ru')=='en' else 'Добавить мероприятие' }}</h2>
    <form method="POST" class="mb-4">
      {{ form.hidden_tag() }}
      <div class="mb-3">
        {{ form.event_name.label(class="form-label") }}
        {{ form.event_name(class="form-control") }}
      </div>
      <div class="mb-3">
        {{ form.city_id.label(class="form-label") }}
        {{ form.city_id(class="form-select") }}
      </div>
      <button type="submit" class="btn btn-primary">{{ 'Add' if session.get('lang','ru')=='en' else 'Добавить' }}</button>
    </form>
    <a href="{{ url_for('index') }}" class="btn btn-secondary">{{ 'Back' if session.get('lang','ru')=='en' else 'Назад' }}</a>
    '''
    if form.validate_on_submit():
        if 'user_id' not in session:
            flash(
                'You must be logged in to perform this action'
                if session.get('lang','ru') == 'en'
                else 'Нельзя делать действия без авторизации', 'danger'
            )
        else:
            db.session.add(Event(
                name=form.event_name.data,
                city_id=form.city_id.data,
                user_id=session['user_id']
            ))
            db.session.commit()
            flash(
                'Event added!'
                if session.get('lang','ru') == 'en'
                else 'Мероприятие добавлено!', 'success'
            )
            return redirect(url_for('index'))
    return render_template_string(base_page(content), form=form)


@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):  # Удаление мероприятия пользователя
    user_id = session.get('user_id')
    event = Event.query.filter_by(id=event_id, user_id=user_id).first()
    if event:
        db.session.delete(event)
        db.session.commit()
        flash(
            'Event deleted!'
            if session.get('lang','ru') == 'en'
            else 'Мероприятие удалено!', 'success'
        )
    else:
        flash(
            'Event not found or unauthorized.'
            if session.get('lang','ru') == 'en'
            else 'Мероприятие не найдено или не принадлежит вам.', 'danger'
        )
    return redirect(url_for('index'))


@app.route('/delete_hotel_booking/<int:booking_id>', methods=['POST'])
def delete_hotel_booking(booking_id):  # Удаление бронирования отеля пользователя
    user_id = session.get('user_id')
    booking = HotelBooking.query.filter_by(id=booking_id, user_id=user_id).first()
    if booking:
        db.session.delete(booking)
        db.session.commit()
        flash(
            'Booking deleted!'
            if session.get('lang','ru') == 'en'
            else 'Бронь удалена!', 'success'
        )
    else:
        flash(
            'Booking not found or unauthorized.'
            if session.get('lang','ru') == 'en'
            else 'Бронь не найдена или не принадлежит вам.', 'danger'
        )
    return redirect(url_for('index'))


@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):  # Удаление купленного билета пользователя
    user_id = session.get('user_id')
    ticket = Ticket.query.filter_by(id=ticket_id, user_id=user_id).first()
    if ticket:
        db.session.delete(ticket)
        db.session.commit()
        flash(
            'Ticket deleted!'
            if session.get('lang','ru') == 'en'
            else 'Билет удалён!', 'success'
        )
    else:
        flash(
            'Ticket not found or unauthorized.'
            if session.get('lang','ru') == 'en'
            else 'Билет не найден или не принадлежит вам.', 'danger'
        )
    return redirect(url_for('index'))


@app.route('/logout')
def logout():  # Выход пользователя из приложения (очистка сессии)
    session.clear()
    flash(
        'Logged out.'
        if session.get('lang','ru') == 'en'
        else 'Вы вышли из системы.', 'info'
    )
    return redirect(url_for('login'))


@app.route('/hotels_for_city/<int:city_id>')
def hotels_for_city(city_id):  # Получение списка отелей для выбранного города
    hotels = Hotel.query.filter_by(city_id=city_id).order_by(Hotel.name).all()
    return jsonify([{"id": h.id, "name": h.name} for h in hotels])


def populate_initial_cities_and_hotels():  # Заполняет БД начальными городами и отелями, если их ещё нет
    for name in POPULAR_CITIES:
        city = City.query.filter_by(name=name).first()
        if not city:
            city = City(name=name)
            db.session.add(city)
            db.session.commit()
        existing = {h.name for h in Hotel.query.filter_by(city_id=city.id)}
        for hn in HOTELS_BY_CITY.get(name, [])[:5]:
            if hn not in existing:
                db.session.add(Hotel(name=hn, city_id=city.id))
        db.session.commit()


if __name__ == '__main__':  # Создание таблиц и заполнение базовых данных, запуск приложения
    with app.app_context():
        db.create_all()
        populate_initial_cities_and_hotels()
    app.run(debug=True)
