from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///theevents.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)


class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    # Добавляем отношения
    hotels = db.relationship('Hotel', backref='city', lazy=True)
    events = db.relationship('Event', backref='city', lazy=True)


class Hotel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)


# Формы
class CityForm(FlaskForm):
    city_name = StringField('Город', validators=[DataRequired()])
    submit = SubmitField('Добавить город')


class HotelForm(FlaskForm):
    hotel_name = StringField('Отель', validators=[DataRequired()])
    city_id = SelectField('Город', coerce=int)
    submit = SubmitField('Добавить отель')


class EventForm(FlaskForm):
    event_name = StringField('Мероприятие', validators=[DataRequired()])
    city_id = SelectField('Город', coerce=int)
    submit = SubmitField('Добавить мероприятие')


# Маршруты
@app.route('/')
def index():
    cities = City.query.all()
    return render_template('index.html', cities=cities)


@app.route('/add_city', methods=['GET', 'POST'])
def add_city():
    form = CityForm()
    if form.validate_on_submit():
        new_city = City(name=form.city_name.data)
        db.session.add(new_city)
        db.session.commit()
        flash('Город добавлен!', 'success')
        return redirect(url_for('index'))
    return render_template('add_city.html', form=form)


@app.route('/add_hotel', methods=['GET', 'POST'])
def add_hotel():
    form = HotelForm()
    form.city_id.choices = [(city.id, city.name) for city in City.query.all()]
    if form.validate_on_submit():
        new_hotel = Hotel(name=form.hotel_name.data, city_id=form.city_id.data)
        db.session.add(new_hotel)
        db.session.commit()
        flash('Отель добавлен!', 'success')
        return redirect(url_for('index'))
    return render_template('add_hotel.html', form=form)


@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    form = EventForm()
    form.city_id.choices = [(city.id, city.name) for city in City.query.all()]
    if form.validate_on_submit():
        new_event = Event(name=form.event_name.data, city_id=form.city_id.data)
        db.session.add(new_event)
        db.session.commit()
        flash('Мероприятие добавлено!', 'success')
        return redirect(url_for('index'))
    return render_template('add_event.html', form=form)


# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)
