from flask import Flask, flash, render_template, url_for, redirect, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
import pandas as pd

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class DataForTraining(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aluminium = db.Column(db.Float, nullable=False)
    chromium = db.Column(db.Float, nullable=False)
    cobalt = db.Column(db.Float, nullable=False)
    copper = db.Column(db.Float, nullable=False)
    lead = db.Column(db.Float, nullable=False)
    manganese = db.Column(db.Float, nullable=False)


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class AddDataForm(FlaskForm):
    aluminium = FloatField('Aluminium', validators=[DataRequired()])
    chromium = FloatField('Chromium', validators=[DataRequired()])
    cobalt = FloatField('Cobalt', validators=[DataRequired()])
    copper = FloatField('Copper', validators=[DataRequired()])
    lead = FloatField('Lead', validators=[DataRequired()])
    manganese = FloatField('Manganese', validators=[DataRequired()])
    submit = SubmitField('Add Data')


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('Username not found. Please register.', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = AddDataForm()
    if form.validate_on_submit():
        new_data = DataForTraining(
            aluminium=form.aluminium.data,
            chromium=form.chromium.data,
            cobalt=form.cobalt.data,
            copper=form.copper.data,
            lead=form.lead.data,
            manganese=form.manganese.data
        )
        db.session.add(new_data)
        db.session.commit()
        flash('Data added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Error occurred during registration. Please try again later.', 'danger')
    return render_template('register.html', form=form)


@app.route('/fetch_training_data', methods=['GET'])
@login_required
def fetch_training_data():
    try:
        data = DataForTraining.query.all()
        data_dict = []
        for item in data:
            data_dict.append({
                'aluminium': item.aluminium,
                'chromium': item.chromium,
                'cobalt': item.cobalt,
                'copper': item.copper,
                'lead': item.lead,
                'manganese': item.manganese
            })
        return jsonify(data_dict)
    except Exception as e:
        return str(e), 500


@app.route('/upload_data', methods=['POST'])
@login_required
def upload_data():
    if 'dataFile' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['dataFile']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if file:
        try:
            # Read CSV file into a Pandas DataFrame
            df = pd.read_csv(file)

            # Iterate through each row and save to database
            for index, row in df.iterrows():
                new_data = DataForTraining(
                    aluminium=row['aluminium'],
                    chromium=row['chromium'],
                    cobalt=row['cobalt'],
                    copper=row['copper'],
                    lead=row['lead'],
                    manganese=row['manganese']
                )
                db.session.add(new_data)

            db.session.commit()
            flash('File uploaded and data saved successfully to data.db', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard or any other relevant route

        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            return redirect(request.url)

    return redirect(request.url)


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'DataForTraining': DataForTraining}


if __name__ == "__main__":
    app.run(debug=True)
