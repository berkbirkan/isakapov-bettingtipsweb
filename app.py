import os
import json
import base64
import requests
import schedule
import threading
import time
from datetime import datetime,timedelta
from flask import Flask
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from collections import defaultdict
from flask_admin import BaseView, expose
from flask_admin import helpers as admin_helpers
import logging
import urllib.parse
import stripe
import uuid
from flask import send_from_directory









# Configure logging anaanın amı ebenin amı
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'


# SQLAlchemy ayarını güncelle
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv("DATABASE_URL", "postgresql://postgres:nStVzf5xlG8b8KD0WtgRRaFLtMLvNf1V6qJ8FZ7NRUDSWKazyzATwEAqF06qMgmJ@b0w8oo8g8k8gc04s0s8osow4:5432/postgres")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'YOUR_MAİL_SERVER'
app.config['MAIL_PORT'] = 587 # default to 587 if MAIL_PORT is not set
app.config['MAIL_USERNAME'] = 'YOUR_EMAİL'
app.config['MAIL_PASSWORD'] = 'YOUR_EMAİL_PASS'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['DEBUG'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'Betting Tips'
mail = Mail(app)

stripe.api_key = 'STRIPE_LİVE_SECRET_KEY'
endpoint_secret = 'STRIPE_ENDPOİNT_SECRET'

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"




# Kök dizine bir route ekleyin
@app.route('/')
def landing_page():
    today = datetime.utcnow().date()
    
    # Fetch the betting tips for today and result is '1'
    betting_tips = BettingTip.query.filter(
        db.func.date(BettingTip.match_date) == today,
        BettingTip.result == '1'
    ).all()
    
    # Check if there are no tips for today, then fetch from yesterday
    if not betting_tips:
        yesterday = today - timedelta(days=1)
        betting_tips = BettingTip.query.filter(
            db.func.date(BettingTip.match_date) == yesterday,
            BettingTip.result == '1'
        ).all()
        header_text = "Here are just a few of the matches we have successfully analyzed yesterday!"
    else:
        header_text = "Here are just a few of the matches we have successfully analyzed today!"
    
    # Filter for leagues with short names and prepare the data
    analyses = [
        {
            "league_name": tip.league_name,
            "home_team": tip.team_home_name,
            "home_logo": tip.team_home_logo,
            "away_team": tip.team_away_name,
            "away_logo": tip.team_away_logo,
            "score": tip.fulltime,
            "prediction": tip.prediction_name
        }
        for tip in betting_tips if len(tip.league_name) <= 100
    ]
    
    return render_template('index.html', analyses=analyses, header_text=header_text)



# Assets klasörü için bir route ekleyin
@app.route('/assets/<path:filename>')
def custom_static(filename):
    return send_from_directory('assets', filename)




# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(256), unique=True, nullable=True)
    created_date = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    subscription_id = db.Column(db.String(80), unique=True, nullable=True)
    renewal_date = db.Column(db.DateTime, nullable=True)
    package = db.Column(db.String(80), nullable=True,default='Free')  # Add this line if package attribute is needed
    

class BettingTip(db.Model):
    id = db.Column(db.String, primary_key=True)
    match_date = db.Column(db.DateTime, nullable=False)
    league_name = db.Column(db.String, nullable=False)
    league_logo = db.Column(db.String, nullable=True)
    league_flag = db.Column(db.String, nullable=True)
    team_home_name = db.Column(db.String, nullable=False)
    team_home_logo = db.Column(db.String, nullable=True)
    team_away_name = db.Column(db.String, nullable=False)
    team_away_logo = db.Column(db.String, nullable=True)
    prediction_type = db.Column(db.String, nullable=False)
    prediction_name = db.Column(db.String, nullable=False)
    prediction_rate = db.Column(db.Float, nullable=False)
    halftime = db.Column(db.String, nullable=True)
    fulltime = db.Column(db.String, nullable=True)
    odds = db.Column(db.String, nullable=True)
    result = db.Column(db.String, nullable=True)

class LiveScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league_name = db.Column(db.String(120), nullable=False)
    league_logo = db.Column(db.String(256), nullable=True)
    league_flag = db.Column(db.String(256), nullable=True)
    team_home_name = db.Column(db.String(120), nullable=False)
    team_home_logo = db.Column(db.String(256), nullable=True)
    team_away_name = db.Column(db.String(120), nullable=False)
    team_away_logo = db.Column(db.String(256), nullable=True)
    livescore = db.Column(db.String(20), nullable=True)
    halftime = db.Column(db.String(20), nullable=True)
    fulltime = db.Column(db.String(20), nullable=True)
    elapsed = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), nullable=True)


class APISettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(256), nullable=False)
    is_api_active = db.Column(db.Boolean, default=False, nullable=False)


with app.app_context():
    db.create_all()

    # Admin kullanıcısını kontrol et ve oluştur
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@admin.com',
            password=generate_password_hash('123123123'),
            is_premium=True,
            is_admin=True,
            api_key=str(uuid.uuid4()),  # API anahtarı gerekiyorsa
            package='Premium'  # İsteğe bağlı olarak paket bilgisi
        )
        db.session.add(admin_user)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    # recaptcha = RecaptchaField()
    submit = SubmitField('Register')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Admin views
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        status = request.args.get('status')
        if status == 'success':
            flash('Payment was successful!', 'success')
        elif status == 'fail':
            flash('Payment failed. Please try again.', 'error')
        return self.render('admin/home.html')

class UserAdmin(ModelView):
   

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def on_model_change(self, form, User, is_created):
        if form.password.data:
            User.password = generate_password_hash(form.password.data)

class BettingTipAdmin(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    @expose('/')
    def index_view(self):
        if current_user.is_admin:
            return super(BettingTipAdmin, self).index_view()
        
class BettingTipsUser(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    @expose('/')
    @login_required
    def index(self):
        if current_user:
            run_update_user_subscription(current_user.id)
        # Fetch betting tips from the database
        now = datetime.utcnow()
        one_day_ago = now - timedelta(days=1)
        
        tips = BettingTip.query.filter(BettingTip.match_date >= one_day_ago).all()

        # Filter tips to limit result=2 to a maximum of 3
        result_2_tips = [tip for tip in tips if tip.result == '2']
        if len(result_2_tips) > 3:
            result_2_tips = result_2_tips[:3]
        
        # Merge filtered result=2 tips with other tips
        other_tips = [tip for tip in tips if tip.result != '2']
        tips = other_tips + result_2_tips
        
        # Group tips by league name
        grouped_tips = defaultdict(list)
        league_info = {}
        for tip in tips:
            grouped_tips[tip.league_name].append(tip)
            if tip.league_name not in league_info:
                league_info[tip.league_name] = {
                    "name": tip.league_name,
                    "logo": tip.league_logo
                }
        
        # Pass grouped tips and league info to the template
        return self.render('admin/betting_tips.html', grouped_tips=grouped_tips, league_info=league_info)


def update_user_subscription(user_id):
    # Fetch the user from the database
    user = User.query.get(user_id)
    if not user:
        return {"error": "User not found"}

    subscription_id = user.subscription_id

    # Check if the subscription ID is valid
    if subscription_id and subscription_id.startswith("sub_"):
        try:
            # Retrieve subscription details from Stripe
            subscription = stripe.Subscription.retrieve(subscription_id)

            if subscription['status'] == 'active':
                # Update user's renewal date with Stripe subscription's renewal date
                renewal_date = datetime.utcfromtimestamp(subscription['current_period_end'])
                user.renewal_date = renewal_date
            else:
                # If subscription is no longer active, update package ID and set renewal date to NULL
                user.package = 'Free'
                user.is_premium = False
                user.renewal_date = None

            db.session.commit()
            return {"message": "User subscription updated successfully"}
        except stripe.error.InvalidRequestError as e:
            # Handle invalid subscription ID error
            return {"error": f"Invalid subscription ID: {str(e)}"}
        except Exception as e:
            # Handle other exceptions
            return {"error": f"An error occurred: {str(e)}"}
    else:
        return {"error": "Invalid or missing subscription ID"}

def run_update_user_subscription(user_id):
    # Create a thread to run the update_user_subscription function
    thread = threading.Thread(target=update_user_subscription, args=(user_id))
    thread.start()
    return {"message": "User subscription update initiated in the background"}



# New function to fetch live scores
def fetch_live_scores():
    api_settings = APISettings.query.first()
    if not api_settings or not api_settings.is_api_active:
        logger.info("API is inactive. Skipping fetch_live_scores.")
        return {}

    api_url = 'https://bettipspro.com/api/live-scores'  # Replace with actual API base URL
    headers = {
        "Email": api_settings.email,
        "API-Key": api_settings.api_key
    }
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        logger.error("Failed to fetch live scores: %s", response.status_code)
        return {}


class APIDocumentation(BaseView):
    @expose('/')
    @login_required
    def index(self):
        return self.render('api_info.html')
        

class LiveScoreAdmin(ModelView):
    def is_accessible(self):
        return current_user.is_admin

    @expose('/')
    def index_view(self):
        if current_user.is_admin:
            return super(LiveScoreAdmin, self).index_view()
        

# New LiveScoreUser ModelView class
class LiveScoreUser(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    @expose('/')
    @login_required
    def index(self):
        if current_user:
            run_update_user_subscription(current_user.id)
        # Fetch live scores from the API
        live_scores = fetch_live_scores()
        
        # Group live scores by league name
        grouped_scores = defaultdict(list)
        league_info = {}
        for match_id, match in live_scores.get('football', {}).items():
            league = match.get('league', {})
            home_team = match.get('team_home', {})
            away_team = match.get('team_away', {})
            
            league_name = league.get('name')
            grouped_scores[league_name].append(match)
            if league_name not in league_info:
                league_info[league_name] = {
                    "name": league_name,
                    "logo": league.get('logo', '')
                }
        
        # Pass grouped scores and league info to the template
        return self.render('live_scores.html', grouped_scores=grouped_scores, league_info=league_info)






admin = Admin(app, name='IsaKapov BettipsPanels', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(UserAdmin(User, db.session))
admin.add_view(APISettings(APISettings,db.session))
admin.add_view(BettingTipsUser(BettingTip, db.session, endpoint='betting_tips_user_view'))
admin.add_view(BettingTipAdmin(BettingTip, db.session))
admin.add_view(LiveScoreUser(LiveScore, db.session, endpoint='live_scores_user_view'))
admin.add_view(APIDocumentation(name='API Documentation', endpoint='api_documentation'))






admin.add_view(LiveScoreAdmin(LiveScore, db.session))



def fetch_data_from_api(api_url, username, password):
    response = requests.get(api_url, auth=(username, password))
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching data: {response.status_code}")
        return None


# Scheduled tasks
def fetch_and_store_betting_tips():
    with app.app_context():
        # Fetch API settings from the database
        api_settings = APISettings.query.first()
        if not api_settings or not api_settings.is_api_active:
            logger.info("API is inactive. Skipping fetch_and_store_betting_tips.")
            return

        api_url = 'https://bettipspro.com/api/betting-tips'  # Replace with actual API base URL
        headers = {
            "Email": api_settings.email,
            "API-Key": api_settings.api_key
        }
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            for match_id, match in data.get('football', {}).items():
                try:
                    league = match.get('league', {})
                    home_team = match.get('team_home', {})
                    away_team = match.get('team_away', {})
                    prediction = match.get('prediction', {})
                    extras = match.get('extras', {})

                    existing_tip = BettingTip.query.get(match_id)
                    
                    if existing_tip:
                        # Update existing record
                        existing_tip.match_date = datetime.utcfromtimestamp(int(match.get('date', 0)))
                        existing_tip.league_name = league.get('name', '')
                        existing_tip.league_logo = league.get('logo', '')
                        existing_tip.league_flag = league.get('flag', '')
                        existing_tip.team_home_name = home_team.get('name', '')
                        existing_tip.team_home_logo = home_team.get('logo', '')
                        existing_tip.team_away_name = away_team.get('name', '')
                        existing_tip.team_away_logo = away_team.get('logo', '')
                        existing_tip.prediction_type = prediction.get('type', '')
                        existing_tip.prediction_name = prediction.get('name', '')
                        existing_tip.prediction_rate = float(prediction.get('rate', 0))
                        existing_tip.halftime = extras.get('halftime', '')
                        existing_tip.fulltime = extras.get('fulltime', '')
                        existing_tip.odds = extras.get('odds', '')
                        existing_tip.result = match.get('result', '')
                    else:
                        # Add new record
                        betting_tip = BettingTip(
                            id=match_id,
                            match_date=datetime.utcfromtimestamp(int(match.get('date', 0))),
                            league_name=league.get('name', ''),
                            league_logo=league.get('logo', ''),
                            league_flag=league.get('flag', ''),
                            team_home_name=home_team.get('name', ''),
                            team_home_logo=home_team.get('logo', ''),
                            team_away_name=away_team.get('name', ''),
                            team_away_logo=away_team.get('logo', ''),
                            prediction_type=prediction.get('type', ''),
                            prediction_name=prediction.get('name', ''),
                            prediction_rate=float(prediction.get('rate', 0)),
                            halftime=extras.get('halftime', ''),
                            fulltime=extras.get('fulltime', ''),
                            odds=extras.get('odds', ''),
                            result=match.get('result', '')
                        )
                        db.session.add(betting_tip)
                except Exception as e:
                    logger.error("Error processing betting tip: %s", e)

            try:
                db.session.commit()
            except Exception as e:
                logger.error("Error committing session: %s", e)
                db.session.rollback()
        else:
            logger.error("Failed to fetch data: %s", response.status_code)

        # Delete matches older than 1 week
        one_week_ago = datetime.utcnow() - timedelta(weeks=1)
        old_tips = BettingTip.query.filter(BettingTip.match_date < one_week_ago).all()
        for old_tip in old_tips:
            db.session.delete(old_tip)
        
        try:
            db.session.commit()
        except Exception as e:
            logger.error("Error committing session during old tips deletion: %s", e)
            db.session.rollback()


def check_all_premium_users():
    print('')
    users = User.query.filter(User.subscription_id.startswith("sub_"))
    for user in users:
        update_user_subscription(user.id)

    #update_user_subscription


def fetch_and_store_live_scores():
    with app.app_context():
        api_url = 'https://json.tipsterman.com/v4/scores'
        username = 'QU'
        password = 'pMg5pEWgTXgHbvDCxAXkztCTafq5CQP7'
        response = requests.get(api_url, auth=(username, password))

        if response.status_code == 200:
            data = response.json()
            for match in data.get('football', {}).values():
                league = match.get('league', {})
                home_team = match.get('team_home', {})
                away_team = match.get('team_away', {})

                league_name = league.get('name')
                home_team_name = home_team.get('name')
                away_team_name = away_team.get('name')

                # Check if required fields are present
                if not all([league_name, home_team_name, away_team_name]):
                    logger.warning("Missing league or team names in match: %s", match)
                    continue

                try:
                    live_score = LiveScore(
                        league_name=league_name,
                        league_logo=league.get('logo', ''),
                        league_flag=league.get('flag', ''),
                        team_home_name=home_team_name,
                        team_home_logo=home_team.get('logo', ''),
                        team_away_name=away_team_name,
                        team_away_logo=away_team.get('logo', ''),
                        livescore=match.get('livescore', ''),
                        halftime=match.get('halftime', ''),
                        fulltime=match.get('fulltime', ''),
                        elapsed=match.get('elapsed', ''),
                        status=match.get('status', '')
                    )
                    db.session.add(live_score)
                except Exception as e:
                    logger.error("Error adding live score to session: %s", e)

            try:
                db.session.commit()
            except Exception as e:
                logger.error("Error committing session: %s", e)
                db.session.rollback()
        else:
            logger.error("Failed to fetch data: %s", response.status_code)



def fetch_and_store_betting_tips_scheduled():
    api_settings = APISettings.query.first()
    if api_settings and api_settings.is_api_active:
        fetch_and_store_betting_tips()
    else:
        logger.info("API is inactive. Skipping fetch_and_store_betting_tips.")

def fetch_live_scores_scheduled():
    api_settings = APISettings.query.first()
    if api_settings and api_settings.is_api_active:
        fetch_and_store_live_scores()
    else:
        logger.info("API is inactive. Skipping fetch_and_store_live_scores.")

# Schedule the tasks
schedule.every(5).minutes.do(fetch_and_store_betting_tips_scheduled)
schedule.every(1).minutes.do(fetch_live_scores_scheduled)
schedule.every(1).minutes.do(check_all_premium_users)



def run_scheduler():
    with app.app_context():
        while True:
            schedule.run_pending()
            time.sleep(1)

# Start the scheduler in a separate thread
scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()

# Routes for user authentication and data access
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = generate_password_hash(form.password.data)
        api_key = str(uuid.uuid4())  # Benzersiz API anahtarı oluştur

        # Check if the email is already registered
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            error = "Email already registered"
            return render_template('register.html', form=form, error=error)

        # Check if the username is already taken
        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            error = "Username already registered"
            return render_template('register.html', form=form, error=error)

        # Create a new user instance
        new_user = User(username=username, email=email, password=password, api_key=api_key, is_premium=False, is_admin=False,package='Free')
        db.session.add(new_user)
        db.session.commit()

        # Automatically log in the user and redirect to the panel
        login_user(new_user)
        return redirect(url_for('admin.index'))

    return render_template('register.html', form=form)





@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            msg = Message('Password Reset Request', sender='support@neuralabz.limited', recipients=[email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Your password reset link is {link}. This link will expire in 1 hour.'
            mail.send(msg)
            message = "A password reset link has been sent to your email."
            return render_template('forgot_password.html', form=form, message=message)
        else:
            error = "This email is not registered."
            return render_template('forgot_password.html', form=form, error=error)
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiration
    except SignatureExpired:
        return render_template('reset_password.html', error="The reset link has expired. Please request a new link.")

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match.", token=token)

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)



@app.route('/create-checkout-session', methods=['GET'])
def create_checkout_session():
    price_id = request.args.get('price_id')
    user_id = request.args.get('user_id')

    if not price_id or not user_id:
        return jsonify(error="Missing required parameters"), 400

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('admin.index', _external=True) + '?status=success',
            cancel_url=url_for('admin.index', _external=True) + '?status=fail',
            metadata={'user_id': user_id}
        )
        return redirect(session.url, code=303)
    except stripe.error.StripeError as e:
        print(f"Stripe error: {e.user_message}")
        return jsonify(error=str(e.user_message)), 400
    except Exception as e:
        print(f"Exception: {str(e)}")
        return jsonify(error=str(e)), 400

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        print("Invalid payload")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print("Invalid signature")
        return jsonify({'error': 'Invalid signature'}), 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']
        subscription_id = session['subscription']

        try:
            # Fetch the subscription details
            subscription = stripe.Subscription.retrieve(subscription_id)

            if subscription['status'] != 'active':
                print("Subscription is not active")
                return jsonify({'error': 'Subscription is not active'}), 400

            renewal_date = datetime.utcfromtimestamp(subscription['current_period_end'])

            # Fetching the line items
            line_items = stripe.checkout.Session.list_line_items(session['id'])
            price_id = line_items['data'][0]['price']['id']

            user = User.query.get(user_id)

            if user:
                if 'price_1PigFyDDedIabPkxUelxZ3gp' in price_id:
                    user.package = 'PremiumAnnual'
                    user.is_premium = True
                elif 'price_1PigFYDDedIabPkx14Jzrrbt' in price_id:
                    user.package = 'PremiumMonthly'
                    user.is_premium = True
                else:
                    print("Unknown price ID")
                    return jsonify({'error': 'Unknown price ID'}), 400

                user.subscription_id = subscription_id
                user.renewal_date = renewal_date
                db.session.commit()

        except stripe.error.InvalidRequestError as e:
            # Invalid subscription ID
            print("Invalid subscription ID")
            return jsonify({'error': 'Invalid subscription ID'}), 400
        except Exception as e:
            # Other errors
            print(f"Error: {e}")
            return jsonify({'error': 'An error occurred'}), 400

    return '', 200


@app.route('/live-scores-view')
@login_required
def live_scores_view():
    if current_user:
        run_update_user_subscription(current_user.id)

    scores = LiveScore.query.with_entities(
        LiveScore.id, LiveScore.league_name, LiveScore.team_home_name,
        LiveScore.team_home_logo, LiveScore.team_away_name, LiveScore.team_away_logo,
        LiveScore.livescore, LiveScore.halftime, LiveScore.fulltime,
        LiveScore.elapsed, LiveScore.status
    ).all()
    return render_template('live_scores.html', scores=scores)

@app.route('/betting-tips')
@login_required
def betting_tips():
    if current_user.is_admin:
        return redirect(url_for('admin.index'))
    return redirect(url_for('betting_tips'))

@app.route('/live-scores')
@login_required
def live_scores():
    if current_user.is_admin:
        return redirect(url_for('admin.index'))
    return redirect(url_for('live_scores_view'))


@app.route('/api/betting-tips')
def api_betting_tips():
    email = request.headers.get('Email')
    api_key = request.headers.get('API-Key')
    user = User.query.filter_by(email=email, api_key=api_key).first()
    if not user:
        return jsonify({"error": "Your email or api key is wrong."}), 401
    if not user.is_premium:
        return jsonify({"error": "You should upgrade to premium for access API."}), 401
    
    api_settings = APISettings.query.first()
    if not api_settings or not api_settings.is_api_active:
        return jsonify({"error": "API is currently inactive."}), 503
    
    run_update_user_subscription(user.id)
    if user and user.is_premium:
        # Fetch data from the new API
        api_url = 'https://bettipspro.com/api/betting-tips'  # Replace with actual API base URL
        headers = {
            "Email": api_settings.email,
            "API-Key": api_settings.api_key
        }
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch betting tips from API."}), 500
        
        data = response.json()
        return jsonify(data)
    else:
        return jsonify({"error": "Unauthorized"}), 401

    
@app.route('/api/live-scores')
def api_live_scores():
    email = request.headers.get('Email')
    api_key = request.headers.get('API-Key')
    user = User.query.filter_by(email=email, api_key=api_key).first()
    if not user:
        return jsonify({"error": "Your email or api key is wrong."}), 401
    
    if not user.is_premium:
        return jsonify({"error": "You should upgrade to premium for access API."}), 401
    
    api_settings = APISettings.query.first()
    if not api_settings or not api_settings.is_api_active:
        return jsonify({"error": "API is currently inactive."}), 503
    
    run_update_user_subscription(user.id)
    
    if user and user.is_premium:
        # Fetch data from the new API
        api_url = 'https://bettipspro.com/api/live-scores'  # Replace with actual API base URL
        headers = {
            "Email": api_settings.email,
            "API-Key": api_settings.api_key
        }
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch live scores from API."}), 500
        
        live_scores = response.json()
        return jsonify(live_scores)
    else:
        return jsonify({"error": "Unauthorized"}), 401


# Create tables and run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5017,debug=False,host='0.0.0.0')