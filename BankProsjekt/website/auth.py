from io import BytesIO
from flask import Blueprint, app, render_template, request, flash, redirect, url_for, session,abort, escape
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import pyqrcode
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
from .forms import RegisterForm, LoginForm
from .models import Account, Transaction, User
from flask_sqlalchemy import SQLAlchemy
from wtforms.validators import ValidationError
from .models import Account, User
import uuid
from datetime import datetime, timedelta


auth = Blueprint("auth", __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(email_address=escape(form.email_address.data)).first()
        if not attempted_user:
            flash("You have entered invalid information1. Please try again")
            return redirect(url_for('auth.login'))
        if attempted_user.block_login_timestamp != None:
            if  attempted_user.block_login_timestamp > datetime.now():
                flash("You haven't waited 10 minutes yet!")
                return redirect(url_for('auth.login'))
        if attempted_user and attempted_user.check_password_correction(
            attempted_password=escape(form.password.data)) and attempted_user.verify_totp(token=escape(form.token.data)):
            login_user(attempted_user)
            attempted_user.failed_logins = 0
            attempted_user.login_timestamp = datetime.now()
            flash(f'Success! You are logged in as: {escape(attempted_user.first_name)}', category='success')
            attempted_user.block_login_timestamp = None
            return redirect(url_for('auth.home'))
        if attempted_user:
            attempted_user.failed_logins += 1
            if attempted_user.failed_logins > 3:
                attempted_user.block_login_timestamp = datetime.now() + timedelta(minutes=10)
                flash("You have entered the wrong information too many times! Please wait 10 minutes.") 
                return redirect(url_for('auth.login'))
            else:
                flash("You have entered invalid information. Please try again")
                return redirect(url_for('auth.login'))
    return render_template('login.html', form=form)


@auth.route("/accounts", methods=["GET", "POST"])
@login_required
def accounts(): 
    if current_user.check_login_time(datetime.now()):
        if request.method == "POST":
            pass  
        return render_template("accounts.html", user=current_user)
    else:
        flash("You have not logged in in 30 minutes. Please login again.")
        logout_user()
        return redirect(url_for('auth.login'))


@auth.route("/accounts/create_account", methods=["GET", "POST"])
@login_required
def create_account():
    if current_user.check_login_time(datetime.now()):
        running = True
        if request.method == "POST":
            while running:
                account_name = escape(request.form.get("account_name"))
                account_number = escape(str(uuid.uuid4()))
                account_balance = int(request.form.get("amount"))
                account_description = escape(str(request.form.get("account_description")))
                if account_balance > 10000:
                    flash("The maximum you can borrow on a single account is 10000 USD.")
                    running = False
                elif account_balance < 0:
                    flash("Account can not have negative balance")
                    running = False
                elif account_number == Account.query.filter_by(account_number=account_number).first():
                    flash("WOOOW a glitch in the matrix! The random account number that was generated is a match with one of our current customers! For your inconvinience, we will gift you 10000$")
                    account_balance += 10000
                elif len(account_description) > 160:
                    flash("The max length of the the description is 160 char! please try again.")
                else:
                    new_account = Account(user_id=current_user.id, account_name=account_name, account_balance=account_balance, account_number=account_number, account_description=account_description)
                    db.session.add(new_account)
                    db.session.commit()
                    flash(f"Account ({account_name}) created", category="sucess")
                    running = False
        return render_template("create_account.html", user=current_user)
    else:
        flash("You have not logged in in 30 minutes. Please login again.")
        logout_user()
        return redirect(url_for('auth.login'))


@auth.route("/accounts/transaction", methods=["GET", "POST"])
@login_required
def transaction():
    if current_user.check_login_time(datetime.now()):
        if request.method == "POST":
            account_name_out = escape(request.form.get("account_name"))
            amount = request.form.get("amount")
            account_number_in = escape(request.form.get("account_number"))
            trans_msg = escape(request.form.get("message"))
            if int(amount) < 1:
                flash("Transaction amount must be a number, and can not be negative or zero")
                running = False
            else:
                running = True
            if trans_msg == None:
                    trans_msg = "No message was given"
            elif len(trans_msg) > 160:
                flash("Message can be max 160 characters")
                running = False
            while running:
                try:
                    account_outbound = Account.query.filter_by(account_name=account_name_out, user_id=current_user.id).first()
                except:
                    flash("You do not have an account by that name.")
                    break
                try:
                    account_receiving = Account.query.filter_by(account_number=account_number_in).first()
                    if account_receiving == None:
                        flash("No account with that account number exists")
                        break
                except: 
                    flash("There exists no accounts with that account number.")
                    break
                try:
                    if account_outbound.account_balance - int(amount) < 0:
                        flash("Insufficient funds")
                        break
                    else:
                        account_outbound.account_balance = account_outbound.account_balance - int(amount)
                        db.session.commit()
                except:
                    flash(f"The transaction could not complete")
                    break
                try:
                    account_receiving.account_balance = account_receiving.account_balance + int(amount)
                    db.session.commit()
                except:
                    flash("There was an error with the transaction")
                    break
                flash(f"{amount} was succesfully sent to {account_number_in}", category="sucess")
                try:
                    new_transaction = Transaction(user_id_out=current_user.id, user_id_in=account_receiving.user_id,
                    trans_amount=amount, account_in_number=account_number_in, account_in_name=account_receiving.account_name, 
                    account_out_number=account_outbound.account_number, account_out_name=account_name_out, trans_msg=trans_msg)
                    db.session.add(new_transaction)
                    db.session.commit()
                    break
                except:
                    flash("There was an error with the transaction! Try again")
                    break


        return render_template("transaction.html", user=current_user)
    else:
        flash("You have not logged in in 30 minutes. Please login again.")
        logout_user()
        return redirect(url_for('auth.login'))
        

@auth.route("/accounts/log", methods=['GET', 'POST'])
@login_required
def log():
    if current_user.check_login_time(datetime.now()):
        return render_template("log.html", user=current_user, out=Transaction.query.filter_by(user_id_out=current_user.id).all(),
        inbound = Transaction.query.filter_by(user_id_in=current_user.id).all())
    else:
        flash("You have not logged in in 30 minutes. Please login again.")
        logout_user()
        return redirect(url_for('auth.login'))


@auth.route("/")
@auth.route("/welcome")
def welcome():
    return render_template("welcome.html")


@auth.route("/home")
@login_required
def home():
    if current_user.check_login_time(datetime.now()):
        return render_template("home.html", user=current_user)
    else:
        flash("You have not logged in in 30 minutes. Please login again.")
        logout_user()
        return redirect(url_for('auth.login'))


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email_address=form.email_address.data).first():
            flash("This email is already in use!")
            return redirect(url_for('auth.signup'))
        user_to_create = User(first_name=escape(form.first_name.data),email_address=escape(form.email_address.data), password=escape(form.password1.data))  
        for letter in form.password1.data:
            check = letter.isupper()
            if check == True:
                break
            else:
                check == False
        if check == False:
            flash("Password must have at least one capital letter in it")
            return redirect(url_for('auth.signup'))
        for number in form.password1.data:
            check2 = number.isdigit()
            if check2 == True:
                break
            else:
                check2 == False
        if check2 == False:
            flash("The password must contain at least one number.")
            return redirect(url_for('auth.signup'))
        user_to_create.login_timestamp = datetime.now()
        user_to_create.failed_logins = 0
        db.session.add(user_to_create)
        db.session.commit()
        flash(f'Account created! Please follow instructions to authenticate your account', category='success')
        session['email_address'] = user_to_create.email_address
        return redirect(url_for('auth.tfa'))

    return render_template('signup.html', form=form)

@auth.route('/tfa')
def tfa():
    if 'email_address' not in session:
        return redirect(url_for('auth.welcome'))
    new_user = User.query.filter_by(email_address=escape(session['email_address'])).first()

    if new_user is None:
        return redirect(url_for('auth.login'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it """
    return render_template('tfa.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@auth.route('/qrcode')
def qrcode():
    if 'email_address' not in session:
        print("email not found in session")
        abort(404)
    new_user = User.query.filter_by(email_address=escape(session['email_address'])).first()
    if new_user is None:
        print(f"User not found with email:" + session["email_adress"] )
        abort(404)

    # for added security, remove username from session
    del session['email_address']

    # render qrcode for FreeTOTP
    otp_uri = new_user.get_totp_uri()
    print(f"OTP URI is \"" + otp_uri + "\"")
    img = pyqrcode.create(otp_uri)
    print(f"SVG URL is something")
    stream = BytesIO()
    img.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


