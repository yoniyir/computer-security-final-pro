from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from app import db, mail
from app.forms import (
    LoginForm,
    RegistrationForm,
    ChangePasswordForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    AddCustomerForm,
    ResetPasswordForm2,
)
from app.models import User, Customer
from app.main import main_bp
import hashlib
import secrets
from flask_mail import Message
from datetime import datetime, timedelta

max_pass_attempts = 3





@main_bp.route("/")
@main_bp.route("/index")
def index():
    return render_template("index.html", title="Home", current_user=current_user)


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if not request.is_secure:
        return "Please use HTTPS.", 403
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Congratulations, you are now a registered user!")
        return redirect(url_for("main.login"))
    return render_template("register.html", title="Register", form=form)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if not request.is_secure:
        return "Please use HTTPS.", 403

    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if not user.check_password(form.password.data):
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()
                # Check if the user is banned
                if user.failed_login_attempts >= max_pass_attempts:
                    flash("Too many failed attempts. Please wait for one minute.")
                    return redirect(url_for("main.login"))
                flash("Invalid password")
                return redirect(url_for("main.login"))
            else:
                if user.failed_login_attempts >= max_pass_attempts and datetime.utcnow() < user.last_failed_login + timedelta(minutes=1):
                    flash("You're currently locked out. Please wait for one minute.")
                    return redirect(url_for("main.login"))
                else:
                    # If the login is successful, reset the failed attempts
                    user.failed_login_attempts = 0
                    db.session.commit()
                    login_user(user, remember=form.remember_me.data)
                    return redirect(url_for("main.index"))
        else:
            flash("Invalid username")
            return redirect(url_for("main.login"))
    return render_template("login.html", title="Sign In", form=form)



@main_bp.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not request.is_secure:
        return "Please use HTTPS.", 403
    if not current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Invalid current password")
            return redirect(url_for("main.change_password"))
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Your password has been changed.")
        return redirect(url_for("main.index"))
    elif form.is_submitted() and not form.validate():
        if not current_user.check_password(form.current_password.data):
            flash("Invalid current password")
    return render_template("change_password.html", title="Change Password", form=form)


@main_bp.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if not request.is_secure:
        return "Please use HTTPS.", 403
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = secrets.token_hex()
            user.password_reset_token = hashlib.sha1(token.encode()).hexdigest()
            db.session.commit()
            # Send the token to the user's email
            msg = f"""To reset your password, please enter the following token:
                {token}
                If you did not make this request, please ignore this email."""
            
            # Remove the newline character from the email header
            msg = msg.replace("\n", "")

            #mail.send_message(
            #    msg, sender="cyberprojhit@zohomail.com", recipients=[user.email])
            print(msg)
            flash("A password reset token has been sent to your email.", "info")
            return redirect(url_for("main.reset_password"))
        flash("No user found with that email address.", "warning")
    return render_template("forgot_password.html", form=form)


@main_bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if not request.is_secure:
        return "Please use HTTPS.", 403
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            password_reset_token=hashlib.sha1(form.token.data.encode()).hexdigest()
        ).first()
        if user:
            db.session.commit()
            flash("Valid Token.", "Now set the new password")
            return redirect(url_for("main.reset_password_2", token=form.token.data))
        flash("Invalid token.", "warning")
    return render_template("reset_password.html", form=form)

@main_bp.route("/reset_password_2", methods=["GET", "POST"])
def reset_password_2():
    if not request.is_secure:
        return "Please use HTTPS.", 403
    token = request.args.get("token")
    form = ResetPasswordForm2()
    if form.validate_on_submit():
        user = User.query.filter_by(
            password_reset_token=hashlib.sha1(token.encode()).hexdigest()
        ).first()
        user.set_password(form.new_password.data)
        user.password_reset_token = None
        db.session.commit()
        flash("Your password has been changed.")
        return redirect(url_for("main.index"))
    return render_template("reset_password_2.html", form=form)

@main_bp.route("/add_customer", methods=["GET", "POST"])
@login_required
def add_customer():
    form = AddCustomerForm()
    if form.validate_on_submit():
        if not validate_customer_name(form.customer_name.data):
            flash("Error, customer name must only contain letters.")
            return redirect(url_for("main.add_customer"))
        customer = Customer(name=form.customer_name.data, user_id=current_user.username)
        db.session.add(customer)
        db.session.commit()
        flash("New customer added.")
        return render_template("add_customer.html",customer=form.customer_name.data,add_customer_form=form)
    return render_template(
        "add_customer.html", title="Add Customer", add_customer_form=form
    )


@main_bp.route("/customers")
@login_required
def customers():
    customers = Customer.query.filter_by(user_id=current_user.username).all()
    return render_template("customers.html", title="Customers", customers=customers)


@main_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@main_bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


def validate_customer_name(name):
    # check if the name includes anything other than letters
    if not name.isalpha():
        return False
    return True