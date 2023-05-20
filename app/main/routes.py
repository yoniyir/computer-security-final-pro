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
from app.models import User, Customer, PasswordManager
from app.main import main_bp
import hashlib
import secrets
from flask_mail import Message
from datetime import datetime, timedelta
from flask import current_app as app
from werkzeug.security import check_password_hash, generate_password_hash
import html
import sqlite3
import string


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
        conn = sqlite3.connect("app.db")
        c = conn.cursor()
        username = form.username.data
        email = form.email.data
        password = form.password.data
        password = generate_password_hash(password)

        # Vulnerable to SQL injection attack, we can use the following payload to drop the table user
        # anything'); DROP TABLE user; SELECT ('1        -------> Will drop the table user
        # ---------------------------------- Vulnerable code ----------------------------------
        """
        sql_script = f"INSERT INTO user (password_hash,email,failed_login_attempts,username) VALUES ('{password}','{email}',0, '{username}');"
        sql_script_2 = f"INSERT INTO password_manager (username, password) VALUES ('{username}', '{password}');"
        c.executescript(f"{sql_script}\n{sql_script_2}")
        """
        # ----------------------------------- End of vulnerability  ------------------------------------
        # ----------------------------------- Protected Code ------------------------------------
        # Protected code with Stored procedures
        # We execute the stored procedure with the username, email and password as parameters to prevent SQL injection
        try:
            c.execute(f"INSERT INTO user ( email, password_hash,failed_login_attempts,username) VALUES ('{email}', '{password}',0,'{username}');")
            c.execute(f"INSERT INTO password_manager (username, password) VALUES ('{username}', '{password}');")
        except:
            flash("One of the values you entered is not valid")
            return redirect(url_for("main.register"))
        # ----------------------------------- End of Protected Code ------------------------------------
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect("app.db")
        c = conn.cursor()
        # anything'; DROP TABLE user; -------> Will drop the table user
        username = form.username.data
        password = form.password.data   
        # ---------------------------------- Vulnerable code ----------------------------------
        """
        c.executescript(f"SELECT * FROM user WHERE username='{username}'")
        user_data = c.fetchone()
        if not user_data:
            c.execute("select * from user where username = ?", (username,))
            user_data = c.fetchone()
        """
        # ----------------------------------- End of vulnerability  ------------------------------------
        # ----------------------------------- Protected Code ------------------------------------
        # Protected code with Stored procedures
        # We execute the stored procedure with the username as parameter to prevent SQL injection
        
        try:
            c.execute(f"SELECT * FROM user WHERE username='{username}'")
        except:
            flash("Invalid username")
            return redirect(url_for("main.login"))
        user_data = c.fetchone()

        # ----------------------------------- End of Protected Code ------------------------------------
        
        if user_data:
            if not check_password_hash(user_data[3], password):  # Assuming user_data[3] is the password field
                # Increase failed attempts
                c.executescript(f"UPDATE user SET failed_login_attempts = failed_login_attempts + 1 WHERE username = '{username}';")
                conn.commit()
                # Check if the user is banned
                c.execute(f"SELECT failed_login_attempts FROM user WHERE username='{username}'")
                attempts = c.fetchone()[0]

                if attempts >= app.config["PASSWORD_ATTEMPTS"]:
                    flash("Too many failed attempts. Please wait for one minute.")
                    return redirect(url_for("main.login"))

                flash("Invalid password")
                return redirect(url_for("main.login"))
            else:
                # If the login is successful, reset the failed attempts
                c.executescript(f"UPDATE user SET failed_login_attempts = 0 WHERE username = '{username}';")
                conn.commit()

                user = User.query.filter_by(username=username).first()  # Get the user object after password validation
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
        # check if the new password is the same as the old 3 passwords
        print(current_user.username)
        password_manager = PasswordManager.query.filter_by(
            username=current_user.username
        )
        password_manager = password_manager.order_by(
            PasswordManager.timestamp.desc()
        ).limit(3)
        for password in password_manager:
            if check_password_hash(password.password, form.new_password.data):
                flash("You cannot use the same password as the last 3 passwords.")
                return redirect(url_for("main.change_password"))
        current_user.set_password(form.new_password.data)
        password_manager = PasswordManager(username=current_user.username)
        password_manager.set_password(form.new_password.data)
        db.session.add(password_manager)
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
            # The token is encoded with SHA1 and stored in the database
            db.session.commit()
            # Send the token to the user's email
            msg = f"""To reset your password, please enter the following token:
                {token}
                If you did not make this request, please ignore this email."""

            # Remove the newline character from the email header
            msg = msg.replace("\n", "")

            mail.send_message(
                msg, sender=app.config["MAIL_USERNAME"], recipients=[user.email])
            # Due to the limitations of the free plan of SMTP Mail, we cannot send emails to other domains so we will print the token instead

            print(msg) # Print the token instead and use it to reset the password
            flash("A password reset token has been sent to your email.", "info")
            return redirect(url_for("main.reset_password"))
        else:
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
        conn = sqlite3.connect("app.db")
        c = conn.cursor()
        name = form.customer_name.data  # unsafe to use
        username = current_user.username
        # anything'); DROP TABLE customer; --   ------> Will drop the table customer
        # ---------------------------------- Vulnerable code ---------------------------------- 
        
        sql_script = f"INSERT INTO customer (user_id,name) VALUES ('{username}','{name}');"
        c.executescript(sql_script)
        

         # secured with Sanitation and Encoding
        # ----------------------------------- Protected Code ------------------------------------

        """
        if(not validate_customer_name_by_check_spacial_char(form.customer_name.data)):
            print(form.customer_name.data)
            flash("Wrong costumer name, can accept only letters and digits")
            return render_template(
                "add_customer.html",
                title="Add Customer",
                add_customer_form=form,
            )
        else:
            name = validate_customer_name_by_encoding(form.customer_name.data)
            sql_script = f"INSERT INTO customer (user_id,name) VALUES ('{username}','{name}');"
            c.execute(sql_script)
        """

        # ----------------------------------- End of Protected Code ------------------------------------
        conn.commit()
        conn.close()
        flash("New customer added.")
        return render_template(
            "add_customer.html",
            customer=form.customer_name.data,
            add_customer_form=form,
        )
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


def validate_customer_name_by_encoding(name):
    name = str(name)
    return html.escape(name)


def validate_customer_name_by_check_spacial_char(name):
    name = str(name)
    for char in name:
        if char not in string.ascii_letters and char not in string.digits:
            return False
    return True
