# Computer Security Course: SQL and XSS Attack Demonstration App

This is a demonstration application developed for the computer security course. Its primary purpose is to illustrate potential SQL and XSS (Cross-Site Scripting) vulnerabilities within a web application. It is a great educational tool for understanding these types of web application vulnerabilities and how they might be exploited.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [App Overview](#app-overview)
- [File Descriptions](#file-descriptions)

## Getting Started

### Prerequisites

Before starting, please ensure you have Python installed on your system. This project uses a virtual environment (venv), which helps manage Python dependencies. 
In order to run the app, install our certificates on Google Chrome.


### Installation

1. Clone the repository.
2. Navigate into the project directory.
3. Create a virtual environment: 
    ```
    python -m venv venv
    ```
4. Activate the virtual environment:
    - On Windows:
        ```
        venv\Scripts\activate
        ```
    - On Unix or MacOS:
        ```
        source venv/bin/activate
        ```
5. Install the necessary dependencies using the requirements.txt file:
    ```
    pip install -r requirements.txt
    ```
6. Run the application:
    ```
    python run.py
    ```

## App Overview

The application revolves around user and customer data, and demonstrates potential security vulnerabilities involving user passwords and customer information.
Our app uses TLS 1.2 and SSL Protocol


## Application Routes

The application's routes are defined in `routes.py`. These functions define how the application should respond to client requests to particular URLs. Each of the routes is associated with a function that runs when the route is requested.

- **/** or **/index**: These routes return the home page of the application.

- **/register**: This route allows new users to register an account. It includes protection against SQL injection attacks.

- **/login**: This route allows users to log in to the application. It includes protection against SQL injection attacks and implements a limit on failed login attempts.

- **/change_password**: This route allows authenticated users to change their password, ensuring it's not the same as the last three used.

- **/forgot_password**: This route enables users to request a password reset token if they've forgotten their password.

- **/reset_password** and **/reset_password_2**: These routes allow a user to reset their password using the token sent to them.

- **/add_customer**: This authenticated route lets users add a new customer to the database. It includes sanitization and encoding to protect against SQL injection attacks.

- **/customers**: This authenticated route displays all the customers associated with the logged-in user.

- **/logout**: This route logs the user out of the application.

Note: For added security, all routes verify that they are being accessed over a secure HTTPS connection. If not, a 403 error is returned.

The `validate_customer_name_by_encoding` and `validate_customer_name_by_check_spacial_char` functions are used to sanitize and validate the customer names before they're added to the database.

## File Descriptions

`models.py`: This file contains the database models for the application. There are three models - User, Customer, and PasswordManager. 

- `User`: This model represents the users of the system. Each user has a unique id, username, and email. Passwords are securely hashed using the Werkzeug library. This model also tracks failed login attempts and timestamps for security purposes.

- `Customer`: This model represents the customers that are associated with a user.

- `PasswordManager`: This model is used to manage hashed passwords for different usernames, and includes a timestamp for each entry.



`forms.py`: This file contains all the forms used in the application. Each form is built with Flask-WTF and has various fields that are validated depending on their purpose. Here are the forms included:

- `RegistrationForm`: This form is used for user registration. It validates if a username and email already exist in the database, and it checks the password against common passwords and the criteria set in the configuration file.

- `ChangePasswordForm`: This form is used when a user wants to change their password. It validates the current password and also checks the new password against the same criteria as in the RegistrationForm.

- `LoginForm`: This form is used for user login.

- `ForgotPasswordForm`: This form is used when a user forgets their password and wants to request a password reset.

- `ResetPasswordForm`: This form is used to validate a reset token when a user has requested a password reset.

- `ResetPasswordForm2`: This form is used for the user to enter a new password after the reset token has been validated.

- `AddCustomerForm`: This form is used to add a new customer to the system.

## App Usage

To run the application:

1. Start by registering a new user.
2. Log in using the registered user credentials.
3. Use the provided forms to change password, reset password, and add customers.
4. Observe the potential security vulnerabilities related to SQL and XSS attacks.

## Configuration

The configuration settings for the application are stored in `config.py`. This file contains several configuration options for the Flask application and the SQLite database, Flask-Mail settings, as well as settings for password complexity.

- `SECRET_KEY`: This is used to secure sessions and protect against cross-site request forgery (CSRF). You should set this to a random value in production.
  
- `SQLALCHEMY_DATABASE_URI`: This is the location of the database. By default, it uses an SQLite database file named `app.db` located in the same directory as the `config.py` file.

- `SQLALCHEMY_TRACK_MODIFICATIONS`: This is set to False to disable an SQLAlchemy feature that we don't need, which would otherwise consume some extra memory.

- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_USERNAME`, `MAIL_PASSWORD`: These settings are used for Flask-Mail configuration. 

- `PASSWORD_LENGTH`, `PASSWORD_UPPERCASE`, `PASSWORD_LOWERCASE`, `PASSWORD_DIGITS`, `PASSWORD_SPECIAL_CHARS`, `PASSWORD_ATTEMPTS`, `COMMON_PASSWORDS`: These are the settings for password complexity and security. They define the minimum length, character requirements, maximum attempts, and common passwords file.




base.html
---------
This is the base template for the application. It includes the HTML skeleton structure and blocks for other templates to override. It usually includes elements like the navigation bar, footer, and common styles or scripts.

index.html
----------
This is the home page of the application. It extends base.html and fills in blocks with content specific to the home page.

register.html
-------------
This page provides a registration form for new users. Users can input their details to create a new account. This template extends base.html.

login.html
----------
This page provides a login form for users. Users can input their credentials to log in to the application. This template extends base.html.

change_password.html
--------------------
This page provides a form for users to change their password. Users can input their current and new password. This template extends base.html.

forgot_password.html
--------------------
This page provides a form for users to reset their password in case they've forgotten it. Users can input their email address to receive a password reset link. This template extends base.html.

add_customer.html
-----------------
This page provides a form for users to add a new customer. Users can input customer details. This template extends base.html.

reset_password.html
-------------------
This page is used for users to input their reset token they received by email after filling out the forgot_password form. This template extends base.html.

reset_password_2.html
---------------------
This page is used for users to input their new password after their reset token has been validated. This template extends base.html.
