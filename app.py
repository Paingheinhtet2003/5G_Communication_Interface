import os
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

# Flask-WTF Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(1, 128)])
    submit = SubmitField("Login")

class MessageForm(FlaskForm):
    message = StringField("Message", validators=[DataRequired(), Length(1, 256)])
    submit = SubmitField("Send")

@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        if (
            username == os.getenv("ADMIN_USERNAME")
            and check_password_hash(os.getenv("ADMIN_PASSWORD_HASH"), password)
        ):
            session.clear()
            session["username"] = username
            session["messages"] = []
            flash("Login successful.", "success")
            return redirect(url_for("main"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/main", methods=["GET", "POST"])
def main():
    if "username" not in session:
        flash("You must be logged in.", "warning")
        return redirect(url_for("login"))
    form = MessageForm()
    sent_message = None
    messages = session.get("messages", [])
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            # Here, you could call a C++ module or any backend logic.
            messages.append(message)
            session["messages"] = messages
            sent_message = message
    return render_template(
        "main.html",
        username=session["username"],
        sent_message=sent_message,
        messages=messages,
        form=form
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# Error Handlers
@app.errorhandler(400)
def bad_request(e):
    return "Bad request!", 400

@app.errorhandler(404)
def not_found(e):
    return "Not found!", 404

@app.errorhandler(500)
def server_error(e):
    return "Internal server error!", 500

if __name__ == "__main__":
    app.run(debug=True)