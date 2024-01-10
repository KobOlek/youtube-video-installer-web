import os
import string

from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from pytube import YouTube
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_ngrok import run_with_ngrok
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
run_with_ngrok(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///video.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQL_ALCHEMY_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class VideoDownloader:
    def __init__(self, link):
        self.__link = link

    def download(self):
        video = YouTube(self.__link)
        video = video.streams.get_highest_resolution()
        title = get_right_title(video.title)
        video.download(filename=title + ".mp4",
                       output_path=os.path.join(os.getcwd(), "static/1/video"))

    def get_video_title(self):
        title = YouTube(self.__link).streams.get_highest_resolution().title
        return title


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register", render_kw={"class": "btn btn-success"})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username is already taken")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login", render_kw={"class": "btn btn-success"})


class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    link = db.Column(db.String, nullable=False, unique=True)
    path = db.Column(db.String, nullable=False, unique=True)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Video %r>' % self.id


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


with app.app_context():
    db.create_all()


def get_right_title(title):
    new_title = title
    for i, _ in enumerate(title):
        if title[i] in string.punctuation:
            new_title = new_title.replace(title[i], "")
    return new_title

video_link = ""
@app.route("/<int:id>/", methods=["POST", "GET"])
def index(id):
    global video_link
    if request.method == "POST":
        link = request.form["link"]

        video_link = link

        videoDownloader = VideoDownloader(link)
        videoDownloader.download()

        title = videoDownloader.get_video_title()

        path = url_for('static', filename=f'/1/video/{title}.mp4')

        video = Video(link=link, title=title, path=path, user_id=id)

        try:
            db.session.add(video)
            db.session.commit()
            return render_template("success.html", id=id)
        except Exception as e:
            return str(e)
    return render_template("index.html", id=id)


@app.route('/<int:id>/download')
def download_file(id):
    global video_link
    video = Video.query.filter_by(link=video_link).first()
    title = get_right_title(video.title)
    file = os.path.join(os.getcwd(), "static/1/video/")+f"{title}.mp4"
    return send_file(file, as_attachment=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/<int:id>/history/")
def history(id):
    videos = Video.query.filter_by(user_id=int(id)).order_by(Video.id).all()
    return render_template("history.html", videos=videos, id=id)


@app.route("/<int:id>/delete/<int:video_id>/", methods=["POST", "GET"])
def delete_video(id, video_id):
    video = Video.query.filter_by(id=video_id).first()

    if request.method == "POST":
        try:
            db.session.delete(video)
            db.session.commit()
            return render_template("success.html", id=id)
        except:
            return "Something went wrong"
    return render_template("delete.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index', id=user.id))
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index', id=new_user.id))

    return render_template("register.html", form=form)


if __name__ == "__main__":
    app.run()
