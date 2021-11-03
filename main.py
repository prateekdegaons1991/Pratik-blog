import smtplib
from functools import wraps
import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug import Response
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, CKEditorField
import datetime
from forms import RegisterForm, CreatePostForm, Login, CommentsForm
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import json

import json

with open("config.json") as c:
    param = json.load(c)["params"]


app = Flask(__name__)
app.config['SECRET_KEY'] = param['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Admin only Decorator
def admin_only(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        try:
            if not current_user.is_authenticated or current_user.id != 1:
                abort(403, "Admin Access Needed")
        except AttributeError:
            abort(401)
        else:
            return f(*args, **kwargs)

    return decorator_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = param['DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


# Create the User Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Create all the tables in the database
db.create_all()


@app.route('/')
@login_required
def get_all_posts():
    return render_template("index.html", all_posts=BlogPost.query.order_by(BlogPost.date),
                           date=datetime.date.today().year)


@app.route("/post/<int:index>", methods=['POST', 'GET'])
@login_required
def show_post(index):
    form = CommentsForm()
    requested_post = BlogPost.query.get(index)
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', index=index))
    return render_template("post.html", post=requested_post, form=form, date=datetime.date.today().year)


@app.route('/create_post', methods=['POST', 'GET'])
# @admin_only
def create_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author_id=current_user.id,
            img_url=form.img_url.data,
            body=form.body.data,
            date=datetime.date.today(
            )
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=form, date=datetime.date.today().year)


@app.route("/edit/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    form = CreatePostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=form, is_edit=True, date=datetime.date.today().year)


@app.route('/delete/<int:post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", date=datetime.date.today().year)


@app.route("/contact", methods=['POST', 'GET'])
@login_required
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        phone = request.form.get('phone')

        # Send Mail
        try:
            # SMTP Connection Creation
            connection = smtplib.SMTP("smtp.gmail.com")
            connection.starttls()
            connection.login(
                user=param['user_email'],
                password=param['user_email_pass']
            )
            connection.sendmail(from_addr=param['user_email'],
                                to_addrs=param['user_email'],
                                msg=f"Subject:Mail From {name}:{email} \n\n{message}\nphone:{phone}")
            connection.close()
        except (smtplib.SMTPException, smtplib.SMTPAuthenticationError, smtplib.SMTPConnectError,
                smtplib.SMTPSenderRefused) as e:
            print(e)
            return redirect(url_for('contact'))
        else:
            return redirect(url_for('thank_you'))
    else:
        return render_template("contact.html", date=datetime.date.today().year)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(request.form.get("password"),
                                                 method='pbkdf2:sha256',
                                                 salt_length=8
                                                 )
        new_user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            # Send Mail
            # SMTP Connection Creation
            connection = smtplib.SMTP("smtp.gmail.com")
            connection.starttls()
            connection.login(
                user=param['user_email'],
                password=param['user_email_pass']
            )
            connection.sendmail(from_addr=param['user_email'],
                                to_addrs=param['user_email'],
                                msg=f"Subject:User {new_user.name} Registered!! \n\n"
                                    f"Name:{new_user.name}"
                                    f"Email ID: {new_user.email}")
            connection.close()
        except (smtplib.SMTPException, smtplib.SMTPAuthenticationError, smtplib.SMTPConnectError,
                smtplib.SMTPSenderRefused, sqlalchemy.exc.IntegrityError) as e:
            flash("Email Id already registered. Login Instead!")
            return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
    return render_template("register.html", form=form, date=datetime.date.today().year)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The email does not exists, please try again! ")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, date=datetime.date.today().year)


@app.route('/thankyou')
@login_required
def thank_you():
    return render_template("thankyou.html", date=datetime.date.today().year)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    # app.run(host='localhost', port=5000)
    app.run(debug=True)
