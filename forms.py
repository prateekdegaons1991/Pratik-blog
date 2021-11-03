from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators, PasswordField
from wtforms.validators import DataRequired, URL
from wtforms.fields.html5 import EmailField
from flask_ckeditor import CKEditor, CKEditorField

app = Flask(__name__)


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", [validators.DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up")


class Login(FlaskForm):
    email = EmailField("Email", [validators.DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class CommentsForm(FlaskForm):
    comment = CKEditorField("Comments", validators=[DataRequired()])
    submit = SubmitField("Comment")
