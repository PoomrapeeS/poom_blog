import flask
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import RegisterForm, LoginForm, CommentForm
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


## Initialize Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


## Create Python Decorator
def admin_only(func):
    ''' Authorized only admin to post and edit'''
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return flask.abort(403)
    return wrapper


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"  # default tablename will "blogpost" if this line isn't written.
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ***************Child Relationship*************#
    # Create Foreign Key, "users.id" the users refer to tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class
    author = relationship("User", back_populates="posts")

    #***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # This will act like a list of Blogpost objects attached to the User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# with app.app_context():
    # db.create_all()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/portfolio')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("portfolio.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        if User.query.filter_by(email=email).first() != None:
            flash("This email is already exist, Please log in instead.")
            return redirect(url_for('login', current_user=current_user))
        password = request.form.get("password")
        name = request.form.get("name")

        hash_and_satled_password = generate_password_hash(password=password,
                                                          method='pbkdf2:sha256',
                                                          salt_length=8)

        new_user = User(email=email, password=hash_and_satled_password, name=name)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")

        logged_in_user = User.query.filter_by(email=email).first()
        if logged_in_user == None:
            flash("This email does not exist, Please register first.")
            return redirect(url_for('login'))

        if logged_in_user and check_password_hash(logged_in_user.password, password):
            login_user(logged_in_user)
        else:
            flash("Password is incorrect, Please try again!")
            return redirect(url_for('login'))

        return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():   # Start to check authentication when user submit the comment
        if current_user.is_authenticated:
            # pass Object of comment_author and parent_post then it will generate id automatically
            new_comment = Comment(text=comment_form.body.data,
                                  comment_author=current_user,
                                  parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()

        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, current_user=current_user, comment_form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=5000)
