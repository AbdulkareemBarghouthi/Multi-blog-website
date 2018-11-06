import os
import webapp2
import jinja2
import re
import random
import string
import hashlib


from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

salt = "Rainbows"

# A class the includes one of the most used 
# hash functions throughout the code
class HashThings():
    def hash_string(self, s):
        return hashlib.sha512(salt + s).hexdigest()

    def secure_that_hash(self, username):
        return "%s|%s" % (username, self.hash_string(username))

# This class was copied from udacity
# basically it really helps in rendering pages 
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def validate_password_verification(self, password, verify):
        return password == verify

    def valid_username(self, username):
        # USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        USER_RE = re.compile(r"[A-Za-z]+[\d@]+[\w@]*|[\d@]+[A-Za-z]+[\w@]*")
        return USER_RE.match(username)


# This class instantiates and creates an entity 
# in the google cloud store, this entity represents 
# the logged in users and the users that use the website
class User(db.Model):
    Username = db.StringProperty(required=True)
    HashedPassword = db.StringProperty(required=True)
    Email = db.StringProperty()
    registerationDate = db.DateTimeProperty(auto_now_add=True)


# This class instantiates and creates an entity 
# in the google cloud store, this entity represents 
# the posts uploaded by the users
class BlogPost(db.Model):
    Title = db.StringProperty(required=True)
    Content = db.TextProperty(required=True)
    Comments = db.ListProperty(basestring)
    Likes = db.IntegerProperty(0)
    Dislikes = db.IntegerProperty(0)
    TimeUploaded = db.DateTimeProperty(auto_now_add=True)
    user = db.ReferenceProperty(User,
                                collection_name="blog_posts")

# This class basically handles all signup functionalities 
# from storing the user to prompting him to the main 
# page, this also includes all exceptions that might 
# let the user do any unautherized actions
class SignUpPage(Handler, HashThings):
    def get(self):
        self.render("signup.html")

    def post(self):
        # get all needed form fields from the http header
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("Verify")
        email = self.request.get("email")
        check = User.all().filter('Username =', username).get()

        # If statements that ensures that the user entered right input
        # , first if statement ensures that the user won't leave field empty
        # , second else if validates if the password and the verify fields match
        # , third if else makes sure that the user entered valid usernames and 
        # password policies 
        if (not username or not password or not verify):
            self.render("signup.html", error="""Ooops, looks like there
                        is something that you left empty!""")
        elif (not self.validate_password_verification(password, verify)):
            self.render("signup.html", verifyError="""The password did not match
                        it's verification! try again""")
        elif (not self.valid_username(username) or
              not self.valid_username(password)):
            self.render("signup.html", verifyError="""invalid Input! Username or password
                                             must have a combination
                                             of letters and numbers""")

        # Hash the password and create user cookie
        hashed_password = self.hash_string(password)
        hashed_username = self.secure_that_hash(username)

        # Validates if the user exists, if not then create a new
        # column in the database for the user
        try:
            if (check.key()):
                self.render("signup.html", verifyError="""User already exists,
                                                       Try Another username""")
        except:
            user = User(Username=username,
                        HashedPassword=hashed_password)
            if email:
                user = User(Email=email)
            user.put()
            self.response.headers.add_header('Set-cookie',
                                             'user_id=%s; Path=/'
                                             % str(hashed_username))
            self.redirect("/blog/main")
        # # since users signups he's automatically logged in


class MainPage(Handler):
    def get(self):
        # Retrieve all blog posts and post them on the main page
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        if not cookieHolder:
            self.render("errorPage.html",
                        error="Seems like you're not signed in")
        else:
            allPosts = db.GqlQuery("SELECT * FROM BlogPost \
                                    ORDER BY TimeUploaded DESC")
            user = User.all().filter("Username =", cookieHolder).get()
            self.render("mainpage.html", allPosts=allPosts, user=user)


class UploadPage(Handler):
    def get(self):
        # Check if a user is logged in
        cookieCheck = self.request.cookies.get("user_id")

        if not cookieCheck:
            self.render("errorPage.html", error="""You cannot upload
                                                a post without signing in""")
        else:
            self.render("uploadpage.html")

    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        if title and content:
    # Whoever logged in (Cookie holder) will own this blog post
            cookieHolder = self.request.cookies.get('user_id').split("|")[0]
    # this is to create a foreign key in
    # for the user in each of his blog posts
            uploaderName = User.all().filter('Username =', cookieHolder).get()
    # Update a blog post relating the user currently signed in
            blogPost = BlogPost(Title=title,
                                Content=content,
                                user=uploaderName,
                                Likes=0,
                                Dislikes=0)
            blogPost.put()
            self.redirect("/blog/" + str(blogPost.key().id()))
        else:
            self.render("uploadpage.html", error="""Make sure
                                                 you have filled everything""")


class SinglePost(Handler):
    # Retrieve a single post after uploading or requesting 
    #  to enter the post itself
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        SinglePost = db.get(key)
        self.render("mainpage.html", SinglePost=SinglePost)


class SignOut(Handler):
    # Make sure that the user is signed in
    # , if so sign him out then delete the cookie
    def get(self):
        if (not self.request.cookies.get("user_id")):
            self.render("errorPage.html", error="""You are not signed
                                                in to signout!""")
        else:
            self.response.headers.add_header('Set-cookie', 'user_id=; Path=/')
            self.redirect('/blog/signup')


class LoginPage(Handler, HashThings):
    def get(self):
        self.render("login.html")

    def post(self):
        # Retrieve user's input through http header
        username = self.request.get("username")
        password = self.request.get("password")

        # Hash the passwords and secure them 
        # , store a cookie for the user
        hashed = self.secure_that_hash(username)
        hashed_cookie = self.request.cookies.get("user_id")

        # Check if input fields are populated
        if (not username or not password):
            self.render("login.html", error="Please fill in all credentials!")
            return

        # if there exists a cookie then redirect to main page 
        # , in summary make sure a cookie was created
        if (hashed_cookie is not None):
            self.redirect('/blog/main')

        user = User.all().filter("Username =", username).get()

        # Handle the possibility of the user not being retrieved 
        # then make sure that the password matches the hash and 
        # grant access to the user, also handle if the user exists or not
        if user:
            if (self.hash_string(password) == user.HashedPassword):
                self.redirect('/blog/main')
                self.response.headers.add_header(
                    'Set-Cookie',
                    'user_id=%s; Path=/'
                    % str(self.secure_that_hash(username)))
            else:
                self.render("login.html", error="Wrong password! Try Again")
        else:
            self.render("login.html", error="User doesn't exist Try again")


class deletePost(Handler):
    # Get the post by the idea and delete the designated post
    # if the user doesn't own the post then don't authorize him
    def get(self, post_id):
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if (cookieHolder !=
                post.user.Username):
            self.render("EditDelete.html", ack="""You are not Authorized
                                               to delete this post""")
        else:
            post.delete()
            self.render("EditDelete.html", ack="Post Deleted!")


class editPost(Handler):
    # Make sure that the logged in user owns the post and 
    # give him the priviledge to edit the post
    def get(self, post_id):
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if (cookieHolder !=
                post.user.Username):
            self.render("EditDelete.html", ack="""You not authorized
                                                to edit this post!""")
        else:
            self.render("EditPage.html", post=post)

    def post(self, post_id):
        # Take user's input from the http header
        # then update the entity with user's new edit
        newTitle = self.request.get("title")
        newContent = self.request.get("content")

        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        post.Title = newTitle
        post.Content = newContent
        post.put()
        self.render("EditDelete.html", ack="Post edited successfully")


class commentPage(Handler):
    # add comment functionality get function displays comments
    # based on the foreign key created in the BlogPost entity
    def get(self, post_id):
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if (cookieHolder ==
                post.user.Username):
            self.render("EditDelete.html", ack="""You cannot comment
                                                on your own post""")
        else:
            self.render("comments.html")

    def post(self, post_id):
        # Create a comment then add it to the foreign key
        # of blogPost entity
        comment = self.request.get("comment")
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        post.Comments.append(comment)
        post.put()
        self.render("EditDelete.html", ack="Comment Uploaded")


class likeFunction(Handler):
    # Iterate the likes in the users entity and make sure
    # that the user doesn't like his own post 
    def get(self, post_id):
        allPosts = BlogPost.all()
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if (cookieHolder == post.user.Username):
            self.render("mainpage.html", allPosts=allPosts,
                        ack="you can't like your own post")
        else:
            post.Likes += 1
            post.put()
            self.render("mainpage.html", allPosts=allPosts)


class dislikeFunction(Handler):
    # Iterate the dislike in the users entity and make sure
    # that the user doesn't dislike his own post (who would)
    def get(self, post_id):
        allPosts = BlogPost.all()
        cookieHolder = self.request.cookies.get("user_id").split("|")[0]
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if (cookieHolder == post.user.Username):
            self.render("mainpage.html", allPosts=allPosts,
                        ack="you can't dislike your own post")
        else:
            post.Dislikes += 1
            post.put()
            self.render("mainpage.html", allPosts=allPosts)


app = webapp2.WSGIApplication([('/blog/main', MainPage),
                               ('/blog/signup', SignUpPage),
                               ('/blog/upload', UploadPage),
                               ('/blog/(\d+)', SinglePost),
                               ('/blog/signout', SignOut),
                               ('/blog/login', LoginPage),
                               ('/blog/delete/(\d+)', deletePost),
                               ('/blog/edit/(\d+)', editPost),
                               ('/blog/comment/(\d+)', commentPage),
                               ('/blog/like/(\d+)', likeFunction),
                               ('/blog/dislike/(\d+)', dislikeFunction)
                               ],
                              debug=True)
