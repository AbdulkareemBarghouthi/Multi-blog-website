import os
import webapp2
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db 
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= True)

def make_salt():
    return "".join(random.choice(string.letters) for i in xrange(5))

salt = make_salt()
class HashThings():
    def hash_string(self, s):
        return hashlib.sha512(salt + s).hexdigest()
    
    def check_secure_hash(self, s):
        if s == hash_string(password):
            return True
        return False
    
    def secure_that_hash(self, username):
        return "%s|%s" % (username, self.hash_string(username))

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

class User(db.Model):
    Username = db.StringProperty(required = True)
    HashedPassword = db.StringProperty(required = True)
    Email = db.StringProperty()
    registerationDate = db.DateTimeProperty(auto_now_add = True)

class BlogPost(db.Model): 
    Title = db.StringProperty(required = True)
    Content = db.TextProperty(required = True)
    TimeUploaded = db.DateTimeProperty(auto_now_add = True)
    user = db.ReferenceProperty(User,
                                collection_name="blog_posts")


class MainPage(Handler):
    def get(self):
        self.write("Hello, World")

    def post(self):
        pass

class SignUpPage(Handler, HashThings):
    def get(self):
        self.render("signup.html")
    
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("Verify")
        email = self.request.get("email")
        check = User.all().filter('Username =', username).get()
        
        if not username or not password or not verify:
            self.render("signup.html", error="Ooops, looks like there is something that you left empty!")
        elif not self.validate_password_verification(password, verify):
            self.render("signup.html", verifyError = "The password did not match it's verification! try again")
        elif not self.valid_username(username) or not self.valid_username(password):
            self.render("signup.html", verifyError = """invalid Input! Username or password 
                                             must have a combination of letters and numbers""")
        # elif userExists == 0:
        #     self.render("signup.html", verifyError = "The user already exists")
        # else:
        #     self.write("everything worked fine!")

        hashed_password = self.hash_string(password)
        hashed_username = self.secure_that_hash(username)

        try:
            if check.key(): 
                self.render("signup.html", verifyError = "User already exists, unlike god and relegions and the purpose of life")
        except:
            user = User(Username=username,
                    HashedPassword=hashed_password)
            if email:
                user = User(Email = email)
            user.put()
            self.response.headers.add_header('Set-cookie', 'user_id=%s; Path=/blog/main' % str(hashed_username))
            self.response.headers.add_header('Set-cookie', 'user_id=%s; Path=/blog/upload' % str(hashed_username))
            self.redirect("/blog/main")
            
        # # since users signups he's automatically logged in
        
        
class MainPage(Handler):
    def get(self):
        self.render("mainpage.html")  
    
    def post(self):
        Retrieve all posts and display them to the main page
        allPosts = User.all().get()

class UploadPage(Handler):
    def get(self):
        self.render("uploadpage.html")

    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        if not title or not content:
            self.render("uploadpage.html", error="Make sure you have filled everything")
        
        # Whoever logged in (Cookie holder) will own this blog post
        cookieHolder = self.request.cookies.get('user_id').split("|")[0]
        
        # this is to create a foreign key in for the user in each of his blog posts
        uploaderName = User.all().filter('Username =', cookieHolder).get()

        # Update a blog post relating the user currently signed in
        blogPost = BlogPost(Title = title,
                Content = content,
                user = uploaderName)
        blogPost.put()
        
        self.redirect("/blog/" + str(blogPost.key().id()))
        
class SinglePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        SinglePost = db.get(key)
        self.render("mainpage.html", SinglePost = SinglePost)
        


app = webapp2.WSGIApplication([('/blog/main', MainPage),
                            ('/blog/signup', SignUpPage),
                            ('/blog/upload', UploadPage),
                            ('/blog/(\d+)', SinglePost)], debug=True)
