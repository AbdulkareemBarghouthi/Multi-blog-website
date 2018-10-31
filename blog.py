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
        
        if not username or not password or not verify:
            self.render("signup.html", error="Ooops, looks like there is something that you left empty!")
        if not self.validate_password_verification(password, verify):
            self.render("signup.html", verifyError = "The password did not match it's verification! try again")
        if not self.valid_username(username) or not self.valid_username(password):
            self.render("signup.html", verifyError = """invalid Input! Username or password 
                                             must have a combination of letters and numbers""")
        
        hashed_password = self.hash_string(password)
        hashed_username = self.secure_that_hash(username)

        check = User.all()
        something = check.filter('Username =', username)
        if something:
            self.render("signup.html", verifyError = "The user already exists")
        else:
            user = User(Username=username,
                        HashedPassword=hashed_password)
            if email:
                user = User(Email = email)
            user.put()
        # since users signups he's automatically logged in
        self.response.headers.add_header('Set-cookie', 'user_id=%s; Path=/blog/main' % str(hashed_username))
        self.redirect("/blog/main")
        
class MainPage(Handler):
    def get(self):
        self.render("mainpage.html")  

class UploadPage(Handler):
    def get(self):
        self.render("uploadpage.html")     

app = webapp2.WSGIApplication([('/blog/main', MainPage),
                            ('/blog/signup', SignUpPage),
                            ('/blog/upload', UploadPage)], debug=True)
