# 10% of final grade.
# Due Wed. 4th March 2015 - end of the day.
# All code in Python, GAE, and webapp2.
# Deploy on GAE.


import os
import base64
import re

import webapp2
import jinja2
from google.appengine.api import mail
from webapp2_extras import sessions

import a2pb

JINJA = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True,
)
class Navigator:
    MainPage = '/main_page'
    class Registration:
        Form = '/register'
        Process = '/register/process'
    class Login:
        Form = '/login'
        Process = '/login/process'
    class Email:
        Confirmation = '/activate/'
        PasswordReset = '/password_reset/'
    PasswordResetForm = '/password_reset'
    Logout = '/logout'
    Root = '/'
    Link = '/navigate'
    @staticmethod
    def CSS(file):
        return '/css/%s' % file
    @staticmethod
    def JS(file):
        return '/js/%s' % file

class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

class NavigatorHandler(BaseHandler):
    def get(self):
        template = JINJA.get_template('html/navigator.html')
        self.response.write(template.render(
            {
                'uid': self.session.get('uid')
            }
        ))


class MainPageHandler(BaseHandler):
    def get(self):
        uid = self.session.get('uid')
        if not uid:
            return self.redirect(Navigator.Login.Form)

        user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
        user = user.filter(a2pb.User.id==self.session.get('uid')).get()
        template = JINJA.get_template('html/main_page.html')
        if user.confirmed:
            pages = [
                {'name': 'Page 1', 'url': '/page1'},
                {'name': 'Page 2', 'url': '/page2'},
                {'name': 'Page 3', 'url': '/page3'},
            ]
            return self.response.write(template.render(
                {
                    'title': 'Main Page',
                    'user': user,
                    'pages': pages
                }
            ))
        return self.response.write(template.render(
            {
                'title': 'Main Page',
                'user': user,
                'msg': 'Your account has not been activated yet!'
            }
        ))

class LoginHandler(BaseHandler):
    def get(self):
        if self.session.get('uid'):
            return self.redirect(Navigator.MainPage)
        # Display the LOGIN form.
        template = JINJA.get_template('html/login.html')
        return self.response.write(template.render(
            {
                'title': 'Welcome to the Login Page'
            }
        ))

    def post(self):
        if self.session.get('uid'):
            return self.redirect(Navigator.MainPage)
        # Check that a login and password arrived from the FORM.
        userid = self.request.get('userid')
        passwd = self.request.get('passwd')
        msg = None
        if userid == '' or passwd == '':
            msg ='Please fill all fields!'
        # Lookup login ID in "confirmed" datastore.
        else:
            user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
            user = user.filter(a2pb.User.id == userid).get()
            if not user:
                msg = 'User id "%s" not found.' % userid
            # Check for password match.
            elif user.password != passwd:
                msg = 'Wrong password.'
        if msg:
            template = JINJA.get_template('html/login.html')
            return self.response.write(template.render(
                {
                    'title': 'Welcome to the Login Page',
                    'msg': msg
                }
            ))
        # Set the user as logged in and let them have access to /page1, /page2, and /page3.  SESSIONs.
        self.session['uid'] = userid
        return self.redirect(Navigator.MainPage)
# What if the user has forgotten their password?  Provide a password-reset facility/form.
class PasswordResetFormHandler(BaseHandler):
    def get(self):
        if self.session.get('uid'):
            user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
            user = user.filter(a2pb.User.id==self.session.get('uid')).get()
            template = JINJA.get_template('html/passwd_reset_form.html')
            return self.response.write(template.render(
                {
                    'title': 'Password Reset',
                    'user': user
                }
            ))
        return self.redirect(Navigator.Root)
    def post(self):
        if self.session.get('uid'):
            success = False
            passwd = self.request.get('passwd')
            passwd2 = self.request.get('passwd2')
            if passwd == '' or passwd2 == '':
                msg = 'Please fill all fields.'
            elif passwd != passwd2:
                msg = 'Passwords typed not the same!'
            elif len(passwd) < 6:
                msg = 'The length of password should not be less than 6.'
            elif passwd.isdigit() or passwd.isalpha():
                msg = 'Password too simple. (all digits or all alphabets)'
            else:
                user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
                user = user.filter(a2pb.User.id==self.session.get('uid')).get()
                user.password = passwd
                user.put()
                msg = 'Your password has been changed.'
                success = True
            template = JINJA.get_template('html/passwd_reset_form_process.html')
            return self.response.write(template.render(
                {
                    'title': 'Password Reset',
                    'msg': msg,
                    'success': success
                }
            ))

class PasswordResetHandler(BaseHandler):
    def get(self, code=None):
        if code:
            passwd_reset = a2pb.PasswordReset.query(ancestor=a2pb.ParentKeys.PasswordReset)
            passwd_reset = passwd_reset.filter(a2pb.PasswordReset.code==code).get()
            if passwd_reset:
                self.session['uid'] = passwd_reset.user_id
                passwd_reset.key.delete()
            else:
                template = JINJA.get_template('html/passwd_reset_process.html')
                return self.response.write(template.render(
                    {
                        'title': 'Password Reset',
                        'msg': 'Unknown Code',
                        'success': False
                    }
                ))
        if self.session.get('uid'):
            return self.redirect(Navigator.PasswordResetForm)
        template = JINJA.get_template('html/passwd_reset.html')
        return self.response.write(template.render(
            {
                'title': 'Password Reset'
            }
        ))
    def post(self, code=None):
        if self.session.get('uid'):
            return self.redirect(Navigator.MainPage)
        userid = self.request.get('userid')
        success = False
        if userid == '':
            msg = 'Please fill all fields!'
        # Does the userid already exist in the "confirmed" datastore or in "pending"?
        else:
            user = a2pb.User.query(a2pb.User.id == userid).get()
            if not user:
                msg = 'user id "%s" does not exist' % userid
            else:
                code = base64.b64encode(os.urandom(64)).decode('utf-8')
                while a2pb.PasswordReset.query(a2pb.PasswordReset.code == code).get():
                    code = base64.b64encode(os.urandom(64)).decode('utf-8')
                a2pb.PasswordReset(parent=a2pb.ParentKeys.PasswordReset,
                                   user_id=userid,
                                   code=code).put()
                email_template = JINJA.get_template('html/email_password_reset.html')
                body = email_template.render({
                    'title': 'Password Reset',
                    'user': userid,
                    'code': 'http://' + os.environ['HTTP_HOST'] + Navigator.Email.PasswordReset + code
                })
                mail.send_mail(sender="Yu Chen <yu.chen@live.ie>",
                               to="{0} <{1}>".format(userid, user.email),
                               subject="Password Reset",
                               body='',
                               html=body)
                msg = 'An email has been sent to you.'
                success = True
        template = JINJA.get_template('html/passwd_reset_process.html')
        return self.response.write(template.render(
            {
                'title': 'Password Reset',
                'msg': msg,
                'success': success
            }
        ))



# We need to provide for LOGOUT.
class LogoutHandler(BaseHandler):
    def get(self):
        self.session.pop('uid')
        return self.redirect(Navigator.Login.Form)


class Page1Handler(BaseHandler):
    def get(self):
        if not self.session.get('uid'):
            return self.redirect(Navigator.Root)
        user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
        user = user.filter(a2pb.User.id==self.session.get('uid')).get()
        if not user.confirmed:
            return self.redirect(Navigator.Root)
        template = JINJA.get_template('html/msg.html')
        return self.response.write(template.render(
            {
                'msg': 'This is page 1.'
            }
        ))


class Page2Handler(BaseHandler):
    def get(self):
        if not self.session.get('uid'):
            return self.redirect(Navigator.Root)
        user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
        user = user.filter(a2pb.User.id==self.session.get('uid')).get()
        if not user.confirmed:
            return self.redirect(Navigator.Root)
        template = JINJA.get_template('html/msg.html')
        return self.response.write(template.render(
            {
                'msg': 'This is page 2.'
            }
        ))


class Page3Handler(BaseHandler):
    def get(self):
        if not self.session.get('uid'):
            return self.redirect(Navigator.Root)
        user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
        user = user.filter(a2pb.User.id==self.session.get('uid')).get()
        if not user.confirmed:
            return self.redirect(Navigator.Root)
        template = JINJA.get_template('html/msg.html')
        return self.response.write(template.render(
            {
                'msg': 'This is page 3.'
            }
        ))


class RegisterHandler(webapp2.RequestHandler):
    def get(self):
        template = JINJA.get_template('html/reg.html')
        self.response.write(template.render(
            {
                'title': 'Welcome to the Registration Page'
            }
        ))

    def post(self):
        userid = self.request.get('userid')
        email = self.request.get('email')
        passwd = self.request.get('passwd')
        passwd2 = self.request.get('passwd2')
        success = False
        # Check if the data items from the POST are empty.
        if userid == '' or email == '' or passwd == '' or passwd2 == '':
            msg = 'Please fill all fields!'
        # Check if passwd == passwd2.
        elif passwd != passwd2:
            msg = 'Passwords typed not the same!'
        # Does the userid already exist in the "confirmed" datastore or in "pending"?
        elif a2pb.User.query(a2pb.User.id == userid).get():
            msg = 'the user id "%s" already exist' % userid
        # Is the password too simple?
        elif not userid.isalnum():
            msg = 'User id can only contain alphabetic and numeric characters.'
        elif len(passwd) < 6:
            msg = 'The length of password should not be less than 6.'
        elif passwd.isdigit() or passwd.isalpha():
            msg = 'Password too simple. (all digits or all alphabets)'
        # Add registration details to "pending" datastore.
        else:
            a2pb.User(parent=a2pb.ParentKeys.User,
                      id=userid,
                      email=email,
                      password=passwd,
                      confirmed=False).put()
            # Send confirmation email.
            code = base64.b64encode(os.urandom(64)).decode('utf-8')
            while a2pb.Activator.query(a2pb.Activator.code == code).get():
                code = base64.b64encode(os.urandom(64)).decode('utf-8')
            a2pb.Activator(parent=a2pb.ParentKeys.Activator,
                           user_id=userid,
                           code=code).put()
            email_template = JINJA.get_template('html/email.html')
            body = email_template.render({
                'title': 'Your a2pb account has been created',
                'user': userid,
                'code': 'http://' + os.environ['HTTP_HOST'] + Navigator.Email.Confirmation + code
            })
            mail.send_mail(sender="Yu Chen <yu.chen@live.ie>",
                           to="{0} <{1}>".format(userid, email),
                           subject="Your a2pb account has been created",
                           body='',
                           html=body)
            msg = 'Success! Please check your email to activate your account'
            success = True

        template = JINJA.get_template('html/reg_process.html')
        self.response.write(template.render(
            {
                'title': 'Processing Registration',
                'msg': msg,
                'success': success
            }
        ))
        # Can GAE send email?
        # Can my GAE app receive email?

        # This code needs to move to the email confirmation handler.


class EmailConfirmationHandler(webapp2.RedirectHandler):
    def get(self, code=None):
        activator = a2pb.Activator.query(ancestor=a2pb.ParentKeys.Activator)
        activator = activator.filter(a2pb.Activator.code == code).get()
        if activator:
            user = a2pb.User.query(ancestor=a2pb.ParentKeys.User)
            user = user.filter(a2pb.User.id == activator.user_id).get()
            user.confirmed = True
            user.put()
            activator.key.delete()
            msg = 'Your account has been activated.'
        else:
            msg = 'Unavailable code!'
        template = JINJA.get_template('html/msg.html')
        self.response.write(template.render(
            {
                'title': 'Activating Account',
                'msg': msg,
            }
        ))

JINJA.globals = {
    'Navigator': Navigator
}
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': base64.b64encode(os.urandom(16)),
    }

app = webapp2.WSGIApplication([
                                  (Navigator.Link, NavigatorHandler),
                                  (Navigator.MainPage, MainPageHandler),
                                  (Navigator.Registration.Form, RegisterHandler),
                                  (Navigator.Registration.Process, RegisterHandler),
                                  ('%s(.*)' % Navigator.Email.Confirmation, EmailConfirmationHandler),
                                  (Navigator.Root, LoginHandler),
                                  (Navigator.Login.Form, LoginHandler),
                                  (Navigator.Login.Process, LoginHandler),
                                  (Navigator.Logout, LogoutHandler),
                                  (Navigator.PasswordResetForm, PasswordResetFormHandler),
                                  ('%s(.*)' % Navigator.Email.PasswordReset, PasswordResetHandler),
                                  # Next three URLs are only available to logged-in users.
                                  ('/page1', Page1Handler),
                                  ('/page2', Page2Handler),
                                  ('/page3', Page3Handler),
                              ], config=config, debug=True)
