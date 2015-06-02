__author__ = 'yuchen'

from google.appengine.ext import ndb


class ParentKeys():
    User = ndb.Key("Entity", "user_key")
    Activator = ndb.Key("Entity", "activator_key")
    PasswordReset = ndb.Key("Entity", "password_reset_key")


class User(ndb.Model):
    id = ndb.StringProperty()
    email = ndb.StringProperty()
    password = ndb.StringProperty()
    confirmed = ndb.BooleanProperty()


class Activator(ndb.Model):
    user_id = ndb.StringProperty()
    code = ndb.StringProperty()


class PasswordReset(ndb.Model):
    user_id = ndb.StringProperty()
    code = ndb.StringProperty()