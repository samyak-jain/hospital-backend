import json
import os
import tornado.auth
import tornado.gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from motor import motor_tornado
from passlib.hash import pbkdf2_sha256
from secrets import dbuser, dbpass, cookie_secret
from tornado.options import define, options

define("port", default=8000, help="runs on the given port", type=int)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        self.get_secure_cookie("user")


class IndexHandler(BaseHandler):
    def get(self):
        if self.current_user:
            self.render("portal.html")


class AuthHandler(BaseHandler):
    @tornado.gen.coroutine
    def post(self, *args, **kwargs):
        username = self.get_argument("user")
        password = self.get_argument("pwd")
        portal = self.get_argument("portal")

        db_client = self.settings["db_client"]
        database = db_client["auth"]

        find = yield database.find_one({"user": username})

        cred = pbkdf2_sha256.verify(password, find["pass"])

        if not cred:
            self.write(json.dumps({
                "status_code": 400,
                "message": "Invalid Credentials"
            }))
            return

        self.set_secure_cookie("user", username)
        self.set_cookie("portal", portal)

        self.write(json.dumps({
            "status_code": 200,
            "message": None
        }))


class SignUpHandler(BaseHandler):
    @tornado.gen.coroutine
    def post(self, *args, **kwargs):
        username = self.get_argument("user")
        password = self.get_argument("pwd")
        user_details = {
            "user": username,
            "name": self.get_argument("name"),
            "dob": self.get_argument("dob"),
            "email": self.get_argument("email"),
            "address": self.get_argument("ad"),
            "portal": self.get_argument("portal"),
            "hospital": self.get_argument("hos")
        }

        db_client = self.settings["db_client"]
        database_auth = db_client["auth"]
        database_details = db_client["user_details"]

        find_user = yield database_auth.find_one({"user": username})
        find_email = yield database_details.find_one({"email": user_details["email"]})

        if find_user:
            self.write(json.dumps({
                "status_code": 400,
                "message": "Username exists"
            }))
        elif find_email:
            self.write(json.dumps({
                "status_code": 400,
                "message": "Email already under use"
            }))

        hash_pass = pbkdf2_sha256.hash(password)

        database_auth.insert_one({"user": username, "pass": hash_pass})
        database_details.insert_one(user_details)

        self.set_secure_cookie("user", username)
        self.set_cookie("portal", user_details["portal"])

        self.write(json.dumps({
            "status_code": 200,
            "message": None
        }))


class PatientHandler(BaseHandler):
    @tornado.gen.coroutine
    @tornado.web.authenticated
    def get(self):
        pass



if __name__ == "__main__":
    tornado.options.parse_command_line()
    client = motor_tornado.MotorClient("mongodb://" + dbuser + ":" + dbpass + "@ds147974.mlab.com:47974/hospital-backend")
    settings = {
        "default_handler_args": dict(status_code=404),
        "debug": True,
        "cookie_secret": cookie_secret,
        "login_url": "/login",
        "db_client": client
    }
    app = tornado.web.Application(
        handlers=[
            (r"/", IndexHandler),
            (r"/login", AuthHandler),
            (r"/signup", SignUpHandler),
            (r"/patient", PatientHandler)
        ], **settings
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(os.environ.get("PORT",options.port))
    tornado.ioloop.IOLoop.instance().start()