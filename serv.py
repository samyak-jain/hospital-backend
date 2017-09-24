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
        if self.get_current_user():
            self.render("portal.html")


class AuthHandler(BaseHandler):
    @tornado.gen.coroutine
    def post(self, *args, **kwargs):
        username = self.get_argument("user")
        password = self.get_argument("pwd")
        portal = self.get_argument("portal")

        hash = pbkdf2_sha256.hash(username)
        db = self.settings["db"]

        find = yield db.find_one({"user": username, "pass": hash, "portal": portal})

        if not find:
            self.write(json.dumps({
                "status_code": 405,
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
    pass


class PatientHandler(BaseHandler):
    @tornado.gen.coroutine
    @tornado.web.authenticated
    def get(self):
        pass


if __name__ == "__main__":
    tornado.options.parse_command_line()
    client = motor_tornado.MotorClient("mongodb://" + dbuser + ":" + dbpass + "@ds147974.mlab.com:47974/hospital-backend")
    db = client["auth"]
    settings = {
        "default_handler_args": dict(status_code=404),
        "debug": True,
        "cookie_secret": cookie_secret,
        "login_url": "/login",
        "db": db
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