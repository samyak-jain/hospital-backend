import json
import os
import traceback
import tornado.httpserver
import tornado.ioloop
import tornado.web
from motor import motor_tornado
from passlib.hash import pbkdf2_sha256
from tornado.gen import coroutine
from tornado.options import define, options
import tornado.options

define("port", default=7000, help="runs on the given port", type=int)
from bson import ObjectId
import Azure


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


class users(object):

    def __init__(self, email, user, name):
        self.email = email
        self.user = user
        self.name = name

    @staticmethod
    @coroutine
    def login(db, name, password):
        hash = yield db.auth.find_one({"user": name})
        if not hash:
            return True
        if  pbkdf2_sha256.verify(password, hash["pass"]):
            return True
        else:
            return False


class patient(users):
    @staticmethod
    @coroutine
    def make_appointment(user, db, ap_details):
        print(user)
        resp = yield db.patient.find_one({'user': user})
        # if resp.get('ap_details') == {}:
        #     x = []
        # else:
        #     x = resp['ap_details']
        #     x.append(ap_details)
        Modi = yield db.patient.update({'_id': resp['_id']}, {'$set': {'ap_details': ap_details}}, upsert=False)
        if Modi['updatedExisting']:
            dbdoc = yield db.doctor.find_one({'fname': user})
            plist = dbdoc['plist']
            plist.append(user)
            Modi2 = yield db.doctor.update({'_id': dbdoc['_id']}, {'$set': {'plist': plist}}, upsert=False)
            if Modi2['updatedExisting']:
                return True
        return False

    # @classmethod
    # @coroutine
    # def get_details(cls, username, db):
    #     resp = yield db.patient.find_one({'user': username})
    #     return cls(resp['email'], username, resp['fname'])


class doctor(users):

    @staticmethod
    @coroutine
    def diagnose(db, username):
        resp = yield db.doctor.find_one({"user": username})
        patient_resp = db.patient.find({'ap_details.type': {'$in': resp['type']}})
        return patient_resp
    #
    # @classmethod
    # @coroutine
    # def get_details(cls, user, db):
    #     resp = yield db.doctor.find_one({'user': user})
    #     return cls(email=resp['email'], user=user, name=resp['fname'])

    @staticmethod
    @coroutine
    def get_doc_list(db, cond):
        resp = yield db.doctor.find({"type": {"$in": cond}})
        listOfDoc = []
        for ele in resp:
            listOfDoc.append(dict(email=ele['email'], user=ele['user'], name=ele['fname'], description=ele['description'], qualifications=ele['qualifications']))

        return listOfDoc

    @staticmethod
    @coroutine
    def get_pat(db, doc):
        resp = yield db.doctor.find_one({'user': doc})
        return resp['plist']


class MyAppException(tornado.web.HTTPError):
    pass


class BaseHandler(tornado.web.RequestHandler):

    def get_current_user(self):
        self.get_secure_cookie("user")

    def db(self):
        Client = self.settings['db_client']
        db = Client.tornado
        return db

    def write_error(self, status_code, **kwargs):
        # self.set_header('Content-Type', 'application/json')
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.render("error.html", d=json.dumps({
                    'error': {
                        'code': status_code,
                        'message': self._reason,
                        'traceback': lines,
                    }
                }), page=None)
        else:
            self.render("error.html", d=json.dumps({
                'error': {
                    'code': status_code,
                    'message': self._reason,
                    }
                }), page=None)


class AuthHandler(BaseHandler):
    @coroutine
    def get(self):
        if bool(self.get_secure_cookie("user")):
            portal = self.get_cookie("portal")
            username = self.get_cookie("name")
            if portal == "1":
                patio = yield self.db().patient.find_one({'user': username})
                self.render("index.html", tarp=1, name=patio['fname'])
            elif portal =="0":
                patio = yield self.db().doctor.find_one({'user': username})
                self.render("index.html", tarp=0, name=patio['fname'])
        else:
            self.render("index.html", tarp=None, name="Amrut")

    @coroutine
    def post(self):
        username = self.get_argument("user")
        password = self.get_argument("pass")
        db_client = self.db()
        flag = users.login(db_client, username, password)
        if not flag:
            self.render("error.html",d=json.dumps({
                "error": {
                    "code": "50",
                    "message": "Credentials invalid or client failure.  "
                }
            }))
            return
        response = yield db_client.auth.find_one({'user': username})
        if response is None:
            raise MyAppException(status_code=400, reason="Invalid Credentials.")
        portal = response['portal']
        self.set_cookie("portal", portal)
        self.set_cookie("name", username)
        self.set_secure_cookie("user", username)
        self.redirect("/user")


class SignUpHandler(BaseHandler):
    def get(self):
        self.render("signup.html")

    @coroutine
    def post(self, *args, **kwargs):
        username = self.get_argument("user")
        password = self.get_argument("pass")

        img = self.get_argument("img")
        if img == "":
            img = r"http://jennstrends.com/wp-content/uploads/2013/10/bad-profile-pic-2.jpeg"

        user_details = {
            "user": username,
            "fname": self.get_argument("fname"),
            "lname": self.get_argument("lname"),
            "email": self.get_argument("email"),
            "address": self.get_argument("address"),
            "portal": self.get_argument("portal"),
            "img": img,
        }

        db_client = self.db()
        database_auth = db_client["auth"]
        database_details = None
        if user_details['portal'] == "1":
            database_details = db_client["patient"]
            user_details['ap_details'] = dict()
            user_details['history'] = self.get_argument("history")

        elif user_details['portal'] == "0":
            database_details = db_client["doctor"]
            user_details['type'] = list()
            user_details['plist'] = list()
            user_details['description'] = self.get_argument("description")
            user_details['type'] = self.get_argument("specialization")
            user_details['qualifications'] = self.get_argument("qualifications")

        find_user = yield database_auth.find_one({"user": username})
        find_email = yield database_details.find_one({"email": user_details["email"]})

        if find_user:
            self.render("error.html", d=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Username exists"
                }}))
            return
        elif find_email:
            self.render("error.html", d=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Email already under use"
            }}))
            return
        hash_pass = pbkdf2_sha256.hash(password)

        database_auth.insert_one({"user": username, "pass": hash_pass, "portal": user_details['portal']})
        yield database_details.insert_one(user_details)

        self.set_cookie("name",username)
        self.set_secure_cookie("user", username)
        self.set_cookie("portal", user_details['portal'])
        self.redirect("/")


class PatientHandler(BaseHandler):
    @coroutine
    def get(self):
        if self.get_secure_cookie("user"):
            portal = self.get_cookie("portal")
            if portal == "1":
                username = self.get_cookie("name")
                database = self.db()
                details = yield database.patient.find_one({"user":username})
                self.render("patient.html", Name=username, resp=details)
            else:
                self.redirect("/")


    @coroutine
    def post(self):
        username = self.get_cookie("name")
        symp = self.get_argument("symptoms")
        sit = self.get_argument("situation")
        type = self.get_argument("type")

        ap_details = {
            # "hname": hname,
            "symptoms": symp,
            "situation": sit,
            "doctor": type
        }
        flag = yield patient.make_appointment(username, self.db(), ap_details)
        doctor_data = yield doctor.get_doc_list(self.db(), type)
        self.render("doctorlist.html", response=doctor_data, Name=username)
        self.write(flag)


class DocHandler(BaseHandler):
    @coroutine
    def get(self):
        if self.get_secure_cookie("user"):
            portal = self.get_cookie("portal")
            if portal == "0":
                username = self.get_cookie("name")
                database = self.db()
                details = yield database.patient.find_one({"user":username})
                self.render("blank.html", Name=username, resp=details)
            else:
                self.redirect("/")


class my404handler(BaseHandler):
    def get(self):
        self.render("error.html", d=json.dumps({
            'error': {
                'code': 404,
                'message': 'Page not found.'
            }
        }))


class LogoutHandler(BaseHandler):
    def get(self):
        if bool(self.get_secure_cookie('user')):
            self.clear_cookie('user')
            self.clear_cookie('portal')
            self.clear_cookie('username')
        else:
            self.write("COOKIES ARENT GETTING SET.")
            return
        self.redirect('/')


class PortalHandler(BaseHandler):
    def get(self):
        if self.get_secure_cookie("user"):
            dat = Azure.get_hospitalList()
            self.render("portal.html", hospital=dat)
        else:
            self.redirect("/")


class PathHandler(BaseHandler):
    def get(self):
        if self.get_secure_cookie("user"):
            portal = self.get_cookie("portal")
            if portal == "1":
                self.redirect("/user")
            else:
                self.redirect("/doc")

if __name__ == "__main__":
    tornado.options.parse_command_line()
    client = motor_tornado.MotorClient("mongodb://amrut:excalibur@ds117605.mlab.com:17605/tornado")
    settings = {
        "default_handler_class": my404handler,
        "debug": True,
        "cookie_secret": "b'LPBDqiL4S8KGi54y5eXFLoSiKE+wz0vajAU6K9aZOJ4='",
        "login_url": "/login",
        "db_client": client
    }
    app = tornado.web.Application(
        handlers=[
            (r"/", AuthHandler),
            (r"/login", AuthHandler),
            (r"/Signup", SignUpHandler),
            (r"/patient", PatientHandler),
            (r"/logout", LogoutHandler),
            (r"/portal", PortalHandler),
            (r"/path", PathHandler),
            (r"/user", PatientHandler),
            (r"/doctor", DocHandler),
        ], **settings,
        template_path=os.path.join(os.path.dirname(__file__), "template"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(os.environ.get("PORT",options.port))
    tornado.ioloop.IOLoop.instance().start()

