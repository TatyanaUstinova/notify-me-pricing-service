import uuid

from src.common.database import Database
from src.common.utils import Utils
from src.models.alerts.alert import Alert
import src.models.users.errors as UserErrors
import src.models.users.constants as UserConstants


class User(object):

    def __init__(self, email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "<User {}>".format(self.email)

    @staticmethod
    def check_login_valid(email, password):
        """
        Verifies that an e-mail/password combo(as sent by the site forms) is valid or not.
        Checks that the e-mail exists, and the password associated to that e-mail is correct.
        :param email: the user's e-mail
        :param password: a sha512-hashed password
        :return: True if valid, False otherwise
        """

        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})  # Password in sha512 -> pbkdf2_sha512
        if not user_data:
            # Tell the user that their e-mail doesn't exist
            raise UserErrors.UserNotExistsError("This user does not exist.")

        if not Utils.check_hashed_password(password, user_data["password"]):
            # Tell the user that their password is wrong
            raise UserErrors.IncorrectPasswordError("Your password was wrong.")

        return True

    @staticmethod
    def register_user(email, password):
        """
        Registers a user using e-mail and password.
        The password already comes hashed as sha-512.
        :param email: user's e-mail (might be invalid)
        :param password: sha512-hashed password
        :return: True if registered successfully, or False otherwise (exception can also be raised)
        """
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})

        if user_data:
            # Tell user they are already registered
            raise UserErrors.UserAlreadyRegisteredError("The e-mail you used to register already exists.")

        if not Utils.check_email_valid(email):
            # Tell user that their e-mail is not constructed properly
            raise UserErrors.InvalidEmailError("The e-mail does not have the right format.")

        User(email, Utils.hash_password(password)).to_db()

        return True

    def to_db(self):
        Database.insert(UserConstants.COLLECTION, self.make_json())

    def make_json(self):
        json_data = {
            "_id": self._id,
            "email": self.email,
            "password": self.password
        }

        return json_data

    @classmethod
    def find_by_email(cls, email):
        return cls(**Database.find_one(UserConstants.COLLECTION, {"email": email}))

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)
