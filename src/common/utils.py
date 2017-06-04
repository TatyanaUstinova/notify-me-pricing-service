from passlib.hash import pbkdf2_sha512
import re


class Utils(object):

    @staticmethod
    def check_email_valid(email):
        email_address_mather = re.compile("^([\.\w-])+@([\w-]+\.)+[\w]+$")  # ^[\w-]+@([\w-]+\.)+[\w]+$
        if email_address_mather.match(email):
            return True
        else:
            return False

    @staticmethod
    def hash_password(password):
        """
        Hashes a password using pbkdf2_sha512
        :param password: the sha512 password from the login/register form
        :return: a sha512 -> pbkdf2_sha512 encrypted password
        """

        return pbkdf2_sha512.encrypt(password)

    @staticmethod
    def check_hashed_password(password, hashed_password):
        """
        Checks that the password the user sent matches that of the database.
        The database password is encrypted more than the user's password at this stage.
        :param password: sha512-hashed password
        :param hashed_password: pbkdf2_sha512 encrypted password
        :return: True if passwords match, False otherwise
        """

        return pbkdf2_sha512.verify(password, hashed_password)
