import hashlib

class LoginManager:
    """This class manages user log-in functionality"""

    def __init__(self):
        """Default constructor"""
        return

    def hasher(self, string):
        """Hashes and encodes a passed string with added salt"""
        salt = "salting"  # added salt before hashing password
        return hashlib.sha256((string + salt).encode()).hexdigest().encode()

    def verifyPassword(self, password):
        """Checks password constraints"""
        if len(password) < 8:
            return False

        digitCount = 0
        for c in password:
            if c.isdigit():
                digitCount += 1
        if digitCount < 2:
            return False

        return True

    def registerNewUser(self):
        """Registers a new user"""
        userName = input("Please enter a username: ")
        while True:
            password = input("Please enter a password: ")
            if not self.verifyPassword(password):
                print("Not a valid password. Password must have 8 characters and 2 digits.")
                continue
            password2 = input("Please verify password: ")
            if password != password2:
                print("Passwords do not match!")
                continue
            break
        return userName.encode(), self.hasher(password)

    def loginUser(self):
        """Catches the username and password of user for login"""
        userName = input("Please enter your username: ")
        password = input("Please enter your password: ")
        return userName.encode(), self.hasher(password)