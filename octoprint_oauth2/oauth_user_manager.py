"""
This file manages OAuthBasedUserManager. A hook for OctoPrint plugin.
"""
import logging

import requests
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

from octoprint.access.users import UserManager, User, LocalProxy, SessionUser


class OAuthBasedUserManager(UserManager):
    """
    OAuthBasedUserManager replaces OctoPrints FilebasedUserManager
    """
    logger = logging.getLogger("octoprint.plugins." + __name__)

    def __init__(self, components, settings):
        OAuthBasedUserManager.logger.info("Initializing OAuthBasedUserManager")
        self._components = components
        self._settings = settings

        # Get data from config file
        self.oauth2 = self._settings.get(["plugins", "oauth2"])
        self.path_for_token = self.oauth2["token_path"]
        self.path_user_info = self.oauth2["user_info_path"]
        self.username_key = self.oauth2["username_key"]
        self.access_token_query_key = self.oauth2["access_token_query_key"]
        try:
            self.token_headers = self.oauth2["token_headers"]
        except KeyError:
            self.token_headers = None

        # Init UserManager
        UserManager.__init__(self)

    def logout_user(self, user):
        """
        Prints log into console, then uses UserManager.logout_user
        """
        OAuthBasedUserManager.logger.info("OAuth Logging out")
        UserManager.logout_user(self, user)

    def get_token(self, oauth2_session, code, client_secret):
        """
        This method uses oauth2_session to fetch an access token from the authorization server.
        If the token_json contains 'access_token', then it returns it. If access_token is missing
        or something is wrong, return None.
        """

        try:
            token_params = {
                "grant_type": "authorization_code",
                "code": code,
                "client_secret": client_secret
            }
            token_json = oauth2_session.fetch_token(self.path_for_token, authorization_response=None,
                                                    code=code, headers=self.token_headers,
                                                    client_secret=client_secret, **token_params)

            try:
                # token is OK
                access_token = token_json["access_token"]
                return access_token
            except KeyError:
                try:
                    error = token_json["error"]
                    OAuthBasedUserManager.logger.error("Error of access token: %s", error)
                except KeyError:
                    OAuthBasedUserManager.logger.error("Error of access token, "
                                                       "error message not found")

        except OAuth2Error:
            OAuthBasedUserManager.logger.error("Bad authorization_code")

        return None

    def get_username(self, oauth2_session, access_token):
        """
        This method makes a request to the resource server.
        Then tries if the specific username_key is OK and returns the username.
        """
        try:
            # GET user data from resource server
            headers = {
                "Authorization": "Bearer " + access_token
            }
            response = requests.get(self.path_user_info, headers=headers)
            data = response.json()

            # Try if data contains username_key from config file
            try:
                login = data[self.username_key]
                return login
            except (KeyError, TypeError):
                OAuthBasedUserManager.logger.error("User data does not contain username key,"
                                                   "you can try to find it here:")
                OAuthBasedUserManager.logger.error(data)
        except (requests.RequestException, ValueError):
            OAuthBasedUserManager.logger.error("Error making request to the resource server")

        return None

    def login_user(self, user):
        """
        This method logs in the user into OctoPrint using authorization OAuth2.
        Users user.get_id() should be dict containing redirect_uri and code.
        It is obtained by view model in static/js folder.
        Method gets specified data from config yaml - client_id and client_secret, then
        starts WebApplicationClient from oauthlib library. Using the library method
        fetch the access token using the method get_token.
        After that, the user is added into users.yaml config file.
        """
        self._cleanup_sessions()

        if user is None:
            return

        if isinstance(user, LocalProxy):
            user = user._get_current_object()
            return user

        if not isinstance(user, User):
            return None

        if not isinstance(user, SessionUser):

            # from get_id we get for each user his redirect uri and code
            try:
                redirect_uri = user.get_id()['redirect_uri']
                code = user.get_id()['code']
            except KeyError:
                OAuthBasedUserManager.logger.error("Code or redirect_uri not found")
                return None

            client_id = self.oauth2["client_id"]
            client_secret = self.oauth2["client_secret"]
            oauth2_session = WebApplicationClient(client_id)
            access_token = self.get_token(oauth2_session, code, client_secret)

            if access_token is None:
                return None

            username = self.get_username(oauth2_session, access_token)
            if username is None:
                OAuthBasedUserManager.logger.error("Username none")
                return None
            user = self.findUser(username)

            if user is None:
                self.addUser(username, "", True, ["user"])
                user = self.findUser(username)

        if not isinstance(user, SessionUser):
            user = SessionUser(user)

        self._session_users_by_session[user.session] = user

        user_id = user.get_id()
        if user_id not in self._sessionids_by_userid:
            self._sessionids_by_userid[user_id] = set()

        self._sessionids_by_userid[user_id].add(user.session)
        return user

    def checkPassword(self, username, password):
        """
        Override checkPassword method. Return always true. Use authorization of OAuth 2.0 instead
        """
        OAuthBasedUserManager.logger.info("Logging in via OAuth 2.0")
        return True

    def findUser(self, userid=None, apikey=None, session=None):
        """
        Find user using UserManager, else set temporary user.
        This is because of the implementation of server/api.
        """
        user = UserManager.findUser(self, userid, apikey, session)
        if user is not None:
            return user

        # making temporary user because of the implementation of api
        # and we need to pass our code from OAuth to login_user
        # api login could be found in server/api/__init__.py
        user = User(userid, "", 1, ["user"])
        return user
