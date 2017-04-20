

class SipUser:

    def __init__(self):
        self.user_uri = None
        self.user_host = None
        self.user_port = None
        self.user_token = None
        self.user_registration_keepalive = None

    def set_user_info(self, user_info):
        uri, host, port, token, rka = user_info
        self.user_uri = uri
        self.user_host = host
        self.user_port = port
        self.user_token = token
        self.user_registration_keepalive = rka
        return True

    def get_user_info(self):
        return self.user_uri, self.user_host, self.user_port, self.user_token, self.user_registration_keepalive
