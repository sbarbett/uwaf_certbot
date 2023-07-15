import requests

class AuthError(Exception):
    def __init__(self, message):
        self.message = message
        
    def __str__(self):
        return repr(self.message)

class GraphQLError(Exception):
    def __init__(self, message):
        self.message = message
        
    def __str__(self):
        return repr(self.message)

class UWAFClient:
    def __init__(self, client_id, client_secret):
        self.domain = "appsecportal.com"
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = self._auth(self.client_id, self.client_secret)
        
    def _auth(self, client_id, client_secret):
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": "https://api." + self.domain + "/",
            "grant_type": "client_credentials"
        }
        req = requests.post("https://auth." + self.domain + "/oauth/token", data=payload)
        if req.status_code == requests.codes.OK:
            json_body = req.json()
            self.access_token = json_body[u'accessToken']
        else:
            raise AuthError(req.json())
            
    def _build_headers(self):
        result = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self.access_token,
            "User-Agent": "uwaf-cert-agent"
        }
        return result