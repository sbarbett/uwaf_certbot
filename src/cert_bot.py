import josepy as jose
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from acme import standalone

class HTTPChallengeNotFound(Exception):
    pass

class CertBot:
    def __init__(self, domain, email):
        self.domain = domain
        self.email = email
        self.lets_encrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self.acc_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.connection = self._get_connection(self.cert_key)
        self.request = self._create_csr(self.connection, self.cert_key)
        self.challenge = self._get_challenge(self.request)
        self.response, self.validation = self.challenge.response_and_validation(self.connection.net.key)
        self.full_chain = None
        
    def _to_bytes(self, pkey):
        pkey_bytes = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pkey_bytes
        
    def _get_connection(self, pkey):
        json_key = jose.JWKRSA(key=pkey)
        net = client.ClientNetwork(json_key, user_agent='uwaf-cert-agent')
        directory = messages.Directory.from_json(net.get(self.lets_encrypt).json())
        connection = client.ClientV2(directory, net=net)
        regr = connection.new_account(messages.NewRegistration.from_data(email=self.email, terms_of_service_agreed=True))
        return connection
        
    def _create_csr(self, connection, pkey):
        csr = crypto_util.make_csr(self._to_bytes(pkey), [self.domain])
        return connection.new_order(csr)
        
    def _get_challenge(self, request):
        challb = None
        for i in request.authorizations[0].body.challenges:
            if i.to_json()['type'] == 'http-01':
                challb = i
                
        if challb is None:
            raise HTTPChallengeNotFound(f"No HTTP-01 challenge found.")
            
        return challb
        
    @property
    def PRIVATE_KEY(self):
        decoded_cert = []
        for line in self._to_bytes(self.cert_key).splitlines():
            decoded_cert.append(line.decode('utf-8'))
            
        return '\n'.join(decoded_cert)
        
    @property
    def VALIDATION_TOKEN(self):
        return str(self.validation)
        
    @property
    def FULL_CHAIN(self):
        return str(self.full_chain)
        
    def answer_http_challenge(self):
        self.connection.answer_challenge(self.challenge, self.response)
        fin = self.connection.poll_and_finalize(self.request)
        self.full_chain = fin.fullchain_pem