import OpenSSL
import josepy as jose
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from contextlib import contextmanager
from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from acme import standalone

DOAMIN = 'example.com'
EMAIL = 'fake@example.com'

# Generate a private key on the fly, this is for your account. More on this below.
acc_pkey = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())

# Load it into json
json_key = jose.JWKRSA(key=acc_pkey)

# Create an ACME client state
net = client.ClientNetwork(json_key, user_agent='uwaf-cert-agent')

# Start a session with LetsEncrypt
directory = messages.Directory.from_json(net.get('https://acme-staging-v02.api.letsencrypt.org/directory').json())

# Establish the client
c = client.ClientV2(directory, net=net)

# Register account and accept terms
regr = c.new_account(messages.NewRegistration.from_data(email=EMAIL, terms_of_service_agreed=True))

# Generate another private key
# ############################
# Your certificate cannot use the same private key as your account.
cert_pkey = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())

# Convert it to bytes
cert_pkey_bytes = cert_pkey.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Print your key in a readable format
# ###################################
# You need this private key in order to install your cert on your web server or wherever. My specific use case for
# writing this script is to install the key in Vercara's UltraWAF config using an asset and responder policy.
for line in cert_pkey_bytes.splitlines():
	print(line.decode('utf-8'))

# Make a CSR (certificate signing request)
csr_pem = crypto_util.make_csr(cert_pkey_bytes, [DOMAIN])

# Order your request
req = c.new_order(csr_pem)

# Get the body of the HTTP challenge, I think it's always the first one offered
# #############################################################################
# Another common challenge option is the DNS challenge. The DNS challenge is probably indice 1. Actually, I should
# probably make this a bit less error-prone, since I don't actually know that the challenges are always offered in
# this order (though, the most likely are), and actually iterate through the list of challenges to find the http
# one. Lazily, however, I'm just getting the challenge at indice 0 and assuming.
challb = req.authorizations[0].body.challenges[0]
# Printing since I'm manually adding the token to my web server, however this stuff will be automated.
print(challb.to_json())

# Get response and validation for the http challenge
# ##################################################
# To expand on this, since it was unclear to me at first, the "response" is an object you need to send back to the
# server in order to tell it you're ready to take the challenge and the "validation" is a string containing the
# token you need to make available in either the body of the responder policy or on the web server so that the
# ACME bot can verify your ownership of the domain.
response, validation = challb.response_and_validation(c.net.key)
# Again, this is for manual config purposes and will be removed later
print(validation)

# Something worth noting
# ######################
# The string in "validation" will have two parts separated by a '.' The path to the full token on the web server
# only needs to have the part before the '.' For example, say your validation output is as follows.
#
# pgr5Q-36YNuJM5OmmUZ2thW89iyYxiLykBoLfF1yPNs.9MlM6jkaAqZgEnnzdS0DLFZo9Yz4SzqR0M4KcTGk3ck
#
# You'd create a file on your web server here:
#
# http://example.com/.well-known/acme-challenge/pgr5Q-36YNuJM5OmmUZ2thW89iyYxiLykBoLfF1yPNs
#
# Inside that file, have the full token string, including the stuff after the period.

"""
Responder policy stuff will go here.

What we need to do is create a responder policy in UltraWAF. This responder policy will tell UltraWAF to respond
to HTTP requests that end with /acme-challenge/{token} with a body of {full_validation_token}. We will use the
same token example I gave above.

pgr5Q-36YNuJM5OmmUZ2thW89iyYxiLykBoLfF1yPNs.9MlM6jkaAqZgEnnzdS0DLFZo9Yz4SzqR0M4KcTGk3ck

HTTP requests ending in...

/acme-challenge/pgr5Q-36YNuJM5OmmUZ2thW89iyYxiLykBoLfF1yPNs

...need to be responded to with the validation string.

We will extract the token from the validation variable with a simple split.

token = validation.split('.')[0]

Then we just need to build a request to UltraWAF's API with the correct endpoint and JSON. Here are the docs for
UltraWAF's API:

https://docs.appsecportal.com/

I think the endpoint we need is ResponderPolicyInput. The responder policy settings will need to look like this:

Field: This is just a name for the policy. We'll use something like "Certbot <our domain>"
Operand: This is what you want the policy to do. In this case, "Respond With"
Response: This is where we will put the full validation token, so the response will look as follows.

policy_response = "HTTP/1.1 200 OK\n\n" + validation + "\n\n"

Matches: This has another 3 parameters nested within it
L Field: We will want to use "URL Path"
L Operand: We'll use "Ends With". We are looking for a url path that ends with a specific string.
L Value: Here's where we will put out token. The value will be like the example below.

match_value = "acme-challenge/" + token

{
  "action": RESPOND_WITH,
  "name": "Certbot " + DOMAIN,
  "responderMatches": [
    {
      "field": URL_PATH,
      "operand": ENDS_WITH,
      "value": match_value
    }
  ],
  "response": policy_response
}

We will need a way to poll the the UWAF API and wait for these changes to propagate. There should
be an endpoint for this.
"""

# Tell LetsEncrypt we are ready for the challenge, this is where we send that response object
c.answer_challenge(challb, response)

# Finalize your request
fin = c.poll_and_finalize(req)

# Print your certificate full chain
print(fin.fullchain_pem)

"""
Here we will need to upload the certificate to UltraWAF
"""