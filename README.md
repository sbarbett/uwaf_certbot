uwaf_certbot
======================

The purpose of this script is to automate the certificate generation process for Vercara's UltraWAF product. You can create a responder policy that contains the validation token for the ACME HTTP challenge.

LetsEncrypt issues 90 day certificates that need to be renewed automatically in some fashion. The src/encryptin.py file is an effort to accomplish this.

## Steps

* Make a private key
* Register with LetsEncrypt using your key and email
* Accept the terms of service
* Make another private key (for the cert)
* Create a CSR
* Send your request
* Accept the HTTP challenge
* Make a responder policy in UWAF to satisfy the challnge
* Wait for the responder policy to propagate to all the UWAF POPs
* Complete and finalize the challenge
* Upload your private key and certificate chain to UWAF