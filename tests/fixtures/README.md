# Test fixtures

`client-certificate.pem` and `client-key.pem` are a self-signed certificate and its private key,
made with openssl for the client assertion tests. `other-key.pem` is an unrelated key, for
signing an assertion the certificate does not match. None of them is used anywhere but the tests.
