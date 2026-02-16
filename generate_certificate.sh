#!/bin/bash
openssl ecparam -name prime256v1 -genkey -out fizz.key
openssl req -x509 -new -nodes -key fizz.key -sha256 -days 365 -out fizz.crt -subj "/CN=localhost" -addext "keyUsage=digitalSignature" -addext "1.3.6.1.4.1.44363.44=ASN1:NULL"
