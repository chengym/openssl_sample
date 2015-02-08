#!/bin/bash

# Generate RSA prv-key
openssl genrsa -out plainPrv.key 1024
# extract pub-key from prv-key
openssl rsa -in plainPrv.key -RSAPublicKey_out -out plainPub.key

openssl genrsa -des3 -out cipherPrv.key 1024

openssl rsa -in cipherPrv.key -pubout -out cipherPub.key
openssl rsa -in cipherPrv.key -RSAPublicKey_out -out cipherPub2.key
