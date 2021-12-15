#!/bin/bash

openssl genrsa > tests/server.key
openssl rsa -pubout < tests/server.key > tests/server.pub
