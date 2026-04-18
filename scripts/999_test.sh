#!/bin/bash

curl -X POST http://127.0.0.1:8080/api/v1/whois \
     -H "Content-Type: application/json" \
     -d '{
           "domain":"example.com",
           "whoisserver":"whois.verisign-grs.com:43",
           "timeout":10
         }' | jq
