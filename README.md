# DEPRECATED - StartSSL is no longer in operation

StartSSL_API
============

A python/CLI API for some StartCom StartSSL functions

## Usage
* Place startssl.conf in /etc or your current working directory
* Adjust the settings in startssl.conf
* Show all available certificates:
  * `startssl.py certs`
* Download a specific certificate
  * `startssl.py certs example.com`
* Download all new and missing certificates
  * `startssl.py certs --store new --store missing`
* Submit CSR files
  * `startssl.py csr example.com.csr mail.example.com.csr`
