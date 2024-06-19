## Quantis Provider ##
Tested against only PCI Quantis devices under the new driver.
To change card numbers check the example: main.c file to see how to send a OSSL_PARAM request to the provider to change the quantis_cardno.

## ANU QRNG ##
Works under the 1 request / min limitation. You will only be able to recieve random bytes under this duration.

## Skeleton ##
Mostly the OpenSSL implementation of seed-src. This is showcasing though, how to write and test a provider all in one file while providing an example
of using said provider.
