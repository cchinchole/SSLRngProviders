# My SSL RNG Providers #

These providers are example implementations for the Quantis PCI card, using the online ANU QRNG api (limit to 1 request / min), and a simple (VERY RUDIMENTARY) skeleton for making your own RNG providers. <br>
The quantis provider has the benefit of showing how you can make an OSSL_PARAM for your provider, following the QUANTIS_CARDNO, you can add a param that can be updated real time to adjust your provider's context. An update and set request is demonstrated within its main.c file <br>
I also include an example main.c for how these can be used for implementation. <br>

# Building and Running #
## Requirements: ##
  <b> skeleton: </b> openssl <br>
  <b> quantis: </b> quantis, openssl <br>
  <b> anu qrng: </b> curl, cjson, openssl <br>

## Usage ##
  make <br>
  ./main <br>
  (for quantis you may need to LD_LIBRARY_PATH=/usr/local/your_quantis_lib_dir/ ./main <br>
