# My SSL RNG Providers #

  These providers are example implementations for the Quantis PCI card, using the online ANU QRNG api (limit to 1 request / min), and a simple (VERY RUDIMENTARY) skeleton for making your own RNG providers. <br><br>
  The quantis provider has the benefit of showing how you can make an OSSL_PARAM for your provider, following the QUANTIS_CARDNO, you can add a param that can be updated real time to adjust your provider's context. An update and set request is demonstrated within its main.c file <br><br>
  I also include an example main.c for how these can be used for implementation. <br><br>

# Building and Running #
## Requirements: ##
  <b> skeleton: </b> openssl <br><br>
  <b> quantis: </b> quantis, openssl <br><br>
  <b> anu qrng: </b> curl, cjson, openssl <br><br>

## Usage ##
  make <br><br>
  ./main <br><br>
  (for quantis you may need to LD_LIBRARY_PATH=/usr/local/your_quantis_lib_dir/ ./main <br>

# Future / TODO #
  I have built a super basic rust provider and will add it to this once I have it cleaned up and more readable.
