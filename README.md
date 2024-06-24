# My SSL RNG Providers #

These providers are example implementations for the Quantis PCI card, using the online ANU QRNG api (limit to 1 request / min), and a simple (VERY RUDIMENTARY) skeleton for making your own RNG providers.
I also include an example main.c for how these can be used for implementation.

# Building and Running #
## Requirements: ##
  #skeleton:# openssl
  #quantis:# quantis, openssl
  #anu qrng:# curl, cjson, openssl

## Usage ##
  make
  ./main
  (for quantis you may need to LD_LIBRARY_PATH=/usr/local/your_quantis_lib_dir/ ./main
