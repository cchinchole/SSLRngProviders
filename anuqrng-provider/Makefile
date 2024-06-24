build:
	gcc -DOSSL_provider_init=QRNGProviderInit -c -o provider.o provider.c
	gcc -c -o main.o main.c
	gcc main.o provider.o -ljson-c -lssl -lcrypto -lcurl -o main
