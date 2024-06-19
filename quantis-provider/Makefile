name=skeleton 
cc=gcc
argsComp= -fPIC -c -o skeleton.o skeleton.c
argsLink= -shared -Wl,--export-dynamic-symbol=OSSL_provider_init -o skeleton.so skeleton.o

build:
	gcc -DOSSL_provider_init=my_prov_init -c quantis.c -o quantis.o
	gcc -c main.c -o main.o
	gcc main.o quantis.o -lcrypto -lQuantis -o main
