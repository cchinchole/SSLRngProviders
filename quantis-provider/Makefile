name=skeleton 
cc=gcc
argsComp= -fPIC -c -o skeleton.o skeleton.c
argsLink= -shared -Wl,--export-dynamic-symbol=OSSL_provider_init -o skeleton.so skeleton.o

build:
	gcc -DOSSL_provider_init=my_prov_init -c -o skeleton.o skeleton.c
	gcc -c -o main.o main.c
	gcc main.o skeleton.o -lcrypto -o main
