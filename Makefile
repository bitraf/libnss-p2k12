all: libnss.so.2

install: libnss.so.2
	install -m 775 -o root -g root libnss_p2k12.so.2 /lib/libnss_p2k12.so.2
	install -o 0 -g 0 -m 1777 -d /var/lib/p2k12

libnss.so.2: nss-p2k12.c
	$(CC) nss-p2k12.c -shared -fPIC -lcurl -olibnss_p2k12.so.2
