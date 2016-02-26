.PHONY: install clean

install: pam_setquota.so
	install --mode=644 pam_setquota.so /lib/security

clean:
	rm -f pam_setquota.o pam_setquota.so
