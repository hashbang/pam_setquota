.PHONY: default install clean

default: target/release/libpam_setquota.so
target/release/libpam_setquota.so: src/pam_setquota.rs Cargo.toml
	cargo build --release

install: target/release/libpam_setquota.so
	install --mode=644 $< $(DESTDIR)/lib/security/pam_setquota.so

clean:
	rm -rf target/
