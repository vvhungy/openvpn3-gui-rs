# Makefile for openvpn3-gui-rs

PREFIX ?= /usr/local
APP_ID = net.openvpn.openvpn3_gui_rs
BINARY = openvpn3-gui-rs
SCHEMA_DIR = $(PREFIX)/share/glib-2.0/schemas
ICON_DIR = $(PREFIX)/share/icons/hicolor
DESKTOP_DIR = $(PREFIX)/share/applications
METAINFO_DIR = $(PREFIX)/share/metainfo

.PHONY: all install uninstall clean deb rpm test smoke-test fmt lint run debug setup-hooks check

all:
	cargo build --release --workspace

install: install-icons install-schema install-desktop install-metainfo
	install -Dm755 target/release/$(BINARY) $(PREFIX)/bin/$(BINARY)

install-icons:
	install -Dm644 data/icons/hicolor/scalable/apps/$(BINARY).svg \
		$(ICON_DIR)/scalable/apps/$(BINARY).svg
	for icon in data/icons/hicolor/scalable/status/*.svg; do \
		install -Dm644 "$$icon" $(ICON_DIR)/scalable/status/$$(basename $$icon); \
	done
	for icon in data/icons/hicolor/scalable/mimetypes/*.svg; do \
		install -Dm644 "$$icon" $(ICON_DIR)/scalable/mimetypes/$$(basename $$icon); \
	done
	for icon in data/icons/Yaru/scalable/mimetypes/*.svg; do \
		install -Dm644 "$$icon" \
			$(PREFIX)/share/icons/Yaru/scalable/mimetypes/$$(basename $$icon); \
	done
	gtk-update-icon-cache -f $(ICON_DIR) 2>/dev/null || true

install-schema:
	install -Dm644 data/$(APP_ID).gschema.xml $(SCHEMA_DIR)/$(APP_ID).gschema.xml
	glib-compile-schemas $(SCHEMA_DIR)

install-desktop:
	install -Dm644 data/$(APP_ID).desktop $(DESKTOP_DIR)/$(APP_ID).desktop
	update-desktop-database $(DESKTOP_DIR) 2>/dev/null || true

install-metainfo:
	install -Dm644 data/$(APP_ID).metainfo.xml $(METAINFO_DIR)/$(APP_ID).metainfo.xml

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)
	rm -f $(DESKTOP_DIR)/$(APP_ID).desktop
	rm -f $(SCHEMA_DIR)/$(APP_ID).gschema.xml
	rm -f $(METAINFO_DIR)/$(APP_ID).metainfo.xml
	rm -f $(ICON_DIR)/scalable/apps/$(BINARY).svg
	for icon in data/icons/hicolor/scalable/status/*.svg; do \
		rm -f $(ICON_DIR)/scalable/status/$$(basename $$icon); \
	done
	for icon in data/icons/hicolor/scalable/mimetypes/*.svg; do \
		rm -f $(ICON_DIR)/scalable/mimetypes/$$(basename $$icon); \
	done
	for icon in data/icons/Yaru/scalable/mimetypes/*.svg; do \
		rm -f $(PREFIX)/share/icons/Yaru/scalable/mimetypes/$$(basename $$icon); \
	done
	-glib-compile-schemas $(SCHEMA_DIR)
	-gtk-update-icon-cache -f $(ICON_DIR) 2>/dev/null || true
	-update-desktop-database $(DESKTOP_DIR) 2>/dev/null || true

clean:
	cargo clean

# Distribution packages
deb: all
	cargo deb -p openvpn3-gui-rs --no-build

rpm: all
	cargo generate-rpm --manifest-path gui/Cargo.toml

# Development targets
run:
	cargo run

test:
	cargo test --workspace

smoke-test:
	bash tests/smoke_test.sh

fmt:
	cargo fmt

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

debug:
	RUST_LOG=debug cargo run

# Install git hooks (run once after cloning)
setup-hooks:
	cp .git/hooks/pre-commit .git/hooks/pre-commit.bak 2>/dev/null || true
	install -m 755 scripts/pre-commit .git/hooks/pre-commit
	@echo "Git hooks installed."

# Run full local check suite (same as CI)
check:
	cargo fmt --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	bash tests/smoke_test.sh
	@echo "All checks passed."

# Install for testing (user-local, no sudo)
install-local: all
	install -Dm755 target/release/$(BINARY) ~/.local/bin/$(BINARY)
	install -Dm644 data/$(APP_ID).gschema.xml \
		~/.local/share/glib-2.0/schemas/$(APP_ID).gschema.xml
	glib-compile-schemas ~/.local/share/glib-2.0/schemas/
	install -Dm644 data/icons/hicolor/scalable/apps/$(BINARY).svg \
		~/.local/share/icons/hicolor/scalable/apps/$(BINARY).svg
	for icon in data/icons/hicolor/scalable/status/*.svg; do \
		install -Dm644 "$$icon" \
			~/.local/share/icons/hicolor/scalable/status/$$(basename $$icon); \
	done
	for icon in data/icons/hicolor/scalable/mimetypes/*.svg; do \
		install -Dm644 "$$icon" \
			~/.local/share/icons/hicolor/scalable/mimetypes/$$(basename $$icon); \
	done
	install -Dm644 data/$(APP_ID).desktop \
		~/.local/share/applications/$(APP_ID).desktop
	gtk-update-icon-cache -f ~/.local/share/icons/hicolor 2>/dev/null || true
