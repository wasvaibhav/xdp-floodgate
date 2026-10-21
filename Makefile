IMAGE ?= floodgate:dev

# Native Linux (needs clang, llvm, libbpf-dev, go).
build:
	go generate ./...
	go build -o bin/floodgate ./cmd/floodgate

PREFIX ?= /usr/local
SYSTEMD_DIR ?= /etc/systemd/system
install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 bin/floodgate "$(DESTDIR)$(PREFIX)/bin/floodgate"
	install -d "$(DESTDIR)$(SYSTEMD_DIR)"
	install -m 0644 deploy/floodgate.service "$(DESTDIR)$(SYSTEMD_DIR)/floodgate.service"
	install -d "$(DESTDIR)/etc/default"
	@if [ ! -e "$(DESTDIR)/etc/default/floodgate" ]; then \
		install -m 0644 deploy/floodgate.default "$(DESTDIR)/etc/default/floodgate"; \
	fi

# BPF_PROG_RUN tests need root; unit tests don't.
test:
	go generate ./...
	sudo -E go test ./...

# Anywhere with Docker (incl. Docker Desktop on macOS/Windows).
docker-build:
	docker build -t $(IMAGE) .

docker-test:
	docker build --target build -t $(IMAGE)-build .
	docker run --rm --privileged $(IMAGE)-build sh -c \
		'mount -t bpf bpf /sys/fs/bpf 2>/dev/null; go test ./...'

.PHONY: build install test docker-build docker-test
