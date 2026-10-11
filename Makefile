BINARY  := spoofer
APP_NAME := fmmon
MODULE  := github.com/saif/spoofer

.PHONY: build test vet lint clean install run

debug:
	go build -gcflags="all=-N -l" -o $(BINARY) .


build:
	go build -o $(BINARY) .

sync-windows: build-windows
	cp $(BINARY).exe ~/Windows/

wails:
	wails3 build

wdev:
	wails3 dev

wails-windows:
	GOOS=windows wails3 build
	cp bin/$(APP_NAME).exe ~/Windows/Spoofer.exe
	
build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY).exe .

wbuild:
	go build -o $(BINARY).exe .

install: wails
	sudo ./install.sh

run-windows: wbuild
	./$(BINARY).exe

run: build
	./$(BINARY)

test:
	go test ./... -count=1

vet:
	go vet ./...

lint: vet
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

clean:
	rm -f $(BINARY)
