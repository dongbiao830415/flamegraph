all:
	CGO_ENABLED=0 GOOS=linux   go build -v -trimpath -ldflags="-s -w" -o aaaa
	CGO_ENABLED=0 GOOS=windows go build -v -trimpath -ldflags="-s -w" -o aaaa.exe

clean:
	rm -f *.log *.exe aaaa
