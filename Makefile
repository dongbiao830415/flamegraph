all:
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o bpftrace  github.com/dongbiao830415/flamegraph/cmd/bpftrace
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o backtrace github.com/dongbiao830415/flamegraph/cmd/backtrace
debug:
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o bpftrace  github.com/dongbiao830415/flamegraph/cmd/bpftrace
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o backtrace github.com/dongbiao830415/flamegraph/cmd/backtrace
clean:
	rm -f *.log *.exe bpftrace backtrace *.svg
