all:
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o bpftrace  github.com/dongbiao830415/flamegraph/cmd/bpftrace
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o backtrace github.com/dongbiao830415/flamegraph/cmd/backtrace
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o memleak   github.com/dongbiao830415/flamegraph/cmd/memleak
debug:
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o bpftrace  github.com/dongbiao830415/flamegraph/cmd/bpftrace
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o backtrace github.com/dongbiao830415/flamegraph/cmd/backtrace
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o memleak   github.com/dongbiao830415/flamegraph/cmd/memleak
clean:
	rm -f *.log *.exe bpftrace backtrace memleak *.svg *.png
