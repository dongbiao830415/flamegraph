all:
	CGO_ENABLED=0 GOOS=linux go build -v -trimpath -ldflags="-s -w" -o bpftrace_to_flamegraph
debug:
	CGO_ENABLED=0 GOOS=linux go build -v -gcflags="all=-N -l" -o bpftrace_to_flamegraph
clean:
	rm -f *.log *.exe bpftrace_to_flamegraph *.svg
