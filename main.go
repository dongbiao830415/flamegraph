package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var (
	exeCache     = make(map[string]map[string]string)
	addr2lineCn  int
	cache2lineCn int
)

var sample = make(map[string]int)

func Addr2line(exe, address string) ([]byte, error) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	//addr2line -e /opt/WiseGrid/api/bin/smartapi -f -i -s  -C  0x71e277
	cmd := exec.Command("addr2line", "-e", exe, "-f", "-i", "-s", "-C", address)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return []byte{}, fmt.Errorf("%s:%s", err.Error(), stderr.String())

		} else {
			return []byte{}, err
		}
	}
	return stdout.Bytes(), nil
}

func Addr2FuncName(exe, address string) (string, error) {
	out, err := Addr2line(exe, address)
	if err != nil {
		return "", err
	}
	br := bufio.NewReader(bytes.NewReader(out))
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break

		} else if err != nil {
			return "", err
		}
		return Bytes2Str(line), nil
	}
	return "", fmt.Errorf("not found")
}

func GetFuncName(exe, address string) (string, error) {
	addressCache, ok := exeCache[exe]
	if !ok {
		addressCache = make(map[string]string)
		exeCache[exe] = addressCache
	}
	funcName, ok := addressCache[address]
	if ok {
		cache2lineCn++
		return funcName, nil
	}

	funcName, err := Addr2FuncName(exe, address)
	if err != nil {
		return "", err
	}

	addressCache[address] = funcName
	addr2lineCn++
	return funcName, nil
}

func RenderSample(stack []string) {
	if len(stack) > 1 {
		for i := 0; i < len(stack)/2; i++ {
			stack[i], stack[len(stack)-1-i] = stack[len(stack)-1-i], stack[i]
		}
	}
	key := strings.Join(stack, ";")
	cn, ok := sample[key]
	if !ok {
		cn = 1

	} else {
		cn++
	}
	sample[key] = cn
}

func ToFlameInput(f string) error {
	file, err := os.Open(f)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "can't open file:%s\n", err.Error())
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	var stack []string
	var cn int
	var l int
	br := bufio.NewReader(file)
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break

		} else if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			return err
		}
		l++
		data := Bytes2Str(line)
		if !strings.Contains(data, "SYMBOL layer") {
			continue
		}

		fileds := strings.Fields(data)
		if len(fileds) != 9 {
			err = fmt.Errorf("stack format error")
			_, _ = fmt.Fprintf(os.Stderr, "line %d %s\n", l, err.Error())
			return err
		}

		index := fileds[6]
		if index = strings.TrimSuffix(index, ":"); index == "0" && len(stack) > 0 {
			RenderSample(stack)
			cn++
			stack = stack[:0]
		}

		exe := fileds[7]
		if j := strings.IndexByte(exe, '('); j >= 0 {
			exe = exe[0:j]
		}

		address := fileds[8]
		address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")

		funcName, err := GetFuncName(exe, address)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "line %d %s\n", l, err.Error())
			return err
		}

		stack = append(stack, funcName)
	}
	if len(stack) <= 0 {
		err = fmt.Errorf("too few stacks")
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return err
	}
	RenderSample(stack)
	cn++

	_, _ = fmt.Fprintf(os.Stderr, "stack number = %d\n", cn)
	_, _ = fmt.Fprintf(os.Stderr, "sample number= %d\n", len(sample))
	_, _ = fmt.Fprintf(os.Stderr, "addr2lineCn  = %d\n", addr2lineCn)
	_, _ = fmt.Fprintf(os.Stderr, "cache2lineCn = %d\n", cache2lineCn)

	for k, v := range sample {
		if one {
			v = 1
		}
		fmt.Printf("%s %d\n", k, v)
	}

	return nil
}

var one bool

// 过滤进程号、过滤行号
func main() {
	flag.BoolVar(&one, "one", false, "one")
	flag.Parse()

	args := flag.Args()
	if len(args) <= 0 {
		os.Exit(1)
		return
	}
	_ = ToFlameInput(args[0])
}
