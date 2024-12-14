package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dongbiao830415/flamegraph/util"
)

var (
	display bool
	one     bool
)

type Local struct {
	FuncName string
	FileLine string
}

func (l *Local) String() string {
	if !display || l.FileLine == "" {
		return l.FuncName
	}
	return fmt.Sprintf("%s at %s", l.FuncName, l.FileLine)
}

var (
	exeCache     = make(map[string]map[string]Local)
	addr2lineCn  int
	cache2lineCn int
)

var blockEnd = util.Str2Bytes("]:")

var sample = make(map[string]int)

func Addr2line(exe, address string) ([]byte, error) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	//addr2line -e /opt/WiseGrid/api/bin/smartapi -f -i -s  -C  0x71e277
	args := []string{
		"-e", exe,
		"-f",
		"-i",
		"-s",
		"-C",
		"-p",
		address,
	}
	cmd := exec.Command("addr2line", args...)
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
		return string(line), nil
	}
	return "", fmt.Errorf("not found")
}

func GetFuncName(exe, address string) Local {
	addressCache, ok := exeCache[exe]
	if !ok {
		addressCache = make(map[string]Local)
		exeCache[exe] = addressCache
	}
	local, ok := addressCache[address]
	if ok {
		cache2lineCn++
		return local
	}

	data, err := Addr2FuncName(exe, address)
	if err != nil {
		return Local{FuncName: address}
	}
	field := strings.Split(data, " at ")
	if len(field) != 2 {
		return Local{FuncName: address}
	}
	local = Local{FuncName: field[0], FileLine: field[1]}
	addressCache[address] = local

	addr2lineCn++
	return local
}

// RenderSample 累计
func RenderSample(stack []Local, cost int) {
	for i := 0; i < len(stack)-1; i++ {
		stack[i].FileLine = stack[i+1].FileLine
	}
	stack[len(stack)-1].FileLine = ""

	stackStr := make([]string, 0, len(stack))
	for i := len(stack) - 1; i >= 0; i-- {
		stackStr = append(stackStr, stack[i].String())
	}
	key := strings.Join(stackStr, ";")
	allCost, ok := sample[key]
	if !ok {
		allCost = cost

	} else {
		allCost += cost
	}
	sample[key] = allCost
}

var l int
var isSkip = false

func parseBacktrace(data []byte) (Local, error) {
	fileds := bytes.Fields(data)
	if len(fileds) != 10 {
		err := fmt.Errorf("stack format error")
		_, _ = fmt.Fprintf(os.Stderr, "backtrace format error at %d:%s\n", l, err.Error())
		return Local{}, err
	}

	exe := fileds[8]
	if j := bytes.IndexByte(exe, '('); j >= 0 {
		exe = exe[0:j]
	}

	if bytes.Contains(exe, util.Str2Bytes("hook.so")) ||
		bytes.Contains(exe, util.Str2Bytes("libmariadb.so")) ||
		bytes.Contains(exe, util.Str2Bytes("libmicrohttpd.so")) {
		isSkip = true
		return Local{}, fmt.Errorf("skip")

	} else if bytes.Contains(exe, util.Str2Bytes("smartctrl")) {
		exe = util.Str2Bytes("/opt/WiseGrid/shell/smartctrl")
	}

	address := fileds[9]
	address = bytes.TrimPrefix(bytes.TrimSuffix(address, util.Str2Bytes("]")), util.Str2Bytes("["))
	addr := string(address)

	return GetFuncName(string(exe), addr), nil
}

func ToFlameInput(f string) error {
	var in bytes.Buffer

	file, err := os.Open(f)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "can't open file:%s\n", err.Error())
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	var state bool
	var stack []Local
	var stackcn int
	var allCost int

	br := bufio.NewReader(file)
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break

		} else if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to read line:%s\n", err.Error())
			return err
		}
		l++
		data := bytes.TrimSpace(line)
		if !state {
			if bytes.HasSuffix(data, util.Str2Bytes("@[")) {
				stackcn++
				state = true
				stack = stack[:0]
				isSkip = false
			}

		} else if index := bytes.Index(data, blockEnd); index != -1 {
			data = bytes.TrimSpace(bytes.TrimPrefix(data[index:], blockEnd))
			//栈结束了输出一条记录
			if cost, err := strconv.Atoi(util.Bytes2Str(data)); err == nil {
				RenderSample(stack, cost)
				allCost += cost

			} else {
				_, _ = fmt.Fprintf(os.Stderr, "failed to parse back trace cost at %d:%s\n", l, err.Error())
			}
			state = false

			if isSkip {
				_, _ = fmt.Fprintf(os.Stderr, "have skip line at %d\n", l)
			}

		} else if len(data) > 0 {
			local, err := parseBacktrace(data)
			if err != nil {
				continue
			}
			stack = append(stack, local)
		}
	}

	if len(sample) <= 0 {
		err = fmt.Errorf("too few stacks")
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return err
	}
	for k, v := range sample {
		if one {
			v = 1
		}
		in.WriteString(fmt.Sprintf("%s %d\n", k, v))
	}
	if err := util.Flamegraph(&in, util.DeleteExt(f)+".svg"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return err
	}
	fmt.Printf("line               = %d\n", l)
	fmt.Printf("stack number       = %d\n", stackcn)
	fmt.Printf("flame stack number = %d\n", len(sample))
	fmt.Printf("all cost           = %v\n", time.Duration(allCost)*1000)
	fmt.Printf("addr2lineCn        = %d\n", addr2lineCn)
	fmt.Printf("cache2lineCn       = %d\n", cache2lineCn)
	return nil
}

// 过滤进程号、过滤行号
func main() {
	flag.BoolVar(&display, "d", false, "display file line")
	flag.BoolVar(&one, "o", false, "one sample")
	flag.Parse()

	args := flag.Args()
	if len(args) <= 0 {
		flag.Usage()
		return
	}
	tm := time.Now()
	defer func() {
		fmt.Printf("cost               = %v\n", time.Now().Sub(tm))
	}()
	_ = ToFlameInput(args[0])
}
