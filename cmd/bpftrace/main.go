package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dongbiao830415/flamegraph/util"
)

var one bool

var blockEnd = util.Str2Bytes("]:")

var sample = make(map[string]int)

func RenderSample(stack []string, cost int) {
	var i int
	for ; i < len(stack); i++ {
		if stack[i] == "main" {
			break
		}
	}
	if i < len(stack) {
		stack = stack[:i+1]
	}
	slices.Reverse(stack)
	key := strings.Join(stack, ";")

	allCost, ok := sample[key]
	if !ok {
		allCost = cost

	} else {
		allCost += cost
	}
	sample[key] = allCost
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

	var stack []string
	var state bool
	var cn int
	var l int
	var stackcn int
	var allCost int
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

		data := bytes.TrimSpace(line)
		if !state {
			if util.Bytes2Str(data) == "@[" {
				stackcn++
				state = true
				stack = stack[:0]
				//stack = append(stack, "system")
			}

		} else if bytes.HasPrefix(data, blockEnd) {
			data = bytes.TrimSpace(bytes.TrimPrefix(data, blockEnd))
			//栈结束了输出一条记录
			if cost, err := strconv.Atoi(util.Bytes2Str(data)); err == nil {
				RenderSample(stack, cost)
				cn++
				allCost += cost

			} else {
				_, _ = fmt.Fprintf(os.Stderr, "l = %d:%s\n", l, err.Error())
			}
			state = false

		} else if len(data) > 0 {
			//将记录保存到栈中
			if index := bytes.Index(data, util.Str2Bytes("+")); index >= 0 {
				data = data[0:index]
			}
			stack = append(stack, string(data))
		}
	}
	if cn <= 0 {
		err = fmt.Errorf("too few stacks")
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return err
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
	fmt.Printf("flame stack number = %d\n", cn)
	fmt.Printf("all cost           = %v\n", time.Duration(allCost))
	return nil
}

// 过滤进程号、过滤行号
func main() {
	flag.BoolVar(&one, "o", false, "one sample")
	flag.Parse()

	args := flag.Args()
	if len(args) <= 0 {
		flag.Usage()
		return
	}

	_ = ToFlameInput(args[0])
}
