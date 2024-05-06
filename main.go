package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

var blockEnd = Str2Bytes("]:")

func flamegraph(folded *bytes.Buffer, svg string) error {
	stdout, err := os.OpenFile(svg, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "can't open file \"%s\":%s\n", svg, err.Error())
		return err
	}
	defer func() {
		_ = stdout.Close()
	}()
	var stderr bytes.Buffer
	cmd := exec.Command("/opt/FlameGraph/flamegraph.pl")
	cmd.Dir = filepath.Dir(svg)
	cmd.Stdin = folded
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%s:%s", err.Error(), stderr.String())

		} else {
			return err
		}
	}
	return nil
}

func RenderSample(stack []string, cost int) string {
	slices.Reverse(stack)
	key := strings.Join(stack, ";")
	return fmt.Sprintf("%s %d\n", key, cost)
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
			if Bytes2Str(data) == "@[" {
				stackcn++
				state = true
				stack = stack[:0]
				//stack = append(stack, "system")
			}

		} else if bytes.HasPrefix(data, blockEnd) {
			data = bytes.TrimSpace(bytes.TrimPrefix(data, blockEnd))
			//栈结束了输出一条记录
			if cost, err := strconv.Atoi(Bytes2Str(data)); err == nil {
				in.WriteString(RenderSample(stack, cost))
				cn++
				allCost += cost

			} else {
				_, _ = fmt.Fprintf(os.Stderr, "l = %d:%s\n", l, err.Error())
			}
			state = false

		} else if len(data) > 0 {
			//将记录保存到栈中
			if index := bytes.Index(data, Str2Bytes("+")); index >= 0 {
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
	if err := flamegraph(&in, DeleteExt(f)+".svg"); err != nil {
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
	if len(os.Args) < 2 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: bpftrace_stack file\n")
		return
	}
	_ = ToFlameInput(os.Args[1])
}
