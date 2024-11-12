package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

type Stack struct {
	data  []string
	x     int
	l     int
	b     int
	c     int
	bytes []int
	count []int
}

func (s *Stack) GetName() string {
	return fmt.Sprintf("%d_%d", s.x, s.l)
}

func (s *Stack) PointsBytes() plotter.XYs {
	points := make(plotter.XYs, len(s.bytes), len(s.bytes))
	for i, b := range s.bytes {
		points[i].X = float64(i)
		points[i].Y = float64(b)
	}
	return points
}

func (s *Stack) Equal(data []string) bool {
	if len(data) != len(s.data) {
		return false
	}
	j := 0
	for ; j < len(s.data); j++ {
		if s.data[j] != data[j] {
			break
		}
	}
	return j >= len(s.data)
}

func (s *Stack) Update(x int) {
	n := s.x - 1
	if s.x == x && n > 0 {
		s.bytes = make([]int, n)
		s.count = make([]int, n)
	}
	s.bytes = append(s.bytes, s.b)
	s.count = append(s.count, s.c)
	s.b = 0
	s.c = 0
}

func (s *Stack) GenPng() {
	p := plot.New()
	p.Title.Text = s.GetName()
	p.X.Label.Text = "X"
	p.Y.Label.Text = "Y"

	err := plotutil.AddLinePoints(p, "bytes", s.PointsBytes())
	if err != nil {
		log.Fatal(err)
	}

	if err = p.Save(4*vg.Inch, 4*vg.Inch, fmt.Sprintf("%s.png", s.GetName())); err != nil {
		log.Fatal(err)
	}
}

func (s *Stack) Print() {
	fmt.Printf("      %s\n", s.GetName())
	for j := 0; j < len(s.data); j++ {
		fmt.Printf("%d\t%s\n", j, s.data[j])
	}
	for j := 0; j < len(s.bytes); j++ {
		fmt.Printf("%d ", s.bytes[j])
	}
	fmt.Printf("\n\n")
}

var stacks []Stack

func findStack(data []string) *Stack {
	for i := 0; i < len(stacks); i++ {
		if stack := &stacks[i]; stack.Equal(data) {
			return stack
		}
	}
	return nil
}

func updateStack(x int) {
	if x == 0 {
		return
	}
	for i := 0; i < len(stacks); i++ {
		stacks[i].Update(x)
	}
}

func RenderSample(stack []string, cost int) string {
	slices.Reverse(stack)
	key := strings.Join(stack, ";")
	return fmt.Sprintf("%s %d\n", key, cost)
}

func parseMemleakResult(f string) error {
	file, err := os.Open(f)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "can't open file:%s\n", err.Error())
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	var x int
	var l int
	var data []string
	var b, c int
	var in bytes.Buffer
	maxDep := 0
	maxl := 0
	f1 := func() {
		//i := 0
		//for ; i < len(data); i++ {
		//	if strings.Contains(data[i], "build_ssl_ctx+") {
		//		break
		//	}
		//}
		//if i >= len(data) {
		//	return
		//}
		if stack := findStack(data); stack != nil {
			stack.b += b
			stack.c += c

		} else {
			if len(data) > maxDep {
				maxDep = len(data)
				maxl = l
			}
			stacks = append(stacks, Stack{data: data, x: x, l: l, b: b, c: c})
		}
	}

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
		lineStr := string(line)
		if strings.HasPrefix(lineStr, "[") {
			updateStack(x)
			x++
			continue
		}
		if strings.HasSuffix(lineStr, " allocations from stack") {
			if len(data) > 0 {
				f1()
			}

			fields := strings.Fields(lineStr)
			if b, err = strconv.Atoi(fields[0]); err != nil {
				return err
			}
			if c, err = strconv.Atoi(fields[3]); err != nil {
				return err
			}
			data = make([]string, 0, 20)
			continue
		}
		//fmt.Printf("%s\n", lineStr)
		lineStr = strings.TrimSpace(lineStr)
		if len(lineStr) <= 0 {
			continue
		}
		fields := strings.Fields(lineStr)
		data = append(data, fields[1])
	}
	f1()
	updateStack(x)

	fmt.Printf("x = %d\t%d\n", x, len(stacks))

	for i := 0; i < len(stacks); i++ {
		stacks[i].Print()
		fmt.Printf("\n\n")
	}

	for i := 0; i < len(stacks); i++ {
		j := 0
		for ; j < len(stacks[i].data); j++ {
			if strings.Contains(stacks[i].data[j], "SSL_CTX_new") {
				break
			}
		}
		if j < len(stacks[i].data) {
			in.WriteString(RenderSample(stacks[i].data, 1))
		}
	}

	//if err := util.Flamegraph(&in, "./a.svg"); err != nil {
	//	_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	//	return err
	//}

	fmt.Printf("%d\t%d\n", maxl, maxDep)
	return nil
}

func main() {
	if err := parseMemleakResult("./a.txt"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return
	}
	for i := 0; i < len(stacks); i++ {
		stacks[i].GenPng()
	}
}
