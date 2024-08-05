package util

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Flamegraph(in *bytes.Buffer, svg string) error {
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
	cmd.Stdin = in
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
