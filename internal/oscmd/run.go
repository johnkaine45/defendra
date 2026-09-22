package oscmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var ErrTimeout = errors.New("команда слишком долго выполнялась")

func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimRight(stdout.String(), "\n")
	errOut := strings.TrimRight(stderr.String(), "\n")
	if cctx.Err() == context.DeadlineExceeded {
		return out, errOut, fmt.Errorf("%w: %s", ErrTimeout, name)
	}
	return out, errOut, err
}

func RunOK(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	out, errOut, err := Run(ctx, timeout, name, args...)
	if err != nil {
		if errOut != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, errOut)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func LookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
