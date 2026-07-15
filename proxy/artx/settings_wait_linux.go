//go:build linux

package artx

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type clockGettimeFunc func(int32, *unix.Timespec) error

type clockNanosleepFunc func(int32, int, *unix.Timespec, *unix.Timespec) error

type timerSlackControl struct {
	current func() (int, error)
	set     func(uintptr) error
}

const preciseSettingsDeadlineSupported = true

const maxPreciseSettingsWait = 192 * time.Microsecond

func waitForSettingsDeadline(ctx context.Context, deadline time.Time) error {
	return waitForSettingsDeadlineLinux(
		ctx,
		deadline,
		time.Now,
		unix.ClockGettime,
		rawClockNanosleep,
		timerSlackControl{current: currentThreadTimerSlack, set: setThreadTimerSlack},
	)
}

func waitForSettingsDeadlineLinux(
	ctx context.Context,
	deadline time.Time,
	now func() time.Time,
	clockGettime clockGettimeFunc,
	clockNanosleep clockNanosleepFunc,
	timerSlack timerSlackControl,
) (waitErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	previousTimerSlack, err := timerSlack.current()
	if err != nil {
		return fmt.Errorf("artx: read thread timer slack: %w", err)
	}
	if err := timerSlack.set(1); err != nil {
		return fmt.Errorf("artx: set thread timer slack: %w", err)
	}
	defer func() {
		if err := timerSlack.set(uintptr(previousTimerSlack)); err != nil && waitErr == nil {
			waitErr = fmt.Errorf("artx: restore thread timer slack: %w", err)
		}
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	remaining := nonNegativeDuration(now(), deadline)
	if remaining == 0 {
		return nil
	}
	if remaining > maxPreciseSettingsWait {
		return fmt.Errorf("artx: precise settings wait %s exceeds maximum %s", remaining, maxPreciseSettingsWait)
	}

	var monotonicNow unix.Timespec
	if err := clockGettime(unix.CLOCK_MONOTONIC, &monotonicNow); err != nil {
		return fmt.Errorf("artx: read monotonic clock: %w", err)
	}
	kernelDeadline := addTimespecDuration(monotonicNow, remaining)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := clockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &kernelDeadline, nil)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("artx: wait for settings deadline: %w", err)
		}
	}
}

func currentThreadTimerSlack() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_TIMERSLACK, 0, 0, 0, 0)
}

func setThreadTimerSlack(value uintptr) error {
	return unix.Prctl(unix.PR_SET_TIMERSLACK, value, 0, 0, 0)
}

// rawClockNanosleep deliberately bypasses the Go scheduler's syscall hooks so
// the goroutine does not pay a post-sleep P reacquisition delay. The caller
// caps this kernel sleep at 192 microseconds, bounding how long it retains a P.
func rawClockNanosleep(clockID int32, flags int, request *unix.Timespec, remain *unix.Timespec) error {
	_, _, errno := unix.RawSyscall6(
		unix.SYS_CLOCK_NANOSLEEP,
		uintptr(clockID),
		uintptr(flags),
		uintptr(unsafe.Pointer(request)),
		uintptr(unsafe.Pointer(remain)),
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func addTimespecDuration(value unix.Timespec, duration time.Duration) unix.Timespec {
	return unix.NsecToTimespec(unix.TimespecToNsec(value) + duration.Nanoseconds())
}
