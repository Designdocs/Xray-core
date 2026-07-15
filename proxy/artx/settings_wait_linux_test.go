//go:build linux

package artx

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxSettingsWaiterUsesAbsoluteMonotonicDeadline(t *testing.T) {
	goNow := time.Unix(100, 0)
	kernelNow := unix.Timespec{Sec: 200, Nsec: 500}
	deadline := goNow.Add(30 * time.Microsecond)
	var gotClockID int32
	var gotFlags int
	var gotDeadline unix.Timespec

	err := waitForSettingsDeadlineLinux(
		context.Background(),
		deadline,
		func() time.Time { return goNow },
		func(clockID int32, value *unix.Timespec) error {
			if clockID != unix.CLOCK_MONOTONIC {
				t.Fatalf("clock ID = %d, want CLOCK_MONOTONIC", clockID)
			}
			*value = kernelNow
			return nil
		},
		func(clockID int32, flags int, request *unix.Timespec, remain *unix.Timespec) error {
			gotClockID = clockID
			gotFlags = flags
			gotDeadline = *request
			if remain != nil {
				t.Fatal("absolute clock_nanosleep received a remainder pointer")
			}
			return nil
		},
		testTimerSlackControl(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotClockID != unix.CLOCK_MONOTONIC || gotFlags != unix.TIMER_ABSTIME {
		t.Fatalf("clock_nanosleep clock/flags = %d/%d, want %d/%d", gotClockID, gotFlags, unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME)
	}
	wantDeadline := unix.NsecToTimespec(unix.TimespecToNsec(kernelNow) + int64(30*time.Microsecond))
	if gotDeadline != wantDeadline {
		t.Fatalf("kernel deadline = %+v, want %+v", gotDeadline, wantDeadline)
	}
}

func TestLinuxSettingsWaiterRetriesInterruptedAbsoluteWait(t *testing.T) {
	goNow := time.Unix(100, 0)
	kernelNow := unix.Timespec{Sec: 200, Nsec: 999_990_000}
	var requests []unix.Timespec

	err := waitForSettingsDeadlineLinux(
		context.Background(),
		goNow.Add(30*time.Microsecond),
		func() time.Time { return goNow },
		func(_ int32, value *unix.Timespec) error {
			*value = kernelNow
			return nil
		},
		func(_ int32, _ int, request *unix.Timespec, _ *unix.Timespec) error {
			requests = append(requests, *request)
			if len(requests) == 1 {
				return unix.EINTR
			}
			return nil
		},
		testTimerSlackControl(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("clock_nanosleep calls = %d, want 2", len(requests))
	}
	wantDeadline := unix.Timespec{Sec: 201, Nsec: 20_000}
	for index, request := range requests {
		if request != wantDeadline {
			t.Fatalf("request %d = %+v, want unchanged absolute deadline %+v", index, request, wantDeadline)
		}
	}
}

func TestLinuxSettingsWaiterRejectsUnboundedPRetention(t *testing.T) {
	goNow := time.Unix(100, 0)
	clockRead := false
	err := waitForSettingsDeadlineLinux(
		context.Background(),
		goNow.Add(maxPreciseSettingsWait+time.Microsecond),
		func() time.Time { return goNow },
		func(int32, *unix.Timespec) error {
			clockRead = true
			return nil
		},
		func(int32, int, *unix.Timespec, *unix.Timespec) error { return nil },
		testTimerSlackControl(),
	)
	if err == nil {
		t.Fatal("unbounded precise settings wait was accepted")
	}
	if clockRead {
		t.Fatal("read the clock for an out-of-range wait")
	}
}

func TestLinuxSettingsWaiterSetsAndRestoresThreadTimerSlack(t *testing.T) {
	goNow := time.Unix(100, 0)
	events := make([]string, 0, 6)
	timerSlack := timerSlackControl{
		current: func() (int, error) {
			events = append(events, "get slack")
			return 50_000, nil
		},
		set: func(value uintptr) error {
			switch value {
			case 1:
				events = append(events, "set slack")
			case 50_000:
				events = append(events, "restore slack")
			default:
				t.Fatalf("timer slack = %d, want 1 or 50000", value)
			}
			return nil
		},
	}

	err := waitForSettingsDeadlineLinux(
		context.Background(),
		goNow.Add(30*time.Microsecond),
		func() time.Time {
			events = append(events, "read Go clock")
			return goNow
		},
		func(_ int32, value *unix.Timespec) error {
			events = append(events, "read kernel clock")
			*value = unix.Timespec{Sec: 200}
			return nil
		},
		func(int32, int, *unix.Timespec, *unix.Timespec) error {
			events = append(events, "sleep")
			return nil
		},
		timerSlack,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantEvents := []string{"get slack", "set slack", "read Go clock", "read kernel clock", "sleep", "restore slack"}
	if len(events) != len(wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	for index := range wantEvents {
		if events[index] != wantEvents[index] {
			t.Fatalf("events = %v, want %v", events, wantEvents)
		}
	}
}

func TestLinuxSettingsWaiterFailsClosedOnTimerSlackErrors(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		wantErr := errors.New("read slack failed")
		setCalls := 0
		err := runLinuxSettingsWaiterWithTimerSlack(timerSlackControl{
			current: func() (int, error) { return 0, wantErr },
			set: func(uintptr) error {
				setCalls++
				return nil
			},
		}, nil)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if setCalls != 0 {
			t.Fatalf("timer slack sets = %d, want 0", setCalls)
		}
	})

	t.Run("set", func(t *testing.T) {
		wantErr := errors.New("set slack failed")
		setCalls := 0
		err := runLinuxSettingsWaiterWithTimerSlack(timerSlackControl{
			current: func() (int, error) { return 50_000, nil },
			set: func(uintptr) error {
				setCalls++
				return wantErr
			},
		}, nil)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if setCalls != 1 {
			t.Fatalf("timer slack sets = %d, want 1", setCalls)
		}
	})

	t.Run("restore after success", func(t *testing.T) {
		wantErr := errors.New("restore slack failed")
		setCalls := 0
		err := runLinuxSettingsWaiterWithTimerSlack(timerSlackControl{
			current: func() (int, error) { return 50_000, nil },
			set: func(uintptr) error {
				setCalls++
				if setCalls == 2 {
					return wantErr
				}
				return nil
			},
		}, nil)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if setCalls != 2 {
			t.Fatalf("timer slack sets = %d, want 2", setCalls)
		}
	})

	t.Run("restore does not replace operation error", func(t *testing.T) {
		operationErr := errors.New("clock failed")
		restoreErr := errors.New("restore slack failed")
		setCalls := 0
		err := runLinuxSettingsWaiterWithTimerSlack(timerSlackControl{
			current: func() (int, error) { return 50_000, nil },
			set: func(uintptr) error {
				setCalls++
				if setCalls == 2 {
					return restoreErr
				}
				return nil
			},
		}, operationErr)
		if !errors.Is(err, operationErr) {
			t.Fatalf("error = %v, want %v", err, operationErr)
		}
		if errors.Is(err, restoreErr) {
			t.Fatalf("restore error replaced operation error: %v", err)
		}
	})
}

func TestLinuxSettingsWaiterChecksCancellationAroundSyscall(t *testing.T) {
	t.Run("before clock read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		clockRead := false
		err := waitForSettingsDeadlineLinux(
			ctx,
			time.Now().Add(time.Microsecond),
			time.Now,
			func(int32, *unix.Timespec) error {
				clockRead = true
				return nil
			},
			func(int32, int, *unix.Timespec, *unix.Timespec) error { return nil },
			testTimerSlackControl(),
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if clockRead {
			t.Fatal("read the clock after cancellation")
		}
	})

	t.Run("after interrupted sleep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		goNow := time.Unix(100, 0)
		calls := 0
		err := waitForSettingsDeadlineLinux(
			ctx,
			goNow.Add(192*time.Microsecond),
			func() time.Time { return goNow },
			func(_ int32, value *unix.Timespec) error {
				*value = unix.Timespec{Sec: 200}
				return nil
			},
			func(int32, int, *unix.Timespec, *unix.Timespec) error {
				calls++
				cancel()
				return unix.EINTR
			},
			testTimerSlackControl(),
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if calls != 1 {
			t.Fatalf("clock_nanosleep calls = %d, want 1", calls)
		}
	})
}

func TestRawClockNanosleepReturnsKernelErrno(t *testing.T) {
	request := unix.Timespec{}
	err := rawClockNanosleep(-1, unix.TIMER_ABSTIME, &request, nil)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("error = %v, want EINVAL", err)
	}
}

func testTimerSlackControl() timerSlackControl {
	return timerSlackControl{
		current: func() (int, error) { return 50_000, nil },
		set:     func(uintptr) error { return nil },
	}
}

func runLinuxSettingsWaiterWithTimerSlack(timerSlack timerSlackControl, clockErr error) error {
	goNow := time.Unix(100, 0)
	return waitForSettingsDeadlineLinux(
		context.Background(),
		goNow.Add(30*time.Microsecond),
		func() time.Time { return goNow },
		func(_ int32, value *unix.Timespec) error {
			*value = unix.Timespec{Sec: 200}
			return clockErr
		},
		func(int32, int, *unix.Timespec, *unix.Timespec) error { return nil },
		timerSlack,
	)
}
