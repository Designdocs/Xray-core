//go:build !linux

package artx

import (
	"context"
	"time"
)

const preciseSettingsDeadlineSupported = false

func waitForSettingsDeadline(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errPreciseSettingsDeadlineUnsupported
}
