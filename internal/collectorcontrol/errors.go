package collectorcontrol

import "errors"

var ErrWorkLeaseInvalid = errors.New("collector work lease is invalid or expired")
var ErrResultConflict = errors.New("collector result conflicts with current state")
