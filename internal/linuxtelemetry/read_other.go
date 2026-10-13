//go:build !linux

package linuxtelemetry

import "context"

type platformReader struct{}

func (platformReader) proc(string, int) ([]byte, error)        { return nil, errUnsupported }
func (platformReader) root(context.Context) (rootStats, error) { return rootStats{}, errUnsupported }
