package main

import (
	"context"
	"runtime"
	"time"

	"github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
)

func (b *Backend) SystemInfo() *types.Info {
	return &types.Info{}
}

func (b *Backend) SystemVersion() types.Version {
	return types.Version{
		Os:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       "20.10.17",
		APIVersion:    "1.41",
		MinAPIVersion: "1.12",
		GoVersion:     runtime.Version(),
	}
}

func (b *Backend) SystemDiskUsage(ctx context.Context, opts system.DiskUsageOptions) (*types.DiskUsage, error) {
	return nil, errNotImplemented
}

func (b *Backend) SubscribeToEvents(since, until time.Time, ef filters.Args) ([]events.Message, chan interface{}) {
	panic("not implemented")
}

func (b *Backend) UnsubscribeFromEvents(chan interface{}) {
	panic("not implemented")
}

func (b *Backend) AuthenticateToRegistry(ctx context.Context, authConfig *types.AuthConfig) (string, string, error) {
	return "", "", errNotImplemented
}
