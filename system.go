package main

import (
	"context"
	"runtime"
	"time"

	"github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	systypes "github.com/docker/docker/api/types/system"
)

func (b *Backend) SystemInfo(ctx context.Context) (*systypes.Info, error) {
	return &systypes.Info{}, nil
}

func (b *Backend) SystemVersion(ctx context.Context) (types.Version, error) {
	return types.Version{
		Os:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       "26.1.4",
		APIVersion:    "1.45",
		MinAPIVersion: "1.24",
		GoVersion:     runtime.Version(),
	}, nil
}

func (b *Backend) SystemDiskUsage(ctx context.Context, opts system.DiskUsageOptions) (*types.DiskUsage, error) {
	return nil, errNotImplemented
}

func (b *Backend) SubscribeToEvents(since, until time.Time, ef filters.Args) ([]events.Message, chan any) {
	panic("not implemented")
}

func (b *Backend) UnsubscribeFromEvents(chan any) {
	panic("not implemented")
}

func (b *Backend) AuthenticateToRegistry(ctx context.Context, authConfig *registry.AuthConfig) (string, string, error) {
	return "", "", errNotImplemented
}
