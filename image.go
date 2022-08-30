package main

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/errdefs"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

func (b *Backend) ImageDelete(imageRef string, force, prune bool) ([]types.ImageDeleteResponseItem, error) {
	return nil, errNotImplemented
}

func (b *Backend) ImageHistory(imageName string) ([]*image.HistoryResponseItem, error) {
	return nil, errNotImplemented
}

func (b *Backend) Images(ctx context.Context, opts types.ImageListOptions) ([]*types.ImageSummary, error) {
	images := []*types.ImageSummary{}
	for k := range b.config.Images {
		images = append(images, &types.ImageSummary{
			ID:       k,
			RepoTags: []string{k},
		})
	}
	return images, nil
}

func (b *Backend) LookupImage(name string) (*types.ImageInspect, error) {
	ref, err := reference.Parse(name)
	if err != nil {
		return nil, err
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return nil, errdefs.InvalidParameter(fmt.Errorf("%s does not name an image", name))
	}
	name = named.Name()
	_, ok = b.config.Images[name]
	if !ok {
		return nil, errdefs.NotFound(fmt.Errorf("%s not found", name))
	}
	inspect := &types.ImageInspect{
		ID:       name,
		RepoTags: []string{name},
	}
	return inspect, nil
}

func (b *Backend) TagImage(imageName, repository, tag string) (string, error) {
	return "", errNotImplemented
}

func (b *Backend) ImagesPrune(ctx context.Context, pruneFilters filters.Args) (*types.ImagesPruneReport, error) {
	return &types.ImagesPruneReport{}, nil
}

func (b *Backend) LoadImage(inTar io.ReadCloser, outStream io.Writer, quiet bool) error {
	return errNotImplemented
}

func (b *Backend) ImportImage(src string, repository string, platform *specs.Platform, tag string, msg string, inConfig io.ReadCloser, outStream io.Writer, changes []string) error {
	return errNotImplemented
}

func (b *Backend) ExportImage(names []string, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) PullImage(ctx context.Context, image, tag string, platform *specs.Platform, metaHeaders map[string][]string, authConfig *types.AuthConfig, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) PushImage(ctx context.Context, image, tag string, metaHeaders map[string][]string, authConfig *types.AuthConfig, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) SearchRegistryForImages(ctx context.Context, searchFilters filters.Args, term string, limit int, authConfig *types.AuthConfig, metaHeaders map[string][]string) (*registry.SearchResults, error) {
	return nil, errNotImplemented
}
