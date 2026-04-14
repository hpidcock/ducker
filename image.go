package main

import (
	"context"
	"fmt"
	"io"

	"github.com/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/errdefs"
	dockerimage "github.com/docker/docker/image"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

func (b *Backend) ImageDelete(ctx context.Context, imageRef string, force, prune bool) ([]image.DeleteResponse, error) {
	return nil, errNotImplemented
}

func (b *Backend) ImageHistory(ctx context.Context, imageName string) ([]*image.HistoryResponseItem, error) {
	return nil, errNotImplemented
}

func (b *Backend) Images(ctx context.Context, opts image.ListOptions) ([]*image.Summary, error) {
	images := []*image.Summary{}
	for k := range b.config.Images {
		images = append(images, &image.Summary{
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

func (b *Backend) TagImage(ctx context.Context, id dockerimage.ID, newRef reference.Named) error {
	return errNotImplemented
}

func (b *Backend) GetImage(ctx context.Context, refOrID string, opts backend.GetImageOpts) (*dockerimage.Image, error) {
	return nil, errNotImplemented
}

func (b *Backend) ImagesPrune(ctx context.Context, pruneFilters filters.Args) (*types.ImagesPruneReport, error) {
	return &types.ImagesPruneReport{}, nil
}

func (b *Backend) LoadImage(ctx context.Context, inTar io.ReadCloser, outStream io.Writer, quiet bool) error {
	return errNotImplemented
}

func (b *Backend) ImportImage(ctx context.Context, ref reference.Named, platform *specs.Platform, msg string, layerReader io.Reader, changes []string) (dockerimage.ID, error) {
	return "", errNotImplemented
}

func (b *Backend) ExportImage(ctx context.Context, names []string, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) PullImage(ctx context.Context, ref reference.Named, platform *specs.Platform, metaHeaders map[string][]string, authConfig *registry.AuthConfig, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) PushImage(ctx context.Context, ref reference.Named, metaHeaders map[string][]string, authConfig *registry.AuthConfig, outStream io.Writer) error {
	return errNotImplemented
}

func (b *Backend) SearchRegistryForImages(ctx context.Context, searchFilters filters.Args, term string, limit int, authConfig *registry.AuthConfig, metaHeaders map[string][]string) (*registry.SearchResults, error) {
	return nil, errNotImplemented
}
