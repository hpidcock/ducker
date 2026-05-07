package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/errdefs"
	dockerimage "github.com/docker/docker/image"
	digest "github.com/opencontainers/go-digest"
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

// GetImage returns image metadata for the named image, looked up against
// the configured EC2 AMI image map.
func (b *Backend) GetImage(
	ctx context.Context,
	refOrID string,
	opts backend.GetImageOpts,
) (*dockerimage.Image, error) {
	ref, err := reference.ParseNormalizedNamed(refOrID)
	if err != nil {
		return nil, errdefs.InvalidParameter(err)
	}
	name := reference.FamiliarName(ref)
	_, ok := b.config.Images[name]
	if !ok {
		return nil, errdefs.NotFound(
			fmt.Errorf("%s not found", name))
	}
	arch := "amd64"
	if strings.HasSuffix(name, "-arm64") {
		arch = "arm64"
	}
	img := dockerimage.NewImage(
		dockerimage.ID(digest.FromString(name)))
	img.V1Image.Architecture = arch
	img.V1Image.OS = "linux"
	img.V1Image.Config = &container.Config{}
	img.RootFS = &dockerimage.RootFS{Type: "layers"}
	if opts.Details {
		tagged, tagErr := reference.WithTag(
			reference.TrimNamed(ref), "latest")
		if tagErr == nil {
			img.Details = &dockerimage.Details{
				References: []reference.Named{tagged},
			}
		} else {
			img.Details = &dockerimage.Details{
				References: []reference.Named{ref},
			}
		}
	}
	return img, nil
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
