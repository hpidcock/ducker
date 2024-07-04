package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/errdefs"
	"github.com/juju/errors"
	"github.com/juju/worker/v3"
	"github.com/sirupsen/logrus"
)

// createContainer
// startContainer
// listContainer
// removeContainer
// stopContainer
// inspectContainer
// runContainer
// execCreate
// copyArchiveToContainer
// logContainer

// version

// listImages
// pullImage
// inspectImage
// commit?
// tagImage?
// pushImage?
// removeImage?

type Backend struct {
	client *ec2.Client
	config *Config

	execsMutex sync.Mutex
	execs      map[string]Exec

	namesMutex sync.RWMutex
	names      map[string]string

	runner *worker.Runner
}

type Exec struct {
	ID       string
	Instance string
	Config   types.ExecConfig
	Running  bool
	ExitCode *int
}

var (
	errNotImplemented = errdefs.NotImplemented(fmt.Errorf("not implemented"))
)

func (b *Backend) findInstance(ctx context.Context, nameOrID string) (Instance, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resolved := nameOrID
	if !strings.HasPrefix(nameOrID, "i-") {
		b.namesMutex.RLock()
		if id, ok := b.names[nameOrID]; ok && len(id) > 0 {
			resolved = id
		} else {
			matching := 0
			matched := ""
			for k, v := range b.names {
				if strings.HasPrefix(k, nameOrID) {
					matched = v
					matching++
				}
			}
			if matching == 1 {
				resolved = matched
			}
		}
		b.namesMutex.RUnlock()
	}
	if !strings.HasPrefix(resolved, "i-") {
		return nil, errdefs.NotFound(fmt.Errorf("container %q not found", nameOrID))
	}

	candidates := []string(nil)
	for _, id := range b.runner.WorkerNames() {
		if strings.HasPrefix(id, resolved) {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) != 1 {
		// either none found or ambiguous
		return nil, errdefs.NotFound(fmt.Errorf("container %q not found", nameOrID))
	}
	resolved = candidates[0]

	worker, err := b.runner.Worker(resolved, ctx.Done())
	if errors.Is(err, errors.NotFound) {
		return nil, errdefs.NotFound(fmt.Errorf("container %q not found", nameOrID))
	} else if err != nil {
		return nil, err
	}

	return worker.(Instance), nil
}

func cleanupExisting(ctx context.Context, cfg *Config, client *ec2.Client) error {
	filters := []ec2types.Filter{{
		Name:   aws.String("tag:ducker"),
		Values: []string{cfg.Namespace},
	}, {
		Name:   aws.String("instance-state-name"),
		Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"},
	}}

	req := &ec2.DescribeInstancesInput{
		Filters: filters,
	}
	instances := []ec2types.Instance{}
	for {
		resp, err := client.DescribeInstances(ctx, req)
		if err != nil {
			return err
		}
		for _, v := range resp.Reservations {
			instances = append(instances, v.Instances...)
		}
		if resp.NextToken != nil {
			req.NextToken = resp.NextToken
			continue
		}
		break
	}

	instanceIDs := []string{}
	for _, instance := range instances {
		if instance.InstanceId != nil {
			logrus.Infof("removing stale instance %s", *instance.InstanceId)
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}

		if len(instanceIDs) == 8 {
			_, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
				InstanceIds: instanceIDs,
			})
			if err != nil {
				return err
			}
			instanceIDs = nil
		}
	}
	if len(instanceIDs) > 0 {
		_, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: instanceIDs,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// Copied mostly from go src. Licensed under the go license.
func fileModeFromUnixMode(mode uint32) os.FileMode {
	fileMode := os.FileMode(mode & 0777)
	switch mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		fileMode |= os.ModeDevice
	case syscall.S_IFCHR:
		fileMode |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		fileMode |= os.ModeDir
	case syscall.S_IFIFO:
		fileMode |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		fileMode |= os.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		fileMode |= os.ModeSocket
	}
	if mode&syscall.S_ISGID != 0 {
		fileMode |= os.ModeSetgid
	}
	if mode&syscall.S_ISUID != 0 {
		fileMode |= os.ModeSetuid
	}
	if mode&syscall.S_ISVTX != 0 {
		fileMode |= os.ModeSticky
	}
	return fileMode
}
