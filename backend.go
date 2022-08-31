package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/errdefs"
	"github.com/juju/utils/v3/ssh"
	"github.com/sirupsen/logrus"
	"gopkg.in/retry.v1"
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

var (
	retryStrategy = retry.LimitCount(10, retry.Exponential{
		Initial:  time.Second,
		Factor:   2.0,
		MaxDelay: 30 * time.Second,
	})
)

func (b *Backend) waitForCloudInit(ctx context.Context, info *runningInfo) error {
	host := info.Image.DefaultUser + "@" + info.IP

	opts := ssh.Options{}
	opts.SetIdentities(b.config.SSH.IdentityFile)
	opts.SetStrictHostKeyChecking(ssh.StrictHostChecksNo)

	attempt := retry.Start(retryStrategy, nil)
	for attempt.Next() {
		cmd := ssh.Command(host, []string{"/bin/bash", "-c", "hostname"}, &opts)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logrus.Errorf("%s: hostname failed: %s\n%s", info.Name, err.Error(), string(out))
			if !attempt.More() {
				return err
			}
			continue
		}
		break
	}

	cmd := ssh.Command(host, []string{"sudo", "cloud-init", "status", "--wait"}, &opts)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("%s: cloud-init failed: %s", info.Name, string(out))
		return err
	}
	return nil
}

type runningInfo struct {
	Name  string
	IP    string
	Image *ImageConfig
}

func (b *Backend) waitForRunningInfo(ctx context.Context, name string) (*runningInfo, error) {
	info := runningInfo{
		Name: name,
	}
	attempt := retry.Start(retryStrategy, nil)
	for attempt.Next() {
		res, err := b.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: []string{name},
		})
		if err != nil {
			if !attempt.More() {
				return nil, err
			} else {
				logrus.Warnf("%s: waiting for info: %s", name, err.Error())
				continue
			}
		}
		instance := res.Reservations[0].Instances[0]
		if instance.PublicIpAddress == nil {
			continue
		}
		if instance.State.Name != "running" {
			continue
		}
		info.IP = *instance.PublicIpAddress
		imageName := ""
		for _, v := range instance.Tags {
			if v.Key == nil {
				continue
			}
			if *v.Key == "image" {
				imageName = aws.ToString(v.Value)
				break
			}
		}
		if imageName == "" {
			return nil, fmt.Errorf("instance %s missing image tag", name)
		}
		image, ok := b.config.Images[imageName]
		if !ok {
			return nil, fmt.Errorf("image %s for instance %s missing", imageName, name)
		}
		info.Image = &image
		break
	}
	if info.IP == "" || info.Image == nil {
		return nil, errdefs.FromStatusCode(fmt.Errorf("instance %s not running", name), 409)
	}
	return &info, nil
}
