package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	containerpkg "github.com/docker/docker/container"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/archive"
	petname "github.com/dustinkirkland/golang-petname"
	"github.com/juju/cmd/v3"
	"github.com/juju/utils/v3"
	"github.com/juju/utils/v3/ssh"
	"github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
)

func (b *Backend) ContainerExecCreate(name string, config *types.ExecConfig) (string, error) {
	logrus.Infof("ContainerExecCreate %s %#v", name, config)
	if !strings.HasPrefix(name, "i-") {
		return "", errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	if config.Detach {
		return "", errdefs.InvalidParameter(fmt.Errorf("detach not supported"))
	}
	if len(config.Env) > 0 {
		return "", errdefs.InvalidParameter(fmt.Errorf("env not supported"))
	}
	if config.Privileged {
		return "", errdefs.InvalidParameter(fmt.Errorf("privileged not supported"))
	}
	if config.WorkingDir != "" {
		return "", errdefs.InvalidParameter(fmt.Errorf("working dir not supported"))
	}
	if len(config.Cmd) == 0 {
		return "", errdefs.InvalidParameter(fmt.Errorf("missing cmd param"))
	}

	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
	res, err := b.client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return "", err
	}
	if res.Reservations[0].Instances[0].State.Name != "running" {
		return "", errdefs.FromStatusCode(fmt.Errorf("instance %s is not running", name), 409)
	}

	bytes := [16]byte{}
	_, _ = rand.Read(bytes[:])
	id := hex.EncodeToString(bytes[:])
	e := Exec{
		ID:       id,
		Instance: name,
		Config:   *config,
	}
	b.execs[id] = e

	return id, nil
}

func (b *Backend) ContainerExecInspect(id string) (*backend.ExecInspect, error) {
	logrus.Infof("ContainerExecInspect %s", id)
	b.execsMutex.Lock()
	execConfig, ok := b.execs[id]
	b.execsMutex.Unlock()
	if !ok {
		return nil, errdefs.NotFound(fmt.Errorf("exec %s not found", id))
	}
	res := &backend.ExecInspect{
		ID:       id,
		ExitCode: execConfig.ExitCode,
		Running:  execConfig.Running,
		ProcessConfig: &backend.ExecProcessConfig{
			Entrypoint: execConfig.Config.Cmd[0],
			Arguments:  execConfig.Config.Cmd[1:],
			User:       execConfig.Config.User,
			Tty:        execConfig.Config.Tty,
		},
	}
	return res, nil
}

func (b *Backend) ContainerExecResize(name string, height, width int) error {
	logrus.Infof("ContainerExecResize %s %d %d", name, height, width)
	return errNotImplemented
}

func (b *Backend) ContainerExecStart(ctx context.Context, name string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (err error) {
	logrus.Infof("ContainerExecStart %s", name)

	b.execsMutex.Lock()
	execConfig, ok := b.execs[name]
	b.execsMutex.Unlock()
	if !ok {
		return errdefs.NotFound(fmt.Errorf("exec %s not found", name))
	}

	info, err := b.waitForRunningInfo(context.Background(), execConfig.Instance)
	if err != nil {
		return err
	}

	user := execConfig.Config.User
	if user == "" {
		// TODO: find image config and get username from there
		user = info.Image.DefaultUser
	}
	host := user + "@" + info.IP

	opts := ssh.Options{}
	opts.SetIdentities(b.config.SSH.IdentityFile)
	opts.SetStrictHostKeyChecking(ssh.StrictHostChecksNo)
	sshCmd := ssh.DefaultClient.Command(host, execConfig.Config.Cmd, &opts)
	if execConfig.Config.AttachStdin && stdin != nil {
		w, err := sshCmd.StdinPipe()
		if err != nil {
			return err
		}
		go func() {
			defer w.Close()
			io.Copy(w, stdin)
		}()
	}
	if execConfig.Config.AttachStdout && stdout != nil {
		r, err := sshCmd.StdoutPipe()
		if err != nil {
			return err
		}
		go func() {
			defer r.Close()
			io.Copy(stdout, r)
		}()
	}
	if execConfig.Config.AttachStderr && stderr != nil {
		r, err := sshCmd.StderrPipe()
		if err != nil {
			return err
		}
		go func() {
			defer r.Close()
			io.Copy(stderr, r)
		}()
	}
	err = sshCmd.Start()
	if err != nil {
		return err
	}

	b.execsMutex.Lock()
	execConfig = b.execs[name]
	execConfig.Running = true
	b.execs[name] = execConfig
	b.execsMutex.Unlock()

	logrus.Debugf("exec %s waiting", name)
	err = sshCmd.Wait()
	logrus.Debugf("exec %s exited with %v", name, err)
	exitCode := 0
	defer func() {
		b.execsMutex.Lock()
		execConfig = b.execs[name]
		execConfig.Running = false
		execConfig.ExitCode = &exitCode
		b.execs[name] = execConfig
		b.execsMutex.Unlock()
	}()
	if execErr, ok := err.(*exec.ExitError); ok {
		exitCode = execErr.ExitCode()
	} else if rcErr, ok := err.(*cmd.RcPassthroughError); ok {
		exitCode = rcErr.Code
	} else if goSSHerr, ok := err.(*cryptossh.ExitError); ok {
		exitCode = goSSHerr.ExitStatus()
	} else if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ExecExists(name string) (bool, error) {
	logrus.Infof("ExecExists %s", name)
	_, ok := b.execs[name]
	return ok, nil
}

func (b *Backend) ContainerArchivePath(name string, path string) (content io.ReadCloser, stat *types.ContainerPathStat, err error) {
	spew.Dump("ContainerArchivePath", name, path)
	return nil, nil, errNotImplemented
}

func (b *Backend) ContainerCopy(name string, res string) (io.ReadCloser, error) {
	spew.Dump("ContainerCopy", name, res)
	return nil, errNotImplemented
}

func (b *Backend) ContainerExport(name string, out io.Writer) error {
	spew.Dump("ContainerExport", name)
	return errNotImplemented
}

func (b *Backend) ContainerExtractToDir(name, path string, copyUIDGID, noOverwriteDirNonDir bool, content io.Reader) error {
	logrus.Infof("ContainerExtractToDir %s %s", name, path)
	if !strings.HasPrefix(name, "i-") {
		return errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	info, err := b.waitForRunningInfo(context.Background(), name)
	if err != nil {
		return err
	}

	// TODO: find image config and get username from there
	host := info.Image.DefaultUser + "@" + info.IP

	destPath := fmt.Sprintf("/tmp/ducker-%s", petname.Generate(3, "-"))

	logrus.Infof("%s: copying to %s:%s", name, host, destPath)

	opts := ssh.Options{}
	opts.SetIdentities(b.config.SSH.IdentityFile)
	opts.SetStrictHostKeyChecking(ssh.StrictHostChecksNo)
	err = ssh.CopyReader(host, destPath, content, &opts)
	if err != nil {
		return err
	}

	logrus.Infof("%s: extracting %s:%s to %s:%s", name, host, destPath, host, path)

	cmd := ssh.Command(host, []string{"sudo", "tar", "-xvf", destPath, "-C", path}, &opts)
	out, err := cmd.CombinedOutput()
	logrus.Debugln(string(out))
	if err != nil {
		return err
	}
	return nil
}

func (b *Backend) ContainerStatPath(name string, path string) (stat *types.ContainerPathStat, err error) {
	spew.Dump("ContainerStatPath", name, path)
	return nil, errNotImplemented
}

func (b *Backend) ContainerCreate(config types.ContainerCreateConfig) (container.ContainerCreateCreatedBody, error) {
	logrus.Infof("ContainerCreate %#v", config)
	if config.Name == "" {
		config.Name = petname.Generate(2, "-")
	}

	ref, err := reference.Parse(config.Config.Image)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return container.ContainerCreateCreatedBody{},
			errdefs.InvalidParameter(fmt.Errorf("%s does not name an image", config.Config.Image))
	}
	imageName := named.Name()
	image, ok := b.config.Images[imageName]
	if !ok {
		return container.ContainerCreateCreatedBody{}, errdefs.NotFound(fmt.Errorf("%s not found", imageName))
	}
	ami, err := image.ResolveAMI(context.Background(), b.client)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}

	vpcId := image.VPC
	if vpcId == "" {
		res, err := b.client.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{
			Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
		})
		if err != nil {
			return container.ContainerCreateCreatedBody{}, err
		}
		if len(res.Vpcs) != 1 {
			return container.ContainerCreateCreatedBody{}, errdefs.NotFound(fmt.Errorf("no default vpc"))
		}
		vpcId = *res.Vpcs[0].VpcId
	}
	subnets, err := b.client.DescribeSubnets(context.Background(), &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcId}}},
	})
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}
	if len(subnets.Subnets) == 0 {
		return container.ContainerCreateCreatedBody{}, errdefs.NotFound(fmt.Errorf("no subnets found"))
	}
	rand.Shuffle(len(subnets.Subnets), func(i, j int) {
		subnets.Subnets[i], subnets.Subnets[j] = subnets.Subnets[j], subnets.Subnets[i]
	})

	id := ""
	for _, subnet := range subnets.Subnets {
		subnetId := *subnet.SubnetId

		req := &ec2.RunInstancesInput{
			MaxCount:         aws.Int32(1),
			MinCount:         aws.Int32(1),
			ImageId:          aws.String(ami),
			InstanceType:     ec2types.InstanceType(image.InstanceType),
			KeyName:          aws.String(b.config.SSH.KeyPair),
			SecurityGroupIds: image.SecurityGroups,
			SubnetId:         aws.String(subnetId),
		}
		if image.IAMInstanceProfile != "" {
			req.IamInstanceProfile = &ec2types.IamInstanceProfileSpecification{
				Arn: aws.String(image.IAMInstanceProfile),
			}
		}
		if image.UserData != "" {
			req.UserData = aws.String(image.UserData)
		}

		tags := []ec2types.Tag{
			{Key: aws.String("Name"), Value: aws.String(config.Name)},
			{Key: aws.String("ducker"), Value: aws.String(b.config.Namespace)},
			{Key: aws.String("image"), Value: aws.String(imageName)},
		}
		for k, v := range config.Config.Labels {
			tags = append(tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}

		req.TagSpecifications = []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags:         tags,
		}}

		resp, err := b.client.RunInstances(context.Background(), req)
		if err != nil && (strings.Contains(err.Error(), "InsufficientInstanceCapacity") ||
			strings.Contains(err.Error(), "Unsupported")) {
			logrus.Errorf("retrying due to failure creating instance: %s", err.Error())
			continue
		} else if err != nil {
			return container.ContainerCreateCreatedBody{}, err
		}

		id = *resp.Instances[0].InstanceId
		break
	}
	if id == "" {
		return container.ContainerCreateCreatedBody{}, errdefs.Deadline(fmt.Errorf("failed to create container"))
	}

	logrus.Debugf("%s: waiting", id)
	info, err := b.waitForRunningInfo(context.Background(), id)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}

	logrus.Debugf("%s: waiting for cloud-init", id)
	err = b.waitForCloudInit(context.Background(), info)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}

	if info.Image.StartScript != "" {
		logrus.Debugf("%s: running start-script", id)
		host := info.Image.DefaultUser + "@" + info.IP
		opts := ssh.Options{}
		opts.SetIdentities(b.config.SSH.IdentityFile)
		opts.SetStrictHostKeyChecking(ssh.StrictHostChecksNo)
		cmd := ssh.Command(host, []string{"/bin/bash", "-c", utils.ShQuote(info.Image.StartScript)}, &opts)
		out, err := cmd.CombinedOutput()
		logrus.Debugf("%s: start-script output: %s", id, string(out))
		if err != nil {
			return container.ContainerCreateCreatedBody{}, err
		}
	}

	return container.ContainerCreateCreatedBody{
		ID: id,
	}, nil
}

func (b *Backend) ContainerKill(name string, sig uint64) error {
	spew.Dump("ContainerKill", name, sig)
	return errNotImplemented
}

func (b *Backend) ContainerPause(name string) error {
	spew.Dump("ContainerPause", name)
	return errNotImplemented
}

func (b *Backend) ContainerRename(oldName, newName string) error {
	spew.Dump("ContainerRename", oldName, newName)
	return errNotImplemented
}

func (b *Backend) ContainerResize(name string, height, width int) error {
	spew.Dump("ContainerResize", name, height, width)
	return errNotImplemented
}

func (b *Backend) ContainerRestart(name string, seconds *int) error {
	logrus.Infof("ContainerRestart %s", name)
	if !strings.HasPrefix(name, "i-") {
		return errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	_, err := b.client.RebootInstances(context.Background(), &ec2.RebootInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ContainerRm(name string, config *types.ContainerRmConfig) error {
	logrus.Infof("ContainerRm %s %#v", name, config)
	if !strings.HasPrefix(name, "i-") {
		return errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
	for k, v := range b.execs {
		if v.Instance == name {
			delete(b.execs, k)
		}
	}

	_, err := b.client.TerminateInstances(context.Background(), &ec2.TerminateInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ContainerStart(name string, hostConfig *container.HostConfig, checkpoint string, checkpointDir string) error {
	logrus.Infof("ContainerStart %s", name)
	if !strings.HasPrefix(name, "i-") {
		return errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	_, err := b.client.StartInstances(context.Background(), &ec2.StartInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ContainerStop(name string, seconds *int) error {
	logrus.Infof("ContainerStop %s", name)
	if !strings.HasPrefix(name, "i-") {
		return errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	_, err := b.client.StopInstances(context.Background(), &ec2.StopInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ContainerUnpause(name string) error {
	spew.Dump("ContainerUnpause", name)
	return errNotImplemented
}

func (b *Backend) ContainerUpdate(name string, hostConfig *container.HostConfig) (container.ContainerUpdateOKBody, error) {
	spew.Dump("ContainerUpdate", name, hostConfig)
	return container.ContainerUpdateOKBody{}, errNotImplemented
}

func (b *Backend) ContainerWait(ctx context.Context, name string, condition containerpkg.WaitCondition) (<-chan containerpkg.StateStatus, error) {
	spew.Dump("ContainerWait", name, condition)
	return nil, errNotImplemented
}

func (b *Backend) ContainerChanges(name string) ([]archive.Change, error) {
	spew.Dump("ContainerChanges", name)
	return nil, errNotImplemented
}

func (b *Backend) ContainerInspect(name string, size bool, version string) (interface{}, error) {
	logrus.Infof("ContainerInspect %s %s", name, version)

	if !strings.HasPrefix(name, "i-") {
		return nil, errdefs.InvalidParameter(fmt.Errorf("only ec2 instance id supported got %s", name))
	}

	res, err := b.client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{name},
	})
	if err != nil {
		return nil, err
	}
	instance := res.Reservations[0].Instances[0]

	c := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{},
	}
	c.ID = *instance.InstanceId
	c.Image = *instance.ImageId
	c.Created = instance.LaunchTime.String()
	c.State = &types.ContainerState{}
	c.Config = &container.Config{
		Labels: map[string]string{},
		Image:  *instance.ImageId,
	}

	for _, v := range instance.Tags {
		if *v.Key == "Name" {
			c.Name = *v.Value
			continue
		}
		c.Config.Labels[*v.Key] = *v.Value
	}
	switch instance.State.Name {
	case "pending":
		c.State.Status = "created"
	case "running":
		c.State.Status = "running"
		c.State.Running = true
		c.State.StartedAt = c.Created
	case "shutting-down":
		c.State.Status = "exited"
		c.State.FinishedAt = time.Now().String()
	case "stopping":
		c.State.Status = "exited"
		c.State.FinishedAt = time.Now().String()
	case "stopped":
		c.State.Status = "exited"
		c.State.FinishedAt = time.Now().String()
	case "terminated":
		c.State.Status = "removing"
		c.State.FinishedAt = time.Now().String()
	}

	return c, nil
}

func (b *Backend) ContainerLogs(ctx context.Context, name string, config *types.ContainerLogsOptions) (msgs <-chan *backend.LogMessage, tty bool, err error) {
	spew.Dump("ContainerLogs", name, config)
	return nil, false, errNotImplemented
}

func (b *Backend) ContainerStats(ctx context.Context, name string, config *backend.ContainerStatsConfig) error {
	spew.Dump("ContainerStats", name, config)
	return errNotImplemented
}

func (b *Backend) ContainerTop(name string, psArgs string) (*container.ContainerTopOKBody, error) {
	spew.Dump("ContainerTop", name, psArgs)
	return nil, errNotImplemented
}

func (b *Backend) Containers(config *types.ContainerListOptions) ([]*types.Container, error) {
	logrus.Infof("Containers %#v", config)

	if config.Size {
		logrus.Warnf("containers does not support size")
	}
	if config.Before != "" {
		logrus.Warnf("containers does not support before")
	}
	if config.Latest {
		logrus.Warnf("containers does not support latest")
	}
	if config.Limit > 0 {
		logrus.Warnf("containers does not support limit")
	}
	if config.Since != "" {
		logrus.Warnf("containers does not support since")
	}

	filters := []ec2types.Filter{{
		Name:   aws.String("tag:ducker"),
		Values: []string{b.config.Namespace},
	}}
	if config.All {
		filters = append(filters, ec2types.Filter{
			Name:   aws.String("instance-state-name"),
			Values: []string{"pending", "running"},
		})
	} else {
		filters = append(filters, ec2types.Filter{
			Name:   aws.String("instance-state-name"),
			Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"},
		})
	}
	for _, k := range config.Filters.Keys() {
		values := config.Filters.Get(k)
		switch k {
		case "name":
			filters = append(filters, ec2types.Filter{
				Name:   aws.String("tag:Name"),
				Values: values,
			})
		case "label":
			for _, v := range values {
				kv := strings.SplitN(v, "=", 2)
				if len(kv) != 2 {
					return nil, errdefs.InvalidParameter(fmt.Errorf("invalid label filter value %q", v))
				}
				key := kv[0]
				value := kv[1]
				filters = append(filters, ec2types.Filter{
					Name:   aws.String(fmt.Sprintf("tag:%s", key)),
					Values: []string{value},
				})
			}
		case "id":
			filters = append(filters, ec2types.Filter{
				Name:   aws.String("instance-id"),
				Values: values,
			})
		default:
			return nil, errdefs.NotImplemented(fmt.Errorf("unsupported filter %s", k))
		}
	}

	req := &ec2.DescribeInstancesInput{
		Filters: filters,
	}
	instances := []ec2types.Instance{}
	for {
		resp, err := b.client.DescribeInstances(context.Background(), req)
		if err != nil {
			return nil, err
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

	containers := []*types.Container{}
	for _, instance := range instances {
		container := types.Container{
			ID:     *instance.InstanceId,
			Labels: make(map[string]string),
		}
		for _, v := range instance.Tags {
			if *v.Key == "Name" {
				container.Names = append(container.Names, *v.Value)
				continue
			}
			container.Labels[*v.Key] = *v.Value
		}
		container.Image = *instance.ImageId
		container.ImageID = *instance.ImageId
		switch instance.State.Name {
		case "pending":
			container.State = "created"
		case "running":
			container.State = "running"
		case "shutting-down":
			container.State = "exited"
		case "stopping":
			container.State = "exited"
		case "stopped":
			container.State = "exited"
		case "terminated":
			container.State = "removing"
		default:
			container.State = "unknown"
		}
		container.Status = string(instance.State.Name)
		container.Created = instance.LaunchTime.Unix()
		containers = append(containers, &container)
	}

	return containers, nil
}

func (b *Backend) ContainerAttach(name string, c *backend.ContainerAttachConfig) error {
	spew.Dump("ContainerAttach", name, c)
	return errNotImplemented
}

func (b *Backend) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (*types.ContainersPruneReport, error) {
	spew.Dump("ContainersPrune", pruneFilters)
	return &types.ContainersPruneReport{}, nil
}

func (b *Backend) CreateImageFromContainer(name string, config *backend.CreateImageConfig) (imageID string, err error) {
	spew.Dump("CreateImageFromContainer", name, config)
	return "", errNotImplemented
}
