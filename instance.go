package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/errdefs"
	petname "github.com/dustinkirkland/golang-petname"
	"github.com/juju/errors"
	"github.com/juju/worker/v3"
	"github.com/kballard/go-shellquote"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/tomb.v2"
)

const (
	InstanceNotFound errors.ConstError = "instance not found"

	cloudInitScript = `#cloud-config
# vim: syntax=yaml
write_files:
- content: %s
  path: /etc/nonce.txt
`
	noncePath = "/etc/nonce.txt"
)

type Instance interface {
	worker.Worker

	ID() string
	Name() string
	RunningInfo(ctx context.Context) (*RunningInfo, error)
	ContainerInfo() (types.Container, types.ContainerState)

	Start() error
	Stop() error
	Restart() error
}

type RunningInfo struct {
	Name    string
	IP      string
	HostKey ssh.PublicKey
	Image   *ImageConfig
}

type InstanceState int

const (
	Creating InstanceState = iota
	CloudInit
	Stopped
	Starting
	Running
	Stopping
	Restarting
	Terminating
	Terminated
)

type awsInstance struct {
	b    *Backend
	tomb tomb.Tomb

	state       InstanceState
	changeState chan InstanceState
	runFunc     chan func() bool

	name string
	id   string

	ip      string
	nonce   string
	hostKey ssh.PublicKey

	created  time.Time
	started  time.Time
	finished time.Time
	image    ImageConfig

	runStartScript bool

	containerInfoMutex sync.RWMutex
	containerInfo      types.Container
	containerState     types.ContainerState
}

func CreateInstance(ctx context.Context, b *Backend, config types.ContainerCreateConfig) (Instance, error) {
	n := &awsInstance{
		b:           b,
		changeState: make(chan InstanceState),
		runFunc:     make(chan func() bool),
	}
	err := n.create(ctx, config)
	if err != nil {
		return nil, err
	}
	n.tomb.Go(n.loop)
	return n, nil
}

func (n *awsInstance) Kill() {
	n.tomb.Kill(nil)
}

func (n *awsInstance) Wait() error {
	return n.tomb.Wait()
}

func (n *awsInstance) ID() string {
	return n.id
}

func (n *awsInstance) Name() string {
	return n.name
}

func (n *awsInstance) RunningInfo(ctx context.Context) (*RunningInfo, error) {
	done := make(chan struct{})
	var runningInfo *RunningInfo
	f := func() bool {
		switch n.state {
		case Creating, CloudInit, Restarting, Starting:
			return true
		case Running:
			runningInfo = &RunningInfo{
				Name:    n.id,
				IP:      n.ip,
				Image:   &n.image,
				HostKey: n.hostKey,
			}
		}
		close(done)
		return false
	}
	select {
	case n.runFunc <- f:
	case <-n.tomb.Dying():
		return nil, fmt.Errorf("instance terminating")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-done:
	case <-n.tomb.Dying():
		return nil, fmt.Errorf("instance terminating")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if runningInfo == nil {
		return nil, fmt.Errorf("instance not running")
	}
	return runningInfo, nil
}

func (n *awsInstance) ContainerInfo() (types.Container, types.ContainerState) {
	n.containerInfoMutex.RLock()
	defer n.containerInfoMutex.RUnlock()
	return n.containerInfo, n.containerState
}

func (n *awsInstance) ctx() context.Context {
	return n.tomb.Context(context.Background())
}

func (n *awsInstance) loop() error {
	rerun := []func() bool(nil)
	for {
		select {
		case <-n.tomb.Dying():
			err := n.enterTerminating()
			if err != nil {
				return err
			}
		case newState := <-n.changeState:
			switch newState {
			case Stopping:
				err := n.enterStopping()
				if err != nil {
					logrus.Errorf("%s: cannot stop: %v", n.id, err)
				}
			case Starting:
				err := n.enterStarting()
				if err != nil {
					logrus.Errorf("%s: cannot start: %v", n.id, err)
				}
			case Restarting:
				err := n.enterRestarting()
				if err != nil {
					logrus.Errorf("%s: cannot restart: %v", n.id, err)
				}
			}
		case f := <-n.runFunc:
			if f() {
				rerun = append(rerun, f)
			}
		case <-time.After(5 * time.Second):
		}

		switch n.state {
		case Creating:
			err := n.creating()
			if err != nil {
				logrus.Errorf("%s: creating: %v", n.id, err)
			}
		case CloudInit:
			err := n.cloudInit()
			if err != nil {
				logrus.Errorf("%s: cloud-init: %v", n.id, err)
			}
		case Stopped:
			err := n.stopped()
			if err != nil {
				logrus.Errorf("%s: stopped: %v", n.id, err)
			}
		case Starting:
			err := n.starting()
			if err != nil {
				logrus.Errorf("%s: starting: %v", n.id, err)
			}
		case Running:
			err := n.running()
			if err != nil {
				logrus.Errorf("%s: running: %v", n.id, err)
			}
		case Stopping:
			err := n.stopping()
			if err != nil {
				logrus.Errorf("%s: stopping: %v", n.id, err)
			}
		case Restarting:
			err := n.restarting()
			if err != nil {
				logrus.Errorf("%s: restarting: %v", n.id, err)
			}
		case Terminating:
			err := n.terminating()
			if err != nil {
				logrus.Errorf("%s: terminating: %v", n.id, err)
			}
		case Terminated:
			err := n.terminated()
			if err != nil {
				logrus.Errorf("%s: terminated: %v", n.id, err)
			}
			return nil
		}

		if rerun != nil {
			nextRerun := []func() bool(nil)
			for _, f := range rerun {
				if f() {
					nextRerun = append(nextRerun, f)
				}
			}
			rerun = nextRerun
		}

		n.updateContainerInfo()
	}
}

func (n *awsInstance) enterCreating() error {
	n.state = Creating
	logrus.Infof("%s: creating", n.id)
	return nil
}

func (n *awsInstance) creating() error {
	s, err := n.status(n.ctx())
	if err != nil {
		return err
	}
	if s.State == nil {
		return fmt.Errorf("missing state")
	}
	if s.State.Name == "stopped" {
		return n.enterTerminating()
	}
	if s.State.Name == "terminated" {
		return n.enterTerminated()
	}
	if s.State.Name != "running" {
		return fmt.Errorf("not yet running: %s", s.State.Name)
	}
	if s.PublicIpAddress == nil {
		return fmt.Errorf("no public address yet")
	}
	n.ip = *s.PublicIpAddress
	return n.enterCloudInit()
}

func (n *awsInstance) enterCloudInit() error {
	n.state = CloudInit
	logrus.Infof("%s: cloud-init", n.id)
	return nil
}

func (n *awsInstance) cloudInit() error {
	var recordedHostKey ssh.PublicKey
	conn, err := ssh.Dial("tcp", net.JoinHostPort(n.ip, "22"), &ssh.ClientConfig{
		User: n.image.DefaultUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(n.b.signers...),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			recordedHostKey = key
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("cannot open connection: %w", err)
	}
	defer conn.Close()

	logrus.Infof("%s: confirming host key...", n.id)
	sess, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open session: %w", err)
	}
	out, err := sess.CombinedOutput(fmt.Sprintf("cat %s", noncePath))
	if err != nil {
		return fmt.Errorf("nonce check failed: %w\n%s", err, string(out))
	}
	maybeNonce := strings.TrimSpace(string(out))
	if !strings.Contains(maybeNonce, n.nonce) {
		return fmt.Errorf("cannot verify instance nonce: wanted %s got %s", n.nonce, maybeNonce)
	}
	logrus.Infof("%s: confirmed host key %s via cloud-init nonce", n.id, ssh.FingerprintSHA256(recordedHostKey))
	n.hostKey = recordedHostKey

	logrus.Infof("%s: waiting for cloud init...", n.id)
	sess, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open session: %w", err)
	}
	out, err = sess.CombinedOutput("sudo cloud-init status --wait")
	if err != nil {
		return fmt.Errorf("cloud-init failed: %w\n%s", err, string(out))
	}

	if !n.runStartScript && n.image.StartScript != "" {
		logrus.Infof("%s: running start-script...", n.id)
		sess, err = conn.NewSession()
		if err != nil {
			return fmt.Errorf("cannot open session: %w", err)
		}
		out, err := sess.CombinedOutput(fmt.Sprintf("/bin/bash -c %s", shellquote.Join(n.image.StartScript)))
		logrus.Debugf("%s: start-script output: %s", n.id, string(out))
		if err != nil {
			return fmt.Errorf("start-script failed: %w", err)
		}
		n.runStartScript = true
	}

	return n.enterRunning()
}

func (n *awsInstance) enterStopped() error {
	n.state = Stopped
	n.finished = time.Now().UTC()
	logrus.Infof("%s: stopped", n.id)
	return nil
}

func (n *awsInstance) stopped() error {
	return nil
}

func (n *awsInstance) enterStarting() error {
	switch n.state {
	case Starting, Running, Restarting, Terminating, Terminated:
		return nil
	}
	_, err := n.b.client.StartInstances(n.tomb.Context(context.Background()), &ec2.StartInstancesInput{
		InstanceIds: []string{n.id},
	})
	if err != nil {
		return err
	}
	n.state = Starting
	logrus.Infof("%s: starting", n.id)
	return nil
}

func (n *awsInstance) starting() error {
	s, err := n.status(n.ctx())
	if err != nil {
		return err
	}
	if s.State.Name == "terminated" {
		return n.enterTerminated()
	}
	if s.State.Name == "running" {
		return n.enterCreating()
	}
	return nil
}

func (n *awsInstance) enterRunning() error {
	n.state = Running
	n.started = time.Now().UTC()
	n.finished = time.Time{}
	logrus.Infof("%s: running", n.id)
	return nil
}

func (n *awsInstance) running() error {
	return nil
}

func (n *awsInstance) enterStopping() error {
	switch n.state {
	case Stopped, Stopping:
		return nil
	}
	_, err := n.b.client.StopInstances(n.tomb.Context(context.Background()), &ec2.StopInstancesInput{
		InstanceIds: []string{n.id},
	})
	if err != nil {
		return err
	}
	n.state = Stopping
	logrus.Infof("%s: stopping", n.id)
	return nil
}

func (n *awsInstance) stopping() error {
	s, err := n.status(n.ctx())
	if err != nil {
		return err
	}
	if s.State.Name == "terminated" {
		return n.enterTerminated()
	}
	if s.State.Name == "stopped" {
		return n.enterStopped()
	}
	return nil
}

func (n *awsInstance) enterRestarting() error {
	switch n.state {
	case Starting, Restarting, Terminating, Terminated:
		return nil
	}
	_, err := n.b.client.RebootInstances(n.tomb.Context(context.Background()), &ec2.RebootInstancesInput{
		InstanceIds: []string{n.id},
	})
	if err != nil {
		return err
	}
	n.state = Restarting
	return nil
}

func (n *awsInstance) restarting() error {
	s, err := n.status(n.ctx())
	if err != nil {
		return err
	}
	if s.State.Name == "terminated" {
		return n.enterTerminated()
	}
	if s.State.Name == "running" {
		return n.enterCreating()
	}
	return nil
}

func (n *awsInstance) enterTerminating() error {
	switch n.state {
	case Terminating, Terminated:
		time.Sleep(time.Second)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := n.b.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{n.id},
	})
	if err != nil {
		logrus.Errorf("failed to terminate instance %s: %v", n.id, err)
	}
	n.state = Terminating
	n.finished = time.Now().UTC()
	logrus.Infof("%s: terminating", n.id)
	return nil
}

func (n *awsInstance) terminating() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := n.status(ctx)
	if errors.Is(err, InstanceNotFound) {
		return n.enterTerminated()
	} else if err != nil {
		return err
	}
	if s.State.Name == "terminated" {
		return n.enterTerminated()
	}
	return nil
}

func (n *awsInstance) enterTerminated() error {
	n.state = Terminated
	n.finished = time.Now().UTC()
	logrus.Infof("%s: terminated", n.id)
	return nil
}

func (n *awsInstance) terminated() error {
	return nil
}

func (n *awsInstance) create(ctx context.Context, config types.ContainerCreateConfig) error {
	ref, err := reference.Parse(config.Config.Image)
	if err != nil {
		return err
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return errdefs.InvalidParameter(fmt.Errorf("%s does not name an image", config.Config.Image))
	}
	imageName := named.Name()
	image, ok := n.b.config.Images[imageName]
	if !ok {
		return errdefs.NotFound(fmt.Errorf("%s not found", imageName))
	}
	image.AMI, err = image.ResolveAMI(ctx, n.b.client)
	if err != nil {
		return err
	}

	vpcId := image.VPC
	if vpcId == "" {
		res, err := n.b.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
		})
		if err != nil {
			return err
		}
		if len(res.Vpcs) != 1 {
			return errdefs.NotFound(fmt.Errorf("no default vpc"))
		}
		vpcId = *res.Vpcs[0].VpcId
	}
	subnets, err := n.b.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcId}}},
	})
	if err != nil {
		return err
	}
	if len(subnets.Subnets) == 0 {
		return errdefs.NotFound(fmt.Errorf("no subnets found"))
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
			ImageId:          aws.String(image.AMI),
			InstanceType:     ec2types.InstanceType(image.InstanceType),
			KeyName:          aws.String(n.b.config.SSH.KeyPair),
			SecurityGroupIds: image.SecurityGroups,
			SubnetId:         aws.String(subnetId),
		}
		if image.IAMInstanceProfile != "" {
			req.IamInstanceProfile = &ec2types.IamInstanceProfileSpecification{
				Arn: aws.String(image.IAMInstanceProfile),
			}
		}

		n.nonce = petname.Generate(5, "-")
		req.UserData = aws.String(base64.StdEncoding.EncodeToString(
			[]byte(fmt.Sprintf(cloudInitScript, n.nonce)),
		))

		tags := []ec2types.Tag{
			{Key: aws.String("Name"), Value: aws.String(config.Name)},
			{Key: aws.String("ducker"), Value: aws.String(n.b.config.Namespace)},
			{Key: aws.String("image"), Value: aws.String(imageName)},
		}
		for k, v := range config.Config.Labels {
			tags = append(tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}

		req.TagSpecifications = []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags:         tags,
		}}

		resp, err := n.b.client.RunInstances(ctx, req)
		if err != nil && (strings.Contains(err.Error(), "InsufficientInstanceCapacity") ||
			strings.Contains(err.Error(), "Unsupported")) {
			logrus.Errorf("retrying due to failure creating instance: %s", err.Error())
			continue
		} else if err != nil {
			return err
		}

		id = *resp.Instances[0].InstanceId
		break
	}
	if id == "" {
		return errdefs.Deadline(fmt.Errorf("failed to create container"))
	}

	n.id = id
	n.name = config.Name
	n.image = image
	n.created = time.Now().UTC()
	n.updateContainerInfo()
	return n.enterCreating()
}

func (n *awsInstance) updateContainerInfo() {
	n.containerInfoMutex.Lock()
	defer n.containerInfoMutex.Unlock()

	n.containerInfo = types.Container{
		ID:      n.id,
		Names:   []string{"/" + n.name},
		Image:   n.image.Name,
		ImageID: n.image.AMI,
		Created: n.created.Unix(),
		Labels:  n.image.Tags,
	}
	n.containerState = types.ContainerState{}
	if !n.started.IsZero() {
		n.containerState.StartedAt = n.started.String()
	}
	if !n.finished.IsZero() {
		n.containerState.FinishedAt = n.finished.String()
	}

	switch n.state {
	case Creating, CloudInit:
		n.containerInfo.State = "created"
	case Starting, Stopping, Restarting, Running:
		n.containerInfo.State = "running"
	case Stopped:
		n.containerInfo.State = "exited"
	case Terminating:
		n.containerInfo.State = "removing"
	default:
		n.containerInfo.State = "unknown"
	}
	switch n.state {
	case Creating:
		n.containerInfo.Status = "creating"
	case CloudInit:
		n.containerInfo.Status = "cloud-init"
	case Stopped:
		n.containerInfo.Status = "stopped"
	case Starting:
		n.containerInfo.Status = "starting"
	case Running:
		n.containerInfo.Status = "running"
	case Stopping:
		n.containerInfo.Status = "stopping"
	case Restarting:
		n.containerInfo.Status = "restarting"
	case Terminating:
		n.containerInfo.Status = "terminating"
	case Terminated:
		n.containerInfo.Status = "terminated"
	default:
		n.containerInfo.Status = "unknown"
	}

	switch n.state {
	case Creating, CloudInit, Starting, Running, Stopping:
		n.containerState.Running = true
	case Restarting:
		n.containerState.Restarting = true
	case Stopped, Terminating, Terminated:
		n.containerState.Dead = true
	}
	switch n.state {
	case Creating:
		n.containerState.Status = "running"
	case CloudInit:
		n.containerState.Status = "running"
	case Stopped:
		n.containerState.Status = "exited"
	case Starting:
		n.containerState.Status = "running"
	case Running:
		n.containerState.Status = "running"
	case Stopping:
		n.containerState.Status = "running"
	case Restarting:
		n.containerState.Status = "restarting"
	case Terminating:
		n.containerState.Status = "removing"
	case Terminated:
		n.containerState.Status = "dead"
	default:
		n.containerState.Status = "unknown"
	}
}

func (n *awsInstance) Start() error {
	select {
	case <-n.tomb.Dying():
		return fmt.Errorf("instance terminating")
	case n.changeState <- Starting:
		return nil
	}
}

func (n *awsInstance) Stop() error {
	select {
	case <-n.tomb.Dying():
		return fmt.Errorf("instance terminating")
	case n.changeState <- Stopping:
		return nil
	}
}

func (n *awsInstance) Restart() error {
	select {
	case <-n.tomb.Dying():
		return fmt.Errorf("instance terminating")
	case n.changeState <- Restarting:
		return nil
	}
}

func (n *awsInstance) status(ctx context.Context) (ec2types.Instance, error) {
	res, err := n.b.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{n.id},
	})
	if err != nil {
		return ec2types.Instance{}, err
	}
	if len(res.Reservations) == 0 {
		return ec2types.Instance{}, InstanceNotFound
	}
	if len(res.Reservations[0].Instances) == 0 {
		return ec2types.Instance{}, InstanceNotFound
	}
	return res.Reservations[0].Instances[0], nil
}
