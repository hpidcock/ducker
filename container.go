package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	containerpkg "github.com/docker/docker/container"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/archive"
	petname "github.com/dustinkirkland/golang-petname"
	"github.com/juju/errors"
	"github.com/juju/worker/v3"
	"github.com/kballard/go-shellquote"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

func (b *Backend) ContainerExecCreate(name string, config *types.ExecConfig) (string, error) {
	logrus.Infof("ContainerExecCreate %s %#v", name, config)
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

	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return "", err
	}

	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()

	bytes := [16]byte{}
	_, _ = rand.Read(bytes[:])
	id := hex.EncodeToString(bytes[:])
	e := Exec{
		ID:       id,
		Instance: instance.ID(),
		Config:   *config,
	}
	b.execs[id] = e

	return id, nil
}

func (b *Backend) ContainerExecInspect(id string) (*backend.ExecInspect, error) {
	logrus.Infof("ContainerExecInspect %s", id)
	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
	execConfig, ok := b.execs[id]
	if !ok {
		return nil, errdefs.NotFound(fmt.Errorf("exec %s not found", id))
	}
	res := &backend.ExecInspect{
		ID:          id,
		ContainerID: execConfig.Instance,
		ExitCode:    execConfig.ExitCode,
		Running:     execConfig.Running,
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

	instance, err := b.findInstance(ctx, execConfig.Instance)
	if err != nil {
		return err
	}

	info, err := instance.RunningInfo(ctx)
	if err != nil {
		return err
	}

	user := execConfig.Config.User
	if user == "" {
		// TODO: find image config and get username from there
		user = info.Image.DefaultUser
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(info.IP, "22"), &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(b.signers...),
		},
		HostKeyCallback: ssh.FixedHostKey(info.HostKey),
	})
	if err != nil {
		return fmt.Errorf("cannot open connection: %w", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open session: %w", err)
	}

	if execConfig.Config.AttachStdin && stdin != nil {
		sess.Stdin = stdin
	}
	if execConfig.Config.AttachStdout && stdout != nil {
		sess.Stdout = stdout
	}
	if execConfig.Config.AttachStderr && stderr != nil {
		sess.Stderr = stderr
	}
	err = sess.Start(shellquote.Join(execConfig.Config.Cmd...))
	if err != nil {
		return err
	}

	b.execsMutex.Lock()
	if updateExecConfig, ok := b.execs[name]; ok {
		updateExecConfig.Running = true
		b.execs[name] = updateExecConfig
	}
	b.execsMutex.Unlock()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			logrus.Infof("canceling exec %s", execConfig.ID)
			err := sess.Signal(ssh.SIGINT)
			if err != nil {
				logrus.Infof("canceling exec %s: %v", execConfig.ID, err)
			}
		case <-done:
			logrus.Infof("exiting exec %s", execConfig.ID)
		}
	}()

	logrus.Debugf("exec %s waiting", name)
	err = sess.Wait()
	logrus.Debugf("exec %s exited with %v", name, err)
	exitCode := 0
	defer func() {
		b.execsMutex.Lock()
		defer b.execsMutex.Unlock()
		if updateExecConfig, ok := b.execs[name]; ok {
			updateExecConfig.Running = false
			updateExecConfig.ExitCode = &exitCode
			b.execs[name] = updateExecConfig
		}
	}()
	if sshErr, ok := err.(*ssh.ExitError); ok {
		exitCode = sshErr.ExitStatus()
	} else if err != nil {
		return err
	}

	return nil
}

func (b *Backend) ExecExists(name string) (bool, error) {
	logrus.Infof("ExecExists %s", name)
	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
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

	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	info, err := instance.RunningInfo(ctx)
	if err != nil {
		return err
	}

	// TODO: find image config and get username from there
	host := info.Image.DefaultUser + "@" + info.IP

	destPath := fmt.Sprintf("/tmp/ducker-%s", petname.Generate(3, "-"))

	logrus.Infof("%s: copying to %s:%s", name, host, destPath)

	conn, err := ssh.Dial("tcp", net.JoinHostPort(info.IP, "22"), &ssh.ClientConfig{
		User: info.Image.DefaultUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(b.signers...),
		},
		HostKeyCallback: ssh.FixedHostKey(info.HostKey),
	})
	if err != nil {
		return fmt.Errorf("cannot open connection: %w", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open session: %w", err)
	}
	sess.Stdin = content
	combined := &bytes.Buffer{}
	sess.Stderr = combined
	sess.Stdout = combined
	err = sess.Run(fmt.Sprintf("cat - > %s", destPath))
	if err != nil {
		return fmt.Errorf("cannot write file %s: %w\n%s", destPath, err, combined.String())
	}

	logrus.Infof("%s: extracting %s:%s to %s:%s", name, host, destPath, host, path)
	sess, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open session: %w", err)
	}
	out, err := sess.CombinedOutput(fmt.Sprintf(
		"sudo tar -xvf %s -C %s", destPath, shellquote.Join(path)))
	logrus.Debugln(string(out))
	if err != nil {
		return err
	}
	return nil
}

func (b *Backend) ContainerStatPath(name string, path string) (*types.ContainerPathStat, error) {
	logrus.Infof("ContainerStatPath %s %s", name, path)
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return nil, err
	}

	ri, err := instance.RunningInfo(context.Background())
	if err != nil {
		return nil, err
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(ri.IP, "22"), &ssh.ClientConfig{
		User: ri.Image.DefaultUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(b.signers...),
		},
		HostKeyCallback: ssh.FixedHostKey(ri.HostKey),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot open connection: %w", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("cannot open session: %w", err)
	}

	out, err := sess.CombinedOutput(fmt.Sprintf("stat -c %s", shellquote.Join("name: %n\nmode: %f\nsize: %s\nmod: %Y\ntype: %F\n", path)))
	logrus.Debugln(string(out))
	if err != nil {
		return nil, err
	}

	var info struct {
		Name    string `yaml:"name"`
		Size    int64  `yaml:"size"`
		Mode    string `yaml:"mode"`
		Mod     int64  `yaml:"mod"`
		EntType string `yaml:"type"`
	}
	err = yaml.Unmarshal(out, &info)
	if err != nil {
		return nil, err
	}
	mode, err := strconv.ParseUint(info.Mode, 16, 32)
	if err != nil {
		return nil, err
	}
	stat := types.ContainerPathStat{
		Name:       info.Name,
		Size:       info.Size,
		Mode:       fileModeFromUnixMode(uint32(mode)),
		Mtime:      time.Unix(info.Mod, 0),
		LinkTarget: "",
	}
	return &stat, nil
}

func (b *Backend) ContainerCreate(config types.ContainerCreateConfig) (container.ContainerCreateCreatedBody, error) {
	logrus.Infof("ContainerCreate %#v", config)
	if config.Name == "" {
		config.Name = petname.Generate(2, "-")
	}
	b.namesMutex.Lock()
	_, ok := b.names[config.Name]
	if ok {
		b.namesMutex.Unlock()
		return container.ContainerCreateCreatedBody{}, errdefs.Conflict(fmt.Errorf("container %s already exists", config.Name))
	} else {
		b.names[config.Name] = "reserved"
		b.namesMutex.Unlock()
		defer func() {
			b.namesMutex.Lock()
			defer b.namesMutex.Unlock()
			if id, ok := b.names[config.Name]; ok && id == "reserved" {
				delete(b.names, config.Name)
			}
		}()
	}

	instance, err := CreateInstance(context.Background(), b, config)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}
	id := instance.ID()
	err = b.runner.StartWorker(id, func() (worker.Worker, error) {
		return instance, nil
	})
	if err != nil {
		instance.Kill()
		return container.ContainerCreateCreatedBody{}, err
	}

	b.namesMutex.Lock()
	b.names[config.Name] = id
	b.namesMutex.Unlock()
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
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return err
	}

	err = instance.Restart()
	if err != nil {
		return err
	}
	return nil
}

func (b *Backend) ContainerRm(name string, config *types.ContainerRmConfig) error {
	logrus.Infof("ContainerRm %s %#v", name, config)
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return err
	}
	id := instance.ID()

	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
	for k, v := range b.execs {
		if v.Instance == id {
			delete(b.execs, k)
		}
	}

	err = b.runner.StopWorker(id)
	if errors.Is(err, worker.ErrDead) {
	} else if err != nil {
		return err
	}

	b.namesMutex.Lock()
	defer b.namesMutex.Unlock()
	delete(b.names, instance.Name())
	return nil
}

func (b *Backend) ContainerStart(name string, hostConfig *container.HostConfig, checkpoint string, checkpointDir string) error {
	logrus.Infof("ContainerStart %s", name)
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return err
	}

	err = instance.Start()
	if err != nil {
		return err
	}
	return nil
}

func (b *Backend) ContainerStop(name string, seconds *int) error {
	logrus.Infof("ContainerStop %s", name)
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return err
	}

	err = instance.Stop()
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
	instance, err := b.findInstance(context.Background(), name)
	if err != nil {
		return nil, err
	}
	id := instance.ID()

	info, state := instance.ContainerInfo()
	c := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			Created: time.Unix(info.Created, 0).String(),
			ID:      info.ID,
			Image:   info.ImageID,
			Name:    info.Names[0],
			State:   &state,
		},
		Config: &container.Config{
			Image:  info.Image,
			Labels: info.Labels,
		},
	}

	b.execsMutex.Lock()
	defer b.execsMutex.Unlock()
	for k, v := range b.execs {
		if v.Instance == id {
			c.ExecIDs = append(c.ExecIDs, k)
		}
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

	closedChan := make(chan struct{})
	close(closedChan)

	// containers cannot be nil, must be at least an empty list
	// for jenkins docker plugin.
	containers := []*types.Container{}

	workers := b.runner.WorkerNames()
	for _, id := range workers {
		worker, err := b.runner.Worker(id, closedChan)
		if err != nil {
			continue
		}
		instance := worker.(Instance)
		info, _ := instance.ContainerInfo()
		containers = append(containers, &info)
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
