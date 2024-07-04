package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/docker/docker/api/server"
	"github.com/docker/docker/api/server/router/container"
	"github.com/docker/docker/api/server/router/image"
	"github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/daemon/listeners"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/runconfig"
	"github.com/juju/clock"
	"github.com/juju/worker/v3"
	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	if len(os.Args) != 2 {
		logrus.Errorf("ducker [config.yaml]")
		os.Exit(1)
		return
	}

	cfg, err := ReadConfig(os.Args[1])
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
		return
	}
	if cfg.Namespace == "" {
		logrus.Errorf("namespace not provided")
		os.Exit(1)
		return
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9933"
	}

	err = run(cfg)
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
		return
	}
}

func run(cfg *Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	awsOpts := []func(*config.LoadOptions) error{}
	if cfg.AWS.Region != "" {
		awsOpts = append(awsOpts, config.WithRegion(cfg.AWS.Region))
	}
	if cfg.AWS.AccessKeyId != "" && cfg.AWS.SecretAccessKey != "" {
		awsOpts = append(awsOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AWS.AccessKeyId, cfg.AWS.SecretAccessKey, "")))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return fmt.Errorf("cannot load aws config: %w", err)
	}
	ec2Client := ec2.NewFromConfig(awsCfg)

	err = cleanupExisting(ctx, cfg, ec2Client)
	if err != nil {
		return fmt.Errorf("cannot cleanup existing instances: %w", err)
	}

	key, err := ioutil.ReadFile(cfg.SSH.IdentityFile)
	if err != nil {
		return fmt.Errorf("cannot parse key file %s: %w", cfg.SSH.IdentityFile, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("cannot parse key file %s: %w", cfg.SSH.IdentityFile, err)
	}

	runner := worker.NewRunner(worker.RunnerParams{
		IsFatal: func(err error) bool {
			return false
		},
		ShouldRestart: func(err error) bool {
			return false
		},
		Clock:  clock.WallClock,
		Logger: logrus.New(),
	})
	defer func() {
		runner.Kill()
		err := runner.Wait()
		if err != nil {
			logrus.Errorf("runner: %v", err)
		}
	}()
	backend := &Backend{
		client:  ec2Client,
		signers: []ssh.Signer{signer},
		config:  cfg,
		execs:   map[string]Exec{},
		names:   map[string]string{},
		runner:  runner,
	}

	decoder := runconfig.ContainerDecoder{
		GetSysInfo: func() *sysinfo.SysInfo {
			return &sysinfo.SysInfo{}
		},
	}
	containerRouter := container.NewRouter(backend, decoder, false)
	imageRouter := image.NewRouter(backend)
	systemRouter := system.NewRouter(backend, nil, nil, &map[string]bool{})

	svr := server.New(&server.Config{
		Logging: true,
	})
	svr.InitRouter(systemRouter, containerRouter, imageRouter)

	ls, err := listeners.Init("tcp", cfg.Listen, "", nil)
	if err != nil {
		return err
	}
	svr.Accept(cfg.Listen, ls...)

	errChan := make(chan error)
	go svr.Wait(errChan)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigs:
		return fmt.Errorf("interrupted: %s", sig.String())
	case err = <-errChan:
		if err != nil {
			return err
		}
	}

	return nil
}
