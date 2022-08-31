package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/errdefs"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Namespace string                 `yaml:"namespace"`
	Images    map[string]ImageConfig `yaml:"images"`
	SSH       SSHConfig              `yaml:"ssh"`
	AWS       AWSConfig              `yaml:"aws"`
	Listen    string                 `yaml:"listen"`
}

type ImageConfig struct {
	AMI                string            `yaml:"ami"`
	AMIOwners          []string          `yaml:"ami-owners"`
	InstanceType       string            `yaml:"instance-type"`
	UserData           string            `yaml:"user-data"`
	StartScript        string            `yaml:"start-script"`
	IAMInstanceProfile string            `yaml:"iam-instance-profile"`
	Tags               map[string]string `yaml:"tags"`
	SecurityGroups     []string          `yaml:"security-groups"`
	DefaultUser        string            `yaml:"default-user"`
	VPC                string            `yaml:"vpc"`
}

type SSHConfig struct {
	KeyPair      string `yaml:"key-pair"`
	IdentityFile string `yaml:"identity-file"`
}

type AWSConfig struct {
	AccessKeyId     string `yaml:"access-key-id"`
	SecretAccessKey string `yaml:"secret-access-key"`
	Region          string `yaml:"region"`
}

func ReadConfig(file string) (*Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if os.Getenv("SNAP_NAME") == "ducker" {
		cmd := exec.Command("snapctl", "get", "env", "-d")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, err
		}
		kv := map[string]string{}
		err = json.Unmarshal(out, &kv)
		if err != nil {
			return nil, err
		}
		for k, v := range kv {
			k = strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
			os.Setenv(k, v)
		}
	}

	config := &Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	config.Listen = os.ExpandEnv(config.Listen)
	config.Namespace = os.ExpandEnv(config.Namespace)
	config.SSH.KeyPair = os.ExpandEnv(config.SSH.KeyPair)
	config.SSH.IdentityFile = os.ExpandEnv(config.SSH.IdentityFile)
	config.AWS.Region = os.ExpandEnv(config.AWS.Region)
	config.AWS.AccessKeyId = os.ExpandEnv(config.AWS.AccessKeyId)
	config.AWS.SecretAccessKey = os.ExpandEnv(config.AWS.SecretAccessKey)

	spew.Dump(config)

	return config, nil
}

func (c *ImageConfig) ResolveAMI(ctx context.Context, client *ec2.Client) (string, error) {
	if strings.HasPrefix(c.AMI, "ami-") {
		return c.AMI, nil
	}

	opts := &ec2.DescribeImagesInput{
		Owners: c.AMIOwners,
		Filters: []types.Filter{
			{Name: aws.String("tag:Name"), Values: []string{c.AMI}},
		},
	}

	res, err := client.DescribeImages(ctx, opts)
	if err != nil {
		return "", err
	}

	var newest *types.Image
	var t time.Time
	for _, v := range res.Images {
		image := v
		if v.CreationDate == nil {
			continue
		}
		creationDate, err := time.Parse("2006-01-02T15:04:05.000Z", *v.CreationDate)
		if err != nil {
			return "", err
		}
		if newest == nil || t.Before(creationDate) {
			t = creationDate
			newest = &image
		}
	}

	if newest == nil {
		return "", errdefs.NotFound(fmt.Errorf("no image with tag:Name=%s was found", c.AMI))
	}

	return *newest.ImageId, nil
}
