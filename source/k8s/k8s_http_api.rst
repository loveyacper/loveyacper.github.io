# 使用HTTPS访问k8s apiserver

## 解析kube config yaml文件 
```
package xxx

import (
	"errors"
	"fmt"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

var config *KubeConfig

// Parse from .kube/config
type KubeConfig struct {
	Kind           string     `yaml:"kind"`
	CurrentContext string     `yaml:"current-context"`
	ApiVersion     string     `yaml:"apiVersion"`
	ClusterList    []Cluster  `yaml:"clusters"`
	UserList       []UserInfo `yaml:"users"`
	ContextList    []Context  `yaml:"contexts"`
}

type Cluster struct {
	ClusterDetail `yaml:"cluster,flow"`
	Name          string `yaml:"name"`
}

type ClusterDetail struct {
	CAData string `yaml:"certificate-authority-data"`
	CAFile string `yaml:"certificate-authority"`
	Server string `yaml:"server"`
}

type UserDetail struct {
	CertData string `yaml:"client-certificate-data"`
	CertFile string `yaml:"client-certificate"`
	KeyData  string `yaml:"client-key-data"`
	KeyFile  string `yaml:"client-key"`
}
type UserInfo struct {
	UserDetail `yaml:"user"`
	Name       string `yaml:"name"`
}

type ContextDetail struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace"`
}
type Context struct {
	ContextDetail `yaml:"context"`
	Name          string `yaml:"name"`
}

func ParseKubeConfig(contents []byte) (cfg *KubeConfig, err error) {
	cfg = new(KubeConfig)
	err = yaml.Unmarshal(contents, cfg)
	if err != nil {
		cfg = nil
	}

	return
}

func ParseKubeConfigFromFile(configFile string) (*KubeConfig, error) {
	contents, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	return ParseKubeConfig(contents)
}

func CheckKubeConfig(cfg *KubeConfig) error {
	if cfg == nil {
		return errors.New("[KubeConfig] Nil")
	}

	if cfg.Kind != "Config" {
		return fmt.Errorf("[KubeConfig] Wrong kind: %s", cfg.Kind)
	}

	if len(cfg.ClusterList) == 0 {
		return errors.New("[KubeConfig] Empty cluster list")
	}

	for _, cluster := range cfg.ClusterList {
		if len(cluster.CAFile) == 0 &&
			len(cluster.CAData) == 0 {
			return fmt.Errorf("[KubeConfig] No ca file for cluster: %s", cluster.Name)
		}
		if len(cluster.Server) == 0 {
			return fmt.Errorf("[KubeConfig] No server addr for cluster: %s", cluster.Name)
		}
	}

	for _, user := range cfg.UserList {
		if len(user.CertData) == 0 &&
			len(user.CertFile) == 0 {
			return fmt.Errorf("[KubeConfig] No cert data for user: %s", user.Name)
		}
		if len(user.KeyData) == 0 &&
			len(user.KeyFile) == 0 {
			return fmt.Errorf("[KubeConfig] No key data for user: %s", user.Name)
		}
	}

	return nil
}

```

## 构造https client访问k8s
```
package k8s

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.code.oa.com/cloud_video_product_private/cloud_gaming/Go/comm/log"
	"io"
	"io/ioutil"
	"net/http"
)

type Client struct {
	*http.Client
	cfg *KubeConfig
}

var K8client *Client

func InitK8SClient(kubeconfig string) (*Client, error) {
	cfg, err := ParseKubeConfigFromFile(kubeconfig)
	if err != nil {
		return nil, err
	}
	err = CheckKubeConfig(cfg)
	if err != nil {
		return nil, err
	}

	// load client cert and key
	var clientCerts tls.Certificate
	user := cfg.UserList[0]
	if len(user.CertData) > 0 {
		cert, err := base64.StdEncoding.DecodeString(user.CertData)
		if err != nil {
			return nil, err
		}
		key, err := base64.StdEncoding.DecodeString(user.KeyData)
		if err != nil {
			return nil, err
		}
		clientCerts, err = tls.X509KeyPair(cert, key)
	} else {
		clientCerts, err = tls.LoadX509KeyPair(user.CertFile, user.KeyFile)
	}
	if err != nil {
		return nil, err
	}

	// load CA
	caData, err := base64.StdEncoding.DecodeString(cfg.ClusterList[0].CAData)
	if err != nil {
		return nil, err
	}
	rootCAData := loadCA(caData)
	if rootCAData == nil {
		rootCAData, err = loadCAFromFile(cfg.ClusterList[0].CAFile)
		if err != nil {
			return nil, err
		}
	}

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCAData,
				InsecureSkipVerify: rootCAData == nil,
				Certificates:       []tls.Certificate{clientCerts},
			},
		}}

	return &Client{c, cfg}, nil
}

func (c *Client) ClusterName() string {
	return c.cfg.ClusterList[0].Name
}

type ResourceType int32

const (
	Job ResourceType = iota
	StatefulSet
	Deployment
	Pod
	Service
	PersistentVolumeClaim
	ConfigMap
	DaemonSet
)

type Metadata struct {
	Name string `json:"name"`
	Namespace string `json:"namespace"`
	SelfLink string `json:"selfLink"`
}

type CreateResourceRsp struct {
	Kind string `json:"kind"`
	ApiVersion string `json:"apiVersion"`
	Metadata Metadata `json:"metadata"`
}

func (c *Client) CreateJob(spec string, namespace string) (*CreateResourceRsp, error) {
	return c.createResource(spec, Job, namespace)
}

func (c *Client) CreateStatefulSet(spec string, namespace string) (*CreateResourceRsp, error) {
	return c.createResource(spec, StatefulSet, namespace)
}

func (c *Client) createResourceFromFile(file string, resType ResourceType, namespace string) (*CreateResourceRsp, error) {
	spec, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return c.createResource(string(spec), resType, namespace)
}

func (c *Client) createResource(spec string, resType ResourceType, namespace string) (*CreateResourceRsp, error) {
	if len(namespace) == 0 {
		namespace = "default"
	}

	var uri string
	switch resType {
	case Job:
		uri = "/apis/batch/v1/namespaces/" + namespace + "/jobs"
	case StatefulSet:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/statefulsets"
	case Deployment:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/deployments"
	case Pod:
		uri = "/api/v1/namespaces/" + namespace + "/pods"
	case Service:
		uri = "/api/v1/namespaces/" + namespace + "/services"
	case PersistentVolumeClaim:
		uri = "/api/v1/namespaces/" + namespace + "/persistentvolumeclaims"
	case ConfigMap:
		uri = "/api/v1/namespaces/" + namespace + "/configmaps"
	case DaemonSet:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/daemonsets"

	default:
		return nil, fmt.Errorf("Not support resource type")
	}

	reader := bytes.NewBufferString(spec)
	if resp, err := c.Post(c.cfg.ClusterList[0].Server+uri,
		"application/yaml",
		reader); err != nil {
		return nil, err
	} else {
		defer resp.Body.Close()

		var buf bytes.Buffer
		io.Copy(&buf, resp.Body)
		var meta CreateResourceRsp
		data := buf.Bytes()
		log.Info("CreateResource", "%s", string(data))
		if err := json.Unmarshal(buf.Bytes(), &meta); err != nil {
			return nil, err
		}

		return &meta, nil
	}
}

func loadCAFromFile(caFile string) (*x509.CertPool, error) {
	if ca, err := ioutil.ReadFile(caFile); err != nil {
		return nil, err
	} else {
		x509cp := loadCA(ca)
		if x509cp == nil {
			err = fmt.Errorf("Can't load ca [%s]", caFile)
		}

		return x509cp, err
	}
}

func loadCA(caData []byte) *x509.CertPool {
	if len(caData) == 0 {
		return nil
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caData); !ok {
		return nil
	}
	return pool
}

func (c *Client)DestroyResourceByLink(selfLink string) error {
	uri := selfLink
	req, err := http.NewRequest("DELETE", c.cfg.ClusterList[0].Server+uri, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/yaml")
	if resp, err := c.Do(req); err != nil {
		return err
	} else {
		defer resp.Body.Close()
		contents := make([]byte, 2048)
		resp.Body.Read(contents)
		log.Info("DeleteResource", "%s", string(contents))
		return nil
	}
}

func (c *Client)DestroyResource(resName string, resType ResourceType, namespace string) error {
	if len(namespace) == 0 {
		namespace = "default"
	}

	var uri string
	switch resType {
	case Job:
		uri = "/apis/batch/v1/namespaces/" + namespace + "/jobs/" + resName
	case StatefulSet:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/statefulsets/" + resName
	case Deployment:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/deployments/" + resName
	case Pod:
		uri = "/api/v1/namespaces/" + namespace + "/pods/" + resName
	case Service:
		uri = "/api/v1/namespaces/" + namespace + "/services/" + resName
	case PersistentVolumeClaim:
		uri = "/api/v1/namespaces/" + namespace + "/persistentvolumeclaims/" + resName
	case ConfigMap:
		uri = "/api/v1/namespaces/" + namespace + "/configmaps/" + resName
	case DaemonSet:
		uri = "/apis/apps/v1/namespaces/" + namespace + "/daemonsets/" + resName

	default:
		return fmt.Errorf("Not support resource type")
	}

	req, err := http.NewRequest("DELETE", c.cfg.ClusterList[0].Server+uri, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/yaml")
	if resp, err := c.Do(req); err != nil {
		return err
	} else {
		defer resp.Body.Close()
		contents := make([]byte, 2048)
		resp.Body.Read(contents)
		log.Info("DestroyResource", "%s", string(contents))

		return nil
	}
}
```
