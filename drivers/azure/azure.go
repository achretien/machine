package azure

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	azure "github.com/Azure/azure-sdk-for-go/management"
	"github.com/Azure/azure-sdk-for-go/management/hostedservice"
	"github.com/Azure/azure-sdk-for-go/management/virtualmachine"
	"github.com/Azure/azure-sdk-for-go/management/vmutils"

	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/log"
	"github.com/docker/machine/ssh"
	"github.com/docker/machine/state"
	"github.com/docker/machine/utils"
	"io/ioutil"
	"encoding/base64"
)

type Driver struct {
	IPAddress               string
	MachineName             string
	CloudServiceName        string
	SubscriptionID          string
	SubscriptionCert        string
	PublishSettingsFilePath string
	Location                string
	Storage                 string
	Size                    string
	UserPassword            string
	Image                   string
	SSHUser                 string
	SSHPort                 int
	DockerPort              int
	CaCertPath              string
	PrivateKeyPath          string
	SwarmMaster             bool
	SwarmHost               string
	SwarmDiscovery          string
	storePath               string
}

func init() {
	drivers.Register("azure", &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

// GetCreateFlags registers the flags this d adds to
// "docker hosts create"
func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.IntFlag{
			Name:  "azure-docker-port",
			Usage: "Azure Docker port",
			Value: 2376,
		},
		cli.StringFlag{
			EnvVar: "AZURE_IMAGE",
			Name:   "azure-image",
			Usage:  "Azure image name. Default is Ubuntu 14.04 LTS x64",
			Value:  "b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04_2-LTS-amd64-server-20150506-en-us-30GB",
		},
		cli.StringFlag{
			EnvVar: "AZURE_LOCATION",
			Name:   "azure-location",
			Usage:  "Azure location",
			Value:  "West US",
		},
		cli.StringFlag{
			Name:  "azure-password",
			Usage: "Azure user password",
		},
		cli.StringFlag{
			EnvVar: "AZURE_PUBLISH_SETTINGS_FILE",
			Name:   "azure-publish-settings-file",
			Usage:  "Azure publish settings file",
		},
		cli.StringFlag{
			EnvVar: "AZURE_SIZE",
			Name:   "azure-size",
			Usage:  "Azure size",
			Value:  "Small",
		},
		cli.IntFlag{
			Name:  "azure-ssh-port",
			Usage: "Azure SSH port",
			Value: 22,
		},

		cli.StringFlag{
			EnvVar: "AZURE_SUBSCRIPTION_CERT",
			Name:   "azure-subscription-cert",
			Usage:  "Azure subscription cert",
		},
		cli.StringFlag{
			EnvVar: "AZURE_SUBSCRIPTION_ID",
			Name:   "azure-subscription-id",
			Usage:  "Azure subscription ID",
		},
		cli.StringFlag{
			Name:  "azure-username",
			Usage: "Azure username",
			Value: "ubuntu",
		},
		cli.StringFlag{
			Name:  "azure-cloud-service",
			Usage: "Azure Cloud Service (will be created if not exists)",
		},
		cli.StringFlag{
			Name:  "azure-storage",
			Usage: "Azure Storage (will be created if not exists)",
		},
	}
}

func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	d := &Driver{MachineName: machineName, storePath: storePath, CaCertPath: caCert, PrivateKeyPath: privateKey}
	return d, nil
}

func (d *Driver) AuthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) DeauthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "ubuntu"
	}

	return d.SSHUser
}

func (d *Driver) DriverName() string {
	return "azure"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.SubscriptionID = flags.String("azure-subscription-id")

	cert := flags.String("azure-subscription-cert")
	publishSettings := flags.String("azure-publish-settings-file")
	image := flags.String("azure-image")
	username := flags.String("azure-username")

	if cert != "" {
		if _, err := os.Stat(cert); os.IsNotExist(err) {
			return err
		}
		d.SubscriptionCert = cert
	}

	if publishSettings != "" {
		if _, err := os.Stat(publishSettings); os.IsNotExist(err) {
			return err
		}
		d.PublishSettingsFilePath = publishSettings
	}

	if (d.SubscriptionID == "" || d.SubscriptionCert == "") && d.PublishSettingsFilePath == "" {
		return errors.New("Please specify azure subscription params using options: --azure-subscription-id and --azure-subscription-cert or --azure-publish-settings-file")
	}

	if image == "" {
		d.Image = "b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04_2-LTS-amd64-server-20150506-en-us-30GB"
	} else {
		d.Image = image
	}

	d.CloudServiceName = flags.String("azure-cloud-service")
	if d.CloudServiceName == "" {
		return errors.New("Please specify azure cloud service param using options: --azure-cloud-service")
	}

	d.Storage = flags.String("azure-storage")
	if d.Storage == "" {
		return errors.New("Please specify azure storage device param using options: --azure-storage")
	}

	d.Location = flags.String("azure-location")
	d.Size = flags.String("azure-size")

	if strings.ToLower(username) == "docker" {
		return errors.New("'docker' is not valid user name for docker host. Please specify another user name")
	}

	d.SSHUser = username
	d.UserPassword = flags.String("azure-password")
	d.DockerPort = flags.Int("azure-docker-port")
	d.SSHPort = flags.Int("azure-ssh-port")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	return nil
}

func (d *Driver) PreCreateCheck() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	// check if the hosted service belong to the account
	if listHostedServicesResponse, err := hostedservice.NewClient(client).ListHostedServices(); err != nil {
		return err
	} else {
		found := false
		for _, hostedService := range listHostedServicesResponse.HostedServices {
			if hostedService.ServiceName == d.CloudServiceName {
				log.Info("Cloud Service found")
				found = true
				break
			}
		}
		if !found {
			log.Info("Cloud Service not found. Check if name is available")
			if response, err := hostedservice.NewClient(client).CheckHostedServiceNameAvailability(d.CloudServiceName); err != nil {
				return err
			} else if !response.Result {
				return errors.New(response.Reason)
			}

			log.Info("Name is available. Create Cloud Service")
			if err := hostedservice.NewClient(client).CreateHostedService(hostedservice.CreateHostedServiceParameters{
				ServiceName: d.CloudServiceName,
				Location:    d.Location,
				Label:       base64.StdEncoding.EncodeToString([]byte(d.CloudServiceName))}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Driver) Create() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	log.Info("Creating Azure Role...")
	role := vmutils.NewVMConfiguration(d.MachineName, d.Size)

	log.Debug("Configure Role with image...")
	if err := vmutils.ConfigureDeploymentFromPlatformImage(
		&role,
		d.Image,
		fmt.Sprintf("http://%s.blob.core.windows.net/vhds/%s-%s.vhd", d.Storage, d.CloudServiceName, d.MachineName),
		""); err != nil {
		return err
	}

	log.Debug("Generating certificate for Azure...")
	if err := d.generateCertForAzure(); err != nil {
		return err
	}

	log.Debug("Adding Linux provisioning...")
	if err := vmutils.ConfigureForLinux(&role, d.MachineName, d.GetSSHUsername(), d.UserPassword); err != nil {
		return err
	}

	log.Debug("Enable public SSH...")
	if err := vmutils.ConfigureWithPublicSSH(&role); err != nil {
		return err
	}

	log.Debug("Authorizing ports...")
	if err := d.addDockerEndpoint(&role); err != nil {
		return err
	}

	log.Debug("Creating VM...")

	operationID, err := virtualmachine.NewClient(client).CreateDeployment(role, d.CloudServiceName, virtualmachine.CreateDeploymentOptions{})
	if err != nil {
		return err
	}
	if err := client.WaitForOperation(operationID, nil); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GetURL() (string, error) {
	url := fmt.Sprintf("tcp://%s:%v", d.getHostname(), d.DockerPort)
	return url, nil
}

func (d *Driver) GetIP() (string, error) {
	return d.getHostname(), nil
}

func (d *Driver) GetState() (state.State, error) {
	client, err := d.setUserSubscription()
	if err != nil {
		return state.Error, err
	}

	deployment, err := virtualmachine.NewClient(client).GetDeployment(d.CloudServiceName, d.MachineName)
	if err != nil {
		if strings.Contains(err.Error(), "Code: ResourceNotFound") {
			return state.Error, errors.New("Azure host was not found. Please check your Azure subscription.")
		}

		return state.Error, err
	}

	vmState := deployment.RoleInstanceList[0].PowerState
	switch vmState {
	case virtualmachine.PowerStateStarted:
		return state.Running, nil
	case virtualmachine.PowerStateStarting:
		return state.Starting, nil
	case virtualmachine.PowerStateStopped:
		return state.Stopped, nil
	case virtualmachine.PowerStateStopping:
		return state.Stopping, nil
	}

	return state.None, nil
}

func (d *Driver) Start() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	if vmState, err := d.GetState(); err != nil {
		return err
	} else if vmState == state.Running || vmState == state.Starting {
		log.Infof("Host is already running or starting")
		return nil
	}

	log.Debugf("starting %s", d.MachineName)

	operationID, err := virtualmachine.NewClient(client).StartRole(d.CloudServiceName, d.MachineName, d.MachineName);
	if err != nil {
		return err
	}

	if err := client.WaitForOperation(operationID, nil); err != nil {
		return err
	}

	d.IPAddress, err = d.GetIP()
	return err
}

func (d *Driver) Stop() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	if vmState, err := d.GetState(); err != nil {
		return err
	} else if vmState == state.Stopped || vmState == state.Stopping {
		log.Infof("Host is already stopped")
		return nil
	}

	log.Debugf("stopping %s", d.MachineName)

	operationID, err := virtualmachine.NewClient(client).ShutdownRole(d.CloudServiceName, d.MachineName, d.MachineName)
	if err != nil {
		return err
	}

	if err := client.WaitForOperation(operationID, nil); err != nil {
		return err
	}

	d.IPAddress = ""
	return nil
}

func (d *Driver) Remove() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	hostClient := hostedservice.NewClient(client)

	if response, err := hostClient.CheckHostedServiceNameAvailability(d.CloudServiceName); err != nil {
		return err
	} else if response.Result {
		return nil
	}

	log.Debugf("removing %s", d.CloudServiceName)

	operationID, err := hostClient.DeleteHostedService(d.CloudServiceName, true)
	if err != nil {
		return err
	}

	return client.WaitForOperation(operationID, nil)
}

func (d *Driver) Restart() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}
	if vmState, err := d.GetState(); err != nil {
		return err
	} else if vmState == state.Stopped {
		return errors.New("Host is already stopped, use start command to run it")
	}else if vmState == state.Stopping {
		return errors.New("Host is stopping, wait a few seconds then use start command to run it")
	}

	log.Debugf("restarting %s", d.MachineName)

	if _, err := virtualmachine.NewClient(client).RestartRole(d.CloudServiceName, d.MachineName, d.MachineName); err != nil {
		return err
	}

	d.IPAddress, err = d.GetIP()
	return err
}

func (d *Driver) Kill() error {
	client, err := d.setUserSubscription()
	if err != nil {
		return err
	}

	if vmState, err := d.GetState(); err != nil {
		return err
	} else if vmState == state.Stopped {
		log.Infof("Host is already stopped")
		return nil
	}

	log.Debugf("killing %s", d.MachineName)

	operationID, err := virtualmachine.NewClient(client).ShutdownRole(d.CloudServiceName, d.MachineName, d.MachineName)
	if err != nil {
		return err
	}

	if err := client.WaitForOperation(operationID, nil); err != nil {
		return err
	}

	d.IPAddress = ""
	return nil
}

func generateVMName() string {
	randomID := utils.TruncateID(utils.GenerateRandomID())
	return fmt.Sprintf("docker-host-%s", randomID)
}

func (d *Driver) setUserSubscription() (client azure.Client, err error) {
	if d.PublishSettingsFilePath != "" {
		return azure.ClientFromPublishSettingsFile(d.PublishSettingsFilePath, "")
	}

	subscriptionCertContent, err := ioutil.ReadFile(d.SubscriptionCert)
	if err != nil {
		return client, err
	}

	return azure.NewClient(d.SubscriptionID, subscriptionCertContent)
}

func (d *Driver) addDockerEndpoint(role *virtualmachine.Role) error {
	configSets := role.ConfigurationSets
	if len(configSets) == 0 {
		return errors.New("no configuration set")
	}
	for i := 0; i < len(configSets); i++ {
		if configSets[i].ConfigurationSetType != "NetworkConfiguration" {
			continue
		}
		ep := virtualmachine.InputEndpoint{
			Name:      "docker",
			Protocol:  "tcp",
			Port:      d.DockerPort,
			LocalPort: d.DockerPort}
		configSets[i].InputEndpoints = append(configSets[i].InputEndpoints, ep)
		log.Debugf("added Docker endpoint (port %d) to configuration", d.DockerPort)
	}
	return nil
}

func (d *Driver) generateCertForAzure() error {
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	cmd := exec.Command("openssl", "req", "-x509", "-key", d.GetSSHKeyPath(), "-nodes", "-days", "365", "-newkey", "rsa:2048", "-out", d.azureCertPath(), "-subj", "/C=AU/ST=Some-State/O=InternetWidgitsPtyLtd/CN=\\*")
	return cmd.Run()
}

func (d *Driver) azureCertPath() string {
	return filepath.Join(d.storePath, "azure_cert.pem")
}

func (d *Driver) getHostname() string {
	return d.CloudServiceName + ".cloudapp.net"
}

