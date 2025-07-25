package installcfg

import (
	"github.com/go-openapi/strfmt"
	configv1 "github.com/openshift/api/config/v1"
	cluster_validations "github.com/openshift/assisted-service/internal/cluster/validations"
)

type Platform struct {
	Baremetal *BareMetalInstallConfigPlatform `json:"baremetal,omitempty"`
	None      *PlatformNone                   `json:"none,omitempty"`
	Vsphere   *VsphereInstallConfigPlatform   `json:"vsphere,omitempty"`
	Nutanix   *NutanixInstallConfigPlatform   `json:"nutanix,omitempty"`
	External  *ExternalInstallConfigPlatform  `json:"external,omitempty"`
}

type BMC struct {
	Username                       string `json:"username"`
	Password                       string `json:"password"`
	Address                        string `json:"address"`
	DisableCertificateVerification bool   `json:"disableCertificateVerification"`
}

type Host struct {
	Name            string `json:"name"`
	Role            string `json:"role"`
	BootMACAddress  string `json:"bootMACAddress"`
	BootMode        string `json:"bootMode"`
	BMC             BMC    `json:"bmc"`
	HardwareProfile string `json:"hardwareProfile"`
}

type BareMetalInstallConfigPlatform struct {
	ProvisioningNetwork          string                                  `json:"provisioningNetwork"`
	APIVIPs                      []string                                `json:"apiVIPs,omitempty"`
	DeprecatedAPIVIP             string                                  `json:"apiVIP,omitempty"`
	IngressVIPs                  []string                                `json:"ingressVIPs,omitempty"`
	DeprecatedIngressVIP         string                                  `json:"ingressVIP,omitempty"`
	Hosts                        []Host                                  `json:"hosts"`
	ClusterOSImage               string                                  `json:"clusterOSImage,omitempty"`
	ClusterProvisioningIP        string                                  `json:"clusterProvisioningIP,omitempty"`
	ProvisioningNetworkInterface string                                  `json:"provisioningNetworkInterface,omitempty"`
	ProvisioningNetworkCIDR      *string                                 `json:"provisioningNetworkCIDR,omitempty"`
	ProvisioningDHCPRange        string                                  `json:"provisioningDHCPRange,omitempty"`
	AdditionalNTPServers         []string                                `json:"additionalNTPServers,omitempty"`
	LoadBalancer                 *configv1.BareMetalPlatformLoadBalancer `json:"loadBalancer,omitempty"`
}

type VsphereFailureDomainTopology struct {
	ComputeCluster string   `json:"computeCluster"`
	Datacenter     string   `json:"datacenter"`
	Datastore      string   `json:"datastore"`
	Folder         string   `json:"folder,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	ResourcePool   string   `json:"resourcePool,omitempty"`
}

// VsphereFailureDomain holds the region and zone failure domain and the vCenter topology of that failure domain.
type VsphereFailureDomain struct {
	// Name defines the name of the VsphereFailureDomain. This name is arbitrary but will be used in VSpherePlatformDeploymentZone for association
	Name string `json:"name"`

	// Region defines a FailureDomainCoordinate which includes the name of the vCenter tag, the failure domain type and the name of the vCenter tag category.
	Region string `json:"region"`

	// Server is the fully-qualified domain name or the IP address of the vCenter server.
	Server string `json:"server"`

	// Topology describes a given failure domain using vSphere constructs
	Topology VsphereFailureDomainTopology `json:"topology"`

	// Zone defines a VSpherePlatformFailureDomain which includes the name of the vCenter tag, the failure domain type and the name of the vCenter tag category.
	Zone string `json:"zone"`
}

// VsphereVCenter stores the vCenter connection fields https://github.com/kubernetes/cloud-provider-vsphere/blob/master/pkg/common/config/types_yaml.go
type VsphereVCenter struct {
	// Datacenter in which VMs are located.
	Datacenters []string `json:"datacenters"`

	// Password is the password for the user to use
	Password strfmt.Password `json:"password"`

	// Port is the TCP port that will be used to communicate to the vCenter endpoint. This is typically unchanged
	// from the default of HTTPS TCP/443.
	Port int32 `json:"port,omitempty"`

	// Server is the fully-qualified domain name or the IP address of the vCenter server
	Server string `json:"server"`

	// Username is the username that will be used to connect to vCenter
	Username string `json:"user"`
}

type VsphereInstallConfigPlatform struct {
	DeprecatedVCenter          string                                `json:"vCenter,omitempty"`
	DeprecatedUsername         string                                `json:"username,omitempty"`
	DeprecatedPassword         strfmt.Password                       `json:"password,omitempty"`
	DeprecatedDatacenter       string                                `json:"datacenter,omitempty"`
	DeprecatedDefaultDatastore string                                `json:"defaultDatastore,omitempty"`
	DeprecatedFolder           string                                `json:"folder,omitempty"`
	DeprecatedNetwork          string                                `json:"network,omitempty"`
	DeprecatedCluster          string                                `json:"cluster,omitempty"`
	DeprecatedAPIVIP           string                                `json:"apiVIP,omitempty"`
	DeprecatedIngressVIP       string                                `json:"ingressVIP,omitempty"`
	IngressVIPs                []string                              `json:"ingressVIPs,omitempty"`
	APIVIPs                    []string                              `json:"apiVIPs,omitempty"`
	FailureDomains             []VsphereFailureDomain                `json:"failureDomains,omitempty"`
	VCenters                   []VsphereVCenter                      `json:"vcenters,omitempty"`
	LoadBalancer               *configv1.VSpherePlatformLoadBalancer `json:"loadBalancer,omitempty"`
}

type NutanixInstallConfigPlatform struct {
	ID                   int                   `json:"-"`
	APIVIPs              []string              `json:"apiVIPs,omitempty"`
	DeprecatedAPIVIP     string                `json:"apiVIP,omitempty"`
	IngressVIPs          []string              `json:"ingressVIPs,omitempty"`
	DeprecatedIngressVIP string                `json:"ingressVIP,omitempty"`
	PrismCentral         NutanixPrismCentral   `json:"prismCentral"`
	PrismElements        []NutanixPrismElement `json:"prismElements"`
	SubnetUUIDs          []strfmt.UUID         `json:"subnetUUIDs"`
}

type NutanixPrismCentral struct {
	ID                             int             `json:"-"`
	NutanixInstallConfigPlatformID int             `json:"-"`
	Endpoint                       NutanixEndpoint `json:"endpoint"`
	Username                       string          `json:"username"`
	Password                       strfmt.Password `json:"password"`
}

type NutanixEndpoint struct {
	ID                    int    `json:"-"`
	NutanixPrismCentralID int    `json:"-"`
	Address               string `json:"address"`
	Port                  int32  `json:"port"`
}

type NutanixPrismElement struct {
	ID                             int             `json:"-"`
	NutanixInstallConfigPlatformID int             `json:"-"`
	Endpoint                       NutanixEndpoint `json:"endpoint"`
	UUID                           strfmt.UUID     `json:"uuid"`
	Name                           string          `json:"name"`
}

// CloudControllerManager describes the type of cloud controller manager to be enabled.
type CloudControllerManager string

const (
	// CloudControllerManagerTypeExternal specifies that an external cloud provider is to be configured.
	CloudControllerManagerTypeExternal = "External"

	// CloudControllerManagerTypeNone specifies that no cloud provider is to be configured.
	CloudControllerManagerTypeNone = ""
)

type ExternalInstallConfigPlatform struct {
	// PlatformName holds the arbitrary string representing the infrastructure provider name, expected to be set at the installation time.
	PlatformName string `yaml:"platformName"`

	// CloudControllerManager when set to external, this property will enable an external cloud provider.
	CloudControllerManager CloudControllerManager `yaml:"cloudControllerManager"`
}

type PlatformNone struct {
}

type BootstrapInPlace struct {
	InstallationDisk string `json:"installationDisk,omitempty"`
}

type Proxy struct {
	HTTPProxy  string `json:"httpProxy,omitempty"`
	HTTPSProxy string `json:"httpsProxy,omitempty"`
	NoProxy    string `json:"noProxy,omitempty"`
}

type ImageContentSource struct {
	Mirrors []string `json:"mirrors"`
	Source  string   `json:"source"`
}

type ImageDigestSource struct {
	// Source is the repository that users refer to, e.g. in image pull specifications.
	Source string `json:"source"`

	// Mirrors is one or more repositories that may also contain the same images.
	Mirrors []string `json:"mirrors,omitempty"`
}

type ClusterNetwork struct {
	Cidr       string `json:"cidr"`
	HostPrefix int    `json:"hostPrefix"`
}

type MachineNetwork struct {
	Cidr string `json:"cidr"`
}

type Capabilities struct {
	BaselineCapabilitySet         configv1.ClusterVersionCapabilitySet `json:"baselineCapabilitySet,omitempty"`
	AdditionalEnabledCapabilities []configv1.ClusterVersionCapability  `json:"additionalEnabledCapabilities,omitempty"`
}

type CPUPartitioningMode string

const (
	CPUPartitioningNone     CPUPartitioningMode = "None"
	CPUPartitioningAllNodes CPUPartitioningMode = "AllNodes"
)

// PolicyType is for usage polices that are applied to additionalTrustBundle.
type PolicyType string

const (
	// PolicyProxyOnly  enables use of AdditionalTrustBundle when http/https proxy is configured.
	PolicyProxyOnly PolicyType = "Proxyonly"
	// PolicyAlways ignores all conditions and uses AdditionalTrustBundle.
	PolicyAlways PolicyType = "Always"
)

type InstallerConfigBaremetal struct {
	APIVersion string `json:"apiVersion"`
	BaseDomain string `json:"baseDomain"`
	Proxy      *Proxy `json:"proxy,omitempty"`
	Networking struct {
		NetworkType    string           `json:"networkType"`
		ClusterNetwork []ClusterNetwork `json:"clusterNetwork"`
		MachineNetwork []MachineNetwork `json:"machineNetwork,omitempty"`
		ServiceNetwork []string         `json:"serviceNetwork"`
	} `json:"networking"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Compute []struct {
		Hyperthreading string `json:"hyperthreading,omitempty"`
		Name           string `json:"name"`
		Replicas       int    `json:"replicas"`
	} `json:"compute"`
	ControlPlane struct {
		Hyperthreading string `json:"hyperthreading,omitempty"`
		Name           string `json:"name"`
		Replicas       int    `json:"replicas"`
	} `json:"controlPlane"`
	Arbiter *struct {
		Hyperthreading string `json:"hyperthreading,omitempty"`
		Name           string `json:"name"`
		Replicas       int    `json:"replicas"`
	} `json:"arbiter,omitempty"`
	Platform              Platform            `json:"platform"`
	BootstrapInPlace      *BootstrapInPlace   `json:"bootstrapInPlace,omitempty"`
	FIPS                  bool                `json:"fips"`
	CPUPartitioningMode   CPUPartitioningMode `json:"cpuPartitioningMode,omitempty"`
	PullSecret            string              `json:"pullSecret"`
	SSHKey                string              `json:"sshKey"`
	AdditionalTrustBundle string              `json:"additionalTrustBundle,omitempty"`
	// This field is only needed for installConfig overrides. It defaults to Proxyonly.
	AdditionalTrustBundlePolicy PolicyType `json:"additionalTrustBundlePolicy,omitempty"`
	// The ImageContentSources field is deprecated. Please use ImageDigestSources.
	DeprecatedImageContentSources []ImageContentSource `json:"imageContentSources,omitempty"`
	ImageDigestSources            []ImageDigestSource  `json:"imageDigestSources,omitempty"`
	Capabilities                  *Capabilities        `json:"capabilities,omitempty"`
	FeatureSet                    configv1.FeatureSet  `json:"featureSet,omitempty"`
	FeatureGates                  []string             `json:"featureGates,omitempty"`
}

func (c *InstallerConfigBaremetal) Validate() error {
	if c.AdditionalTrustBundle != "" {
		return cluster_validations.ValidatePEMCertificateBundle(c.AdditionalTrustBundle)
	}

	return nil
}

type LoadBalancer struct {
	Type string `json:"type,omitempty"`
}
