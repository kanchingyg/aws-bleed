package scan

// Client is read-only Describe*/List* inventory for waste heuristics.
type Client interface {
	DescribeNatGateways(region string) ([]NatGateway, error)
	DescribeVpcEndpoints(region string) ([]VpcEndpoint, error)
	DescribeVolumes(region string) ([]Volume, error)
	DescribeAddresses(region string) ([]Address, error)
	DescribeSnapshots(region string) ([]Snapshot, error)
	DescribeLogGroups(region string) ([]LogGroup, error)
}

type NatGateway struct {
	NatGatewayID string
	VpcID        string
	State        string
}

type VpcEndpoint struct {
	VpcID           string
	ServiceName     string
	VpcEndpointType string
}

type Volume struct {
	VolumeID   string
	SizeGiB    int32
	VolumeType string
	State      string
}

type Address struct {
	AllocationID  string
	PublicIP      string
	AssociationID *string
}

type Snapshot struct {
	SnapshotID    string
	VolumeSizeGiB int32
	StartTime     string
}

type LogGroup struct {
	LogGroupName    string
	RetentionInDays *int32
	StoredBytes     *int64
}
