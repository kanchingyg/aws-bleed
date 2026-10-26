package awslive

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/kanchingyg/aws-bleed/internal/scan"
)

// LiveClient implements scan.Client with paginated Describe*/List* calls.
type LiveClient struct {
	defaultRegion string
	ec2           map[string]*ec2.Client
	logs          map[string]*cloudwatchlogs.Client
}

// NewLiveClient loads AWS config for the default region.
func NewLiveClient(defaultRegion string) (*LiveClient, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(defaultRegion))
	if err != nil {
		return nil, err
	}
	return &LiveClient{
		defaultRegion: defaultRegion,
		ec2:           map[string]*ec2.Client{defaultRegion: ec2.NewFromConfig(cfg)},
		logs:          map[string]*cloudwatchlogs.Client{defaultRegion: cloudwatchlogs.NewFromConfig(cfg)},
	}, nil
}

func (c *LiveClient) ec2For(region string) (*ec2.Client, error) {
	if client, ok := c.ec2[region]; ok {
		return client, nil
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := ec2.NewFromConfig(cfg)
	c.ec2[region] = client
	return client, nil
}

func (c *LiveClient) logsFor(region string) (*cloudwatchlogs.Client, error) {
	if client, ok := c.logs[region]; ok {
		return client, nil
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := cloudwatchlogs.NewFromConfig(cfg)
	c.logs[region] = client
	return client, nil
}

func (c *LiveClient) DescribeNatGateways(region string) ([]scan.NatGateway, error) {
	ec2c, err := c.ec2For(region)
	if err != nil {
		return nil, err
	}
	return PaginateWithToken(func(token *string) ([]scan.NatGateway, *string, error) {
		in := &ec2.DescribeNatGatewaysInput{}
		if token != nil {
			in.NextToken = token
		}
		res, err := ec2c.DescribeNatGateways(context.Background(), in)
		if err != nil {
			return nil, nil, err
		}
		items := make([]scan.NatGateway, 0, len(res.NatGateways))
		for _, n := range res.NatGateways {
			state := ""
			if n.State != "" {
				state = string(n.State)
			}
			items = append(items, scan.NatGateway{
				NatGatewayID: aws.ToString(n.NatGatewayId),
				VpcID:        aws.ToString(n.VpcId),
				State:        state,
			})
		}
		return items, res.NextToken, nil
	})
}

func (c *LiveClient) DescribeVpcEndpoints(region string) ([]scan.VpcEndpoint, error) {
	ec2c, err := c.ec2For(region)
	if err != nil {
		return nil, err
	}
	return PaginateWithToken(func(token *string) ([]scan.VpcEndpoint, *string, error) {
		in := &ec2.DescribeVpcEndpointsInput{}
		if token != nil {
			in.NextToken = token
		}
		res, err := ec2c.DescribeVpcEndpoints(context.Background(), in)
		if err != nil {
			return nil, nil, err
		}
		items := make([]scan.VpcEndpoint, 0, len(res.VpcEndpoints))
		for _, e := range res.VpcEndpoints {
			typ := ""
			if e.VpcEndpointType != "" {
				typ = string(e.VpcEndpointType)
			}
			items = append(items, scan.VpcEndpoint{
				VpcID:           aws.ToString(e.VpcId),
				ServiceName:     aws.ToString(e.ServiceName),
				VpcEndpointType: typ,
			})
		}
		return items, res.NextToken, nil
	})
}

func (c *LiveClient) DescribeVolumes(region string) ([]scan.Volume, error) {
	ec2c, err := c.ec2For(region)
	if err != nil {
		return nil, err
	}
	return PaginateWithToken(func(token *string) ([]scan.Volume, *string, error) {
		in := &ec2.DescribeVolumesInput{}
		if token != nil {
			in.NextToken = token
		}
		res, err := ec2c.DescribeVolumes(context.Background(), in)
		if err != nil {
			return nil, nil, err
		}
		items := make([]scan.Volume, 0, len(res.Volumes))
		for _, v := range res.Volumes {
			state := ""
			if v.State != "" {
				state = string(v.State)
			}
			volType := "gp3"
			if v.VolumeType != "" {
				volType = string(v.VolumeType)
			}
			items = append(items, scan.Volume{
				VolumeID:   aws.ToString(v.VolumeId),
				SizeGiB:    aws.ToInt32(v.Size),
				VolumeType: volType,
				State:      state,
			})
		}
		return items, res.NextToken, nil
	})
}

func (c *LiveClient) DescribeAddresses(region string) ([]scan.Address, error) {
	ec2c, err := c.ec2For(region)
	if err != nil {
		return nil, err
	}
	res, err := ec2c.DescribeAddresses(context.Background(), &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}
	items := make([]scan.Address, 0, len(res.Addresses))
	for _, a := range res.Addresses {
		items = append(items, scan.Address{
			AllocationID:  aws.ToString(a.AllocationId),
			PublicIP:      aws.ToString(a.PublicIp),
			AssociationID: a.AssociationId,
		})
	}
	return items, nil
}

func (c *LiveClient) DescribeSnapshots(region string) ([]scan.Snapshot, error) {
	ec2c, err := c.ec2For(region)
	if err != nil {
		return nil, err
	}
	return PaginateWithToken(func(token *string) ([]scan.Snapshot, *string, error) {
		in := &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}}
		if token != nil {
			in.NextToken = token
		}
		res, err := ec2c.DescribeSnapshots(context.Background(), in)
		if err != nil {
			return nil, nil, err
		}
		items := make([]scan.Snapshot, 0, len(res.Snapshots))
		for _, s := range res.Snapshots {
			start := time.Time{}
			if s.StartTime != nil {
				start = *s.StartTime
			}
			items = append(items, scan.Snapshot{
				SnapshotID:    aws.ToString(s.SnapshotId),
				VolumeSizeGiB: aws.ToInt32(s.VolumeSize),
				StartTime:     start.UTC().Format(time.RFC3339),
			})
		}
		return items, res.NextToken, nil
	})
}

func (c *LiveClient) DescribeLogGroups(region string) ([]scan.LogGroup, error) {
	logsc, err := c.logsFor(region)
	if err != nil {
		return nil, err
	}
	return PaginateWithToken(func(token *string) ([]scan.LogGroup, *string, error) {
		in := &cloudwatchlogs.DescribeLogGroupsInput{}
		if token != nil {
			in.NextToken = token
		}
		res, err := logsc.DescribeLogGroups(context.Background(), in)
		if err != nil {
			return nil, nil, err
		}
		items := make([]scan.LogGroup, 0, len(res.LogGroups))
		for _, g := range res.LogGroups {
			var retention *int32
			if g.RetentionInDays != nil {
				retention = g.RetentionInDays
			}
			items = append(items, scan.LogGroup{
				LogGroupName:    aws.ToString(g.LogGroupName),
				RetentionInDays: retention,
				StoredBytes:     g.StoredBytes,
			})
		}
		return items, res.NextToken, nil
	})
}

// Ensure LiveClient satisfies scan.Client.
var _ scan.Client = (*LiveClient)(nil)
