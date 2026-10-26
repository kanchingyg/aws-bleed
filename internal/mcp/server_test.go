package mcp

import (
	"strings"
	"testing"

	"github.com/kanchingyg/aws-bleed/internal/scan"
)

type mockClient struct{}

func (mockClient) DescribeNatGateways(region string) ([]scan.NatGateway, error) {
	return []scan.NatGateway{{NatGatewayID: "nat-0abc", VpcID: "vpc-aaa", State: "available"}}, nil
}
func (mockClient) DescribeVpcEndpoints(region string) ([]scan.VpcEndpoint, error) {
	return nil, nil
}
func (mockClient) DescribeVolumes(region string) ([]scan.Volume, error) {
	return []scan.Volume{
		{VolumeID: "vol-gp2", SizeGiB: 100, VolumeType: "gp2", State: "in-use"},
		{VolumeID: "vol-orphan", SizeGiB: 50, VolumeType: "gp3", State: "available"},
	}, nil
}
func (mockClient) DescribeAddresses(region string) ([]scan.Address, error) {
	return []scan.Address{{AllocationID: "eipalloc-1", PublicIP: "203.0.113.10"}}, nil
}
func (mockClient) DescribeSnapshots(region string) ([]scan.Snapshot, error) {
	return []scan.Snapshot{{SnapshotID: "snap-old", VolumeSizeGiB: 20, StartTime: "2000-01-01T00:00:00Z"}}, nil
}
func (mockClient) DescribeLogGroups(region string) ([]scan.LogGroup, error) {
	b := int64(10 * 1_073_741_824)
	return []scan.LogGroup{{LogGroupName: "/app/prod", StoredBytes: &b}}, nil
}

func TestGuardMutatingDryRun(t *testing.T) {
	SetGuards(false, true)
	blocked, _ := GuardMutatingTool(true)
	if blocked {
		t.Fatal("dry-run should allow mutating tool dispatch")
	}
	SetGuards(false, false)
	blocked, _ = GuardMutatingTool(true)
	if !blocked {
		t.Fatal("expected block without allow-write")
	}
}

func TestRedactSecrets(t *testing.T) {
	got := RedactSecrets("leak ASIAIOSFODNN7EXAMPLE still")
	if got != "leak [REDACTED] still" {
		t.Fatalf("got %q", got)
	}
}

func TestLoopBreaker(t *testing.T) {
	ResetLoopBreaker()
	if CheckLoopBreaker("t", map[string]interface{}{"a": 1}) != "" {
		t.Fatal("first call")
	}
	if CheckLoopBreaker("t", map[string]interface{}{"a": 1}) != "" {
		t.Fatal("second call")
	}
	if !strings.Contains(CheckLoopBreaker("t", map[string]interface{}{"a": 1}), "LOOP_BREAKER") {
		t.Fatal("third call")
	}
}

func TestMCPDryRunPatch(t *testing.T) {
	SetGuards(true, true)
	SetScanClient(mockClient{})
	SetNCtx(4096)
	scanRes, err := handleTool("scan_aws_waste", map[string]interface{}{"regions": []interface{}{"us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if scanRes["totalFindings"] != 6 {
		t.Fatalf("findings %v", scanRes["totalFindings"])
	}
	patchRes, err := handleTool("generate_finops_patch", map[string]interface{}{
		"format":    "terraform",
		"writePath": "/tmp/fix.tf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if patchRes["code"] == nil {
		t.Fatal("expected code")
	}
	if patchRes["written"] != nil {
		t.Fatal("dry-run must not write")
	}
}
