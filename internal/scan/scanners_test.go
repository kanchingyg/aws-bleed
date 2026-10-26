package scan

import (
	"testing"
	"time"
)

type mockClient struct{}

func (mockClient) DescribeNatGateways(region string) ([]NatGateway, error) {
	return []NatGateway{{NatGatewayID: "nat-0abc", VpcID: "vpc-aaa", State: "available"}}, nil
}

func (mockClient) DescribeVpcEndpoints(region string) ([]VpcEndpoint, error) {
	return nil, nil
}

func (mockClient) DescribeVolumes(region string) ([]Volume, error) {
	return []Volume{
		{VolumeID: "vol-gp2", SizeGiB: 100, VolumeType: "gp2", State: "in-use"},
		{VolumeID: "vol-orphan", SizeGiB: 50, VolumeType: "gp3", State: "available"},
	}, nil
}

func (mockClient) DescribeAddresses(region string) ([]Address, error) {
	return []Address{{AllocationID: "eipalloc-1", PublicIP: "203.0.113.10"}}, nil
}

func (mockClient) DescribeSnapshots(region string) ([]Snapshot, error) {
	stale := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return []Snapshot{{SnapshotID: "snap-old", VolumeSizeGiB: 20, StartTime: stale}}, nil
}

func (mockClient) DescribeLogGroups(region string) ([]LogGroup, error) {
	bytes := int64(10 * 1_073_741_824)
	return []LogGroup{{LogGroupName: "/app/prod", StoredBytes: &bytes}}, nil
}

func TestScanAwsWaste(t *testing.T) {
	findings, err := ScanAwsWaste(mockClient{}, []string{"us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	var nat, logs, gp2, avail, eip, snap *Finding
	for i := range findings {
		switch findings[i].Kind {
		case "nat_missing_endpoints":
			nat = &findings[i]
		case "logs_infinite_retention":
			logs = &findings[i]
		case "ebs_gp2":
			gp2 = &findings[i]
		case "ebs_available":
			avail = &findings[i]
		case "eip_unassociated":
			eip = &findings[i]
		case "snapshot_stale":
			snap = &findings[i]
		}
	}
	if nat == nil || nat.MonthlyUSDSaved != Pricing.NATMissingEndpointBleedUSD {
		t.Fatalf("nat finding: %+v", nat)
	}
	if logs == nil || logs.MonthlyUSDSaved != 5 {
		t.Fatalf("logs finding: %+v", logs)
	}
	if gp2 == nil || gp2.MonthlyUSDSaved != 100*Pricing.GP2SurchargePerGBUSD {
		t.Fatalf("gp2 finding: %+v", gp2)
	}
	if avail == nil || avail.MonthlyUSDSaved != 50*Pricing.AvailableVolumePerGBUSD {
		t.Fatalf("avail finding: %+v", avail)
	}
	if eip == nil || eip.MonthlyUSDSaved != Pricing.IdleEIPUSD {
		t.Fatalf("eip finding: %+v", eip)
	}
	if snap == nil || snap.MonthlyUSDSaved != 20*Pricing.SnapshotPerGBUSD {
		t.Fatalf("snap finding: %+v", snap)
	}
	if TotalMonthlyUSD(findings) != 60.65 {
		t.Fatalf("total %v", TotalMonthlyUSD(findings))
	}
}

func TestTruncateMessaging(t *testing.T) {
	findings := make([]Finding, 12)
	for i := range findings {
		findings[i] = Finding{
			ID:              "f-" + itoa(i),
			Kind:            "eip_unassociated",
			Region:          "us-east-1",
			MonthlyUSDSaved: float64(12 - i),
			Evidence:        map[string]interface{}{},
		}
	}
	shown := TruncateFindingsForMcp(findings, 1000)
	if len(shown) >= len(findings) {
		t.Fatalf("expected truncation, got %d", len(shown))
	}
	total := TotalMonthlyUSD(findings)
	totalCount := len(findings)
	table := FormatFindingsTable(shown, &FormatOptions{
		TotalCount:      &totalCount,
		TotalMonthlyUSD: &total,
	})
	if !contains(table, "showing") || !contains(table, "of 12 findings") {
		t.Fatalf("missing truncate line: %s", table)
	}
	if !contains(table, "TOTAL\t\t78") {
		t.Fatalf("missing total: %s", table)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
