package scan

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Pricing holds heuristic USD/mo constants (read-only Describe* inventory).
var Pricing = struct {
	NATMissingEndpointBleedUSD float64
	LogStoragePerGBUSD         float64
	GP2SurchargePerGBUSD       float64
	AvailableVolumePerGBUSD    float64
	IdleEIPUSD                 float64
	SnapshotPerGBUSD           float64
	SnapshotStaleDays          float64
}{
	NATMissingEndpointBleedUSD: 45,
	LogStoragePerGBUSD:         0.5,
	GP2SurchargePerGBUSD:       0.02,
	AvailableVolumePerGBUSD:    0.08,
	IdleEIPUSD:                 3.65,
	SnapshotPerGBUSD:           0.05,
	SnapshotStaleDays:          90,
}

func roundUSD(n float64) float64 {
	return math.Round(n*100) / 100
}

func hasGatewayEndpoint(endpoints []VpcEndpoint, vpcID, suffix string) bool {
	for _, e := range endpoints {
		typ := e.VpcEndpointType
		if typ == "" || typ == "Gateway" {
			if e.VpcID == vpcID && strings.HasSuffix(e.ServiceName, suffix) {
				return true
			}
		}
	}
	return false
}

func scanNatBleed(region string, nats []NatGateway, endpoints []VpcEndpoint) []Finding {
	var out []Finding
	for _, nat := range nats {
		if nat.State != "" && nat.State != "available" {
			continue
		}
		missingS3 := !hasGatewayEndpoint(endpoints, nat.VpcID, ".s3")
		missingDdb := !hasGatewayEndpoint(endpoints, nat.VpcID, ".dynamodb")
		if !missingS3 && !missingDdb {
			continue
		}
		out = append(out, Finding{
			ID:              "nat-" + nat.NatGatewayID,
			Kind:            "nat_missing_endpoints",
			Region:          region,
			MonthlyUSDSaved: Pricing.NATMissingEndpointBleedUSD,
			Evidence: map[string]interface{}{
				"natGatewayId":          nat.NatGatewayID,
				"vpcId":                 nat.VpcID,
				"missingS3Endpoint":     missingS3,
				"missingDynamoEndpoint": missingDdb,
			},
		})
	}
	return out
}

func scanLogs(region string, groups []LogGroup) []Finding {
	var out []Finding
	for _, g := range groups {
		if g.RetentionInDays != nil {
			continue
		}
		stored := float64(0)
		if g.StoredBytes != nil {
			stored = float64(*g.StoredBytes)
		}
		gb := stored / 1_073_741_824
		monthly := roundUSD(gb * Pricing.LogStoragePerGBUSD)
		out = append(out, Finding{
			ID:              "log-" + hashID(g.LogGroupName),
			Kind:            "logs_infinite_retention",
			Region:          region,
			MonthlyUSDSaved: monthly,
			Evidence: map[string]interface{}{
				"logGroupName":    g.LogGroupName,
				"storedGiB":       roundUSD(gb),
				"retentionInDays": nil,
			},
		})
	}
	return out
}

func scanVolumes(region string, volumes []Volume) []Finding {
	var out []Finding
	for _, v := range volumes {
		if v.State == "available" {
			out = append(out, Finding{
				ID:              "ebs-avail-" + v.VolumeID,
				Kind:            "ebs_available",
				Region:          region,
				MonthlyUSDSaved: roundUSD(float64(v.SizeGiB) * Pricing.AvailableVolumePerGBUSD),
				Evidence: map[string]interface{}{
					"volumeId": v.VolumeID,
					"sizeGiB":  v.SizeGiB,
					"state":    v.State,
				},
			})
			continue
		}
		if v.VolumeType == "gp2" && v.State == "in-use" {
			out = append(out, Finding{
				ID:              "ebs-gp2-" + v.VolumeID,
				Kind:            "ebs_gp2",
				Region:          region,
				MonthlyUSDSaved: roundUSD(float64(v.SizeGiB) * Pricing.GP2SurchargePerGBUSD),
				Evidence: map[string]interface{}{
					"volumeId":   v.VolumeID,
					"sizeGiB":    v.SizeGiB,
					"volumeType": v.VolumeType,
				},
			})
		}
	}
	return out
}

func scanEips(region string, addresses []Address) []Finding {
	var out []Finding
	for _, a := range addresses {
		if a.AssociationID != nil && *a.AssociationID != "" {
			continue
		}
		pub := a.PublicIP
		out = append(out, Finding{
			ID:              "eip-" + a.AllocationID,
			Kind:            "eip_unassociated",
			Region:          region,
			MonthlyUSDSaved: Pricing.IdleEIPUSD,
			Evidence: map[string]interface{}{
				"allocationId": a.AllocationID,
				"publicIp":     pub,
			},
		})
	}
	return out
}

func scanSnapshots(region string, snaps []Snapshot, now time.Time) []Finding {
	var out []Finding
	for _, s := range snaps {
		start, err := time.Parse(time.RFC3339, s.StartTime)
		if err != nil {
			start = time.Time{}
		}
		ageDays := now.Sub(start).Hours() / 24
		if ageDays < Pricing.SnapshotStaleDays {
			continue
		}
		out = append(out, Finding{
			ID:              "snap-" + s.SnapshotID,
			Kind:            "snapshot_stale",
			Region:          region,
			MonthlyUSDSaved: roundUSD(float64(s.VolumeSizeGiB) * Pricing.SnapshotPerGBUSD),
			Evidence: map[string]interface{}{
				"snapshotId":    s.SnapshotID,
				"volumeSizeGiB": s.VolumeSizeGiB,
				"ageDays":       int(ageDays),
			},
		})
	}
	return out
}

func hashID(s string) string {
	var h int32
	for i := 0; i < len(s); i++ {
		h = h*31 + int32(s[i])
	}
	abs := int64(h)
	if abs < 0 {
		abs = -abs
	}
	return strconvBase36(abs)
}

func strconvBase36(n int64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	var out []byte
	for n > 0 {
		out = append([]byte{digits[n%36]}, out...)
		n /= 36
	}
	return string(out)
}

// TruncateFindingsForMcp keeps top items by USD/mo for context limits.
func TruncateFindingsForMcp(findings []Finding, nCtx int) []Finding {
	maxItems := int(math.Max(5, math.Floor(float64(nCtx)/200)))
	sorted := append([]Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].MonthlyUSDSaved > sorted[j].MonthlyUSDSaved
	})
	if len(sorted) > maxItems {
		sorted = sorted[:maxItems]
	}
	return sorted
}

// ScanAwsWaste runs heuristics across regions using a read-only client.
func ScanAwsWaste(client Client, regions []string) ([]Finding, error) {
	var all []Finding
	now := time.Now().UTC()
	for _, region := range regions {
		nats, err := client.DescribeNatGateways(region)
		if err != nil {
			return nil, err
		}
		endpoints, err := client.DescribeVpcEndpoints(region)
		if err != nil {
			return nil, err
		}
		volumes, err := client.DescribeVolumes(region)
		if err != nil {
			return nil, err
		}
		addresses, err := client.DescribeAddresses(region)
		if err != nil {
			return nil, err
		}
		snapshots, err := client.DescribeSnapshots(region)
		if err != nil {
			return nil, err
		}
		logs, err := client.DescribeLogGroups(region)
		if err != nil {
			return nil, err
		}
		all = append(all, scanNatBleed(region, nats, endpoints)...)
		all = append(all, scanLogs(region, logs)...)
		all = append(all, scanVolumes(region, volumes)...)
		all = append(all, scanEips(region, addresses)...)
		all = append(all, scanSnapshots(region, snapshots, now)...)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].MonthlyUSDSaved > all[j].MonthlyUSDSaved
	})
	return all, nil
}

// TotalMonthlyUSD sums finding estimates.
func TotalMonthlyUSD(findings []Finding) float64 {
	var sum float64
	for _, f := range findings {
		sum += f.MonthlyUSDSaved
	}
	return roundUSD(sum)
}

// FormatOptions controls honest truncate messaging in tables.
type FormatOptions struct {
	TotalCount      *int
	TotalMonthlyUSD *float64
}

// FormatFindingsTable renders TSV with optional "showing N of M" footer.
func FormatFindingsTable(findings []Finding, opts *FormatOptions) string {
	var lines []string
	lines = append(lines, "kind\tregion\tUSD/mo\tid")
	for _, f := range findings {
		lines = append(lines, strings.Join([]string{
			f.Kind,
			f.Region,
			formatFloat(f.MonthlyUSDSaved),
			f.ID,
		}, "\t"))
	}
	if opts != nil && opts.TotalCount != nil && *opts.TotalCount > len(findings) {
		lines = append(lines, "# showing "+itoa(len(findings))+" of "+itoa(*opts.TotalCount)+" findings (sorted by USD/mo)")
	}
	bleedTotal := TotalMonthlyUSD(findings)
	if opts != nil && opts.TotalMonthlyUSD != nil {
		bleedTotal = *opts.TotalMonthlyUSD
	}
	lines = append(lines, "TOTAL\t\t"+formatFloat(bleedTotal))
	return strings.Join(lines, "\n")
}

func formatFloat(n float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", n), "0"), ".")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
