package terraform

import (
	"strings"
	"testing"

	"github.com/kanchingyg/aws-bleed/internal/scan"
)

func TestEscapeHclString(t *testing.T) {
	got := EscapeHclString(`a"b\c`)
	want := `a\"b\\c`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestGenerateTerraformPatch(t *testing.T) {
	findings := []scan.Finding{
		{
			ID: "nat-1", Kind: "nat_missing_endpoints", Region: "us-east-1", MonthlyUSDSaved: 45,
			Evidence: map[string]interface{}{
				"vpcId": "vpc-aaa", "missingS3Endpoint": true, "missingDynamoEndpoint": true,
			},
		},
		{
			ID: "log-x", Kind: "logs_infinite_retention", Region: "us-east-1", MonthlyUSDSaved: 1,
			Evidence: map[string]interface{}{"logGroupName": `/app/"prod"`, "storedGiB": 1},
		},
		{
			ID: "gp2-1", Kind: "ebs_gp2", Region: "us-east-1", MonthlyUSDSaved: 2,
			Evidence: map[string]interface{}{"volumeId": "vol-gp2", "sizeGiB": 100},
		},
	}
	hcl := GenerateFinopsPatch(findings, "terraform", nil)
	if !strings.Contains(hcl, `resource "aws_vpc_endpoint"`) {
		t.Fatal("missing vpc endpoint")
	}
	if !strings.Contains(hcl, "com.amazonaws.us-east-1.s3") {
		t.Fatal("missing s3 service")
	}
	if !strings.Contains(hcl, "retention_in_days = 30") {
		t.Fatal("missing retention")
	}
	if !strings.Contains(hcl, `name              = "/app/\"prod\""`) {
		t.Fatalf("escape failed: %s", hcl)
	}
	if !strings.Contains(hcl, `type              = "gp3"`) {
		t.Fatal("missing gp3")
	}
}
