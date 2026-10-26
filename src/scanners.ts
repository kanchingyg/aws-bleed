/**
 * AWS FinOps waste scanner rules for NAT gateways, CloudWatch logs, EBS volumes, idle EIPs, and stale snapshots.
 *
 * @module
 */

/** Category of AWS cost bleed detected by the scanner. */
export type BleedFindingKind =
  | "nat_missing_endpoints"
  | "logs_infinite_retention"
  | "ebs_available"
  | "ebs_gp2"
  | "eip_unassociated"
  | "snapshot_stale";

/** Individual AWS cost bleed finding with estimated monthly savings. */
export interface BleedFinding {
  /** Stable identifier for this finding. */
  id: string;
  /** Waste rule category. */
  kind: BleedFindingKind;
  /** AWS region where the resource resides. */
  region: string;
  /** Estimated USD saved per month after remediation. */
  monthlyUsdSaved: number;
  /** Resource metadata used for Terraform or CLI patch generation. */
  evidence: Record<string, unknown>;
}

/** Minimal NAT Gateway descriptor returned by EC2 DescribeNatGateways. */
export interface NatGatewayItem {
  /** NAT Gateway resource ID. */
  natGatewayId: string;
  /** Parent VPC ID. */
  vpcId: string;
  /** Provisioning state. */
  state?: string;
}

/** Minimal VPC Endpoint descriptor returned by EC2 DescribeVpcEndpoints. */
export interface VpcEndpointItem {
  /** Parent VPC ID. */
  vpcId: string;
  /** AWS service name (for example `com.amazonaws.us-east-1.s3`). */
  serviceName: string;
  /** Endpoint type (`Gateway` or `Interface`). */
  vpcEndpointType?: string;
}

/** Minimal EBS Volume descriptor returned by EC2 DescribeVolumes. */
export interface VolumeItem {
  /** EBS volume ID. */
  volumeId: string;
  /** Provisioned size in GiB. */
  sizeGiB: number;
  /** Volume type (`gp2`, `gp3`, `io1`, etc.). */
  volumeType: string;
  /** Attachment state (`available`, `in-use`, etc.). */
  state: string;
}

/** Minimal Elastic IP descriptor returned by EC2 DescribeAddresses. */
export interface AddressItem {
  /** Elastic IP allocation ID. */
  allocationId: string;
  /** Public IPv4 address. */
  publicIp?: string;
  /** EC2 association ID if attached. */
  associationId?: string;
}

/** Minimal EBS Snapshot descriptor returned by EC2 DescribeSnapshots. */
export interface SnapshotItem {
  /** EBS snapshot ID. */
  snapshotId: string;
  /** Source volume size in GiB. */
  volumeSizeGiB: number;
  /** ISO-8601 snapshot start timestamp. */
  startTime: string;
}

/** Minimal CloudWatch Log Group descriptor returned by DescribeLogGroups. */
export interface LogGroupItem {
  /** Log group name. */
  logGroupName: string;
  /** Configured retention in days, or undefined if never expiring. */
  retentionInDays?: number;
  /** Stored bytes reported by CloudWatch Logs. */
  storedBytes?: number;
}

/** Read-only AWS inventory client interface used by `scanAwsWaste`. */
export interface AwsScanClient {
  /** Lists NAT gateways in the target region. */
  describeNatGateways(region: string): Promise<NatGatewayItem[]>;
  /** Lists VPC endpoints in the target region. */
  describeVpcEndpoints(region: string): Promise<VpcEndpointItem[]>;
  /** Lists EBS volumes in the target region. */
  describeVolumes(region: string): Promise<VolumeItem[]>;
  /** Lists Elastic IP addresses in the target region. */
  describeAddresses(region: string): Promise<AddressItem[]>;
  /** Lists self-owned EBS snapshots in the target region. */
  describeSnapshots(region: string): Promise<SnapshotItem[]>;
  /** Lists CloudWatch log groups in the target region. */
  describeLogGroups(region: string): Promise<LogGroupItem[]>;
}

/** Formatting options for `formatFindingsTable`. */
export interface FormatFindingsOptions {
  /** Total finding count before truncation. */
  totalCount?: number;
  /** Precomputed monthly USD sum across all findings. */
  totalMonthlyUsd?: number;
}

/** Heuristic USD/month pricing constants used for read-only inventory estimation. */
export const PRICING: {
  readonly NAT_MISSING_ENDPOINT_BLEED_USD: number;
  readonly LOG_STORAGE_PER_GB_USD: number;
  readonly GP2_SURCHARGE_PER_GB_USD: number;
  readonly AVAILABLE_VOLUME_PER_GB_USD: number;
  readonly IDLE_EIP_USD: number;
  readonly SNAPSHOT_PER_GB_USD: number;
  readonly SNAPSHOT_STALE_DAYS: number;
} = {
  NAT_MISSING_ENDPOINT_BLEED_USD: 45,
  LOG_STORAGE_PER_GB_USD: 0.5,
  GP2_SURCHARGE_PER_GB_USD: 0.02,
  AVAILABLE_VOLUME_PER_GB_USD: 0.08,
  IDLE_EIP_USD: 3.65,
  SNAPSHOT_PER_GB_USD: 0.05,
  SNAPSHOT_STALE_DAYS: 90,
};

function roundUsd(n: number): number {
  return Math.round(n * 100) / 100;
}

function hasGatewayEndpoint(endpoints: VpcEndpointItem[], vpcId: string, suffix: string): boolean {
  return endpoints.some(
    (e) =>
      e.vpcId === vpcId &&
      (e.vpcEndpointType === "Gateway" || !e.vpcEndpointType) &&
      e.serviceName.endsWith(suffix),
  );
}

function scanNatBleed(region: string, nats: NatGatewayItem[], endpoints: VpcEndpointItem[]): BleedFinding[] {
  const out: BleedFinding[] = [];
  for (const nat of nats) {
    if (nat.state && nat.state !== "available") continue;
    const missingS3 = !hasGatewayEndpoint(endpoints, nat.vpcId, ".s3");
    const missingDdb = !hasGatewayEndpoint(endpoints, nat.vpcId, ".dynamodb");
    if (!missingS3 && !missingDdb) continue;
    out.push({
      id: `nat-${nat.natGatewayId}`,
      kind: "nat_missing_endpoints",
      region,
      monthlyUsdSaved: PRICING.NAT_MISSING_ENDPOINT_BLEED_USD,
      evidence: {
        natGatewayId: nat.natGatewayId,
        vpcId: nat.vpcId,
        missingS3Endpoint: missingS3,
        missingDynamoEndpoint: missingDdb,
      },
    });
  }
  return out;
}

function scanLogs(region: string, groups: LogGroupItem[]): BleedFinding[] {
  const out: BleedFinding[] = [];
  for (const g of groups) {
    if (g.retentionInDays != null) continue;
    const gb = (g.storedBytes ?? 0) / 1_073_741_824;
    const monthly = roundUsd(gb * PRICING.LOG_STORAGE_PER_GB_USD);
    out.push({
      id: `log-${hashId(g.logGroupName)}`,
      kind: "logs_infinite_retention",
      region,
      monthlyUsdSaved: monthly,
      evidence: {
        logGroupName: g.logGroupName,
        storedGiB: roundUsd(gb),
        retentionInDays: null,
      },
    });
  }
  return out;
}

function scanVolumes(region: string, volumes: VolumeItem[]): BleedFinding[] {
  const out: BleedFinding[] = [];
  for (const v of volumes) {
    if (v.state === "available") {
      out.push({
        id: `ebs-avail-${v.volumeId}`,
        kind: "ebs_available",
        region,
        monthlyUsdSaved: roundUsd(v.sizeGiB * PRICING.AVAILABLE_VOLUME_PER_GB_USD),
        evidence: { volumeId: v.volumeId, sizeGiB: v.sizeGiB, state: v.state },
      });
      continue;
    }
    if (v.volumeType === "gp2" && v.state === "in-use") {
      out.push({
        id: `ebs-gp2-${v.volumeId}`,
        kind: "ebs_gp2",
        region,
        monthlyUsdSaved: roundUsd(v.sizeGiB * PRICING.GP2_SURCHARGE_PER_GB_USD),
        evidence: { volumeId: v.volumeId, sizeGiB: v.sizeGiB, volumeType: v.volumeType },
      });
    }
  }
  return out;
}

function scanEips(region: string, addresses: AddressItem[]): BleedFinding[] {
  return addresses
    .filter((a) => !a.associationId)
    .map((a) => ({
      id: `eip-${a.allocationId}`,
      kind: "eip_unassociated",
      region,
      monthlyUsdSaved: PRICING.IDLE_EIP_USD,
      evidence: {
        allocationId: a.allocationId,
        publicIp: a.publicIp ?? "",
      },
    }));
}

function scanSnapshots(region: string, snaps: SnapshotItem[], now: Date = new Date()): BleedFinding[] {
  const out: BleedFinding[] = [];
  for (const s of snaps) {
    const ageDays = (now.getTime() - new Date(s.startTime).getTime()) / 86_400_000;
    if (ageDays < PRICING.SNAPSHOT_STALE_DAYS) continue;
    out.push({
      id: `snap-${s.snapshotId}`,
      kind: "snapshot_stale",
      region,
      monthlyUsdSaved: roundUsd(s.volumeSizeGiB * PRICING.SNAPSHOT_PER_GB_USD),
      evidence: { snapshotId: s.snapshotId, volumeSizeGiB: s.volumeSizeGiB, ageDays: Math.floor(ageDays) },
    });
  }
  return out;
}

function hashId(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}

/** Sorts findings by monthly USD savings and truncates the list to fit the active context window. */
export function truncateFindingsForMcp(findings: BleedFinding[], nCtx: number): BleedFinding[] {
  const maxItems = Math.max(5, Math.floor(nCtx / 200));
  return [...findings].sort((a, b) => b.monthlyUsdSaved - a.monthlyUsdSaved).slice(0, maxItems);
}

/** Runs all read-only waste scanners across the requested AWS regions and sorts findings by savings. */
export async function scanAwsWaste(client: AwsScanClient, regions: string[]): Promise<BleedFinding[]> {
  const all: BleedFinding[] = [];
  for (const region of regions) {
    const [nats, endpoints, volumes, addresses, snapshots, logs] = await Promise.all([
      client.describeNatGateways(region),
      client.describeVpcEndpoints(region),
      client.describeVolumes(region),
      client.describeAddresses(region),
      client.describeSnapshots(region),
      client.describeLogGroups(region),
    ]);
    all.push(
      ...scanNatBleed(region, nats, endpoints),
      ...scanLogs(region, logs),
      ...scanVolumes(region, volumes),
      ...scanEips(region, addresses),
      ...scanSnapshots(region, snapshots),
    );
  }
  return all.sort((a, b) => b.monthlyUsdSaved - a.monthlyUsdSaved);
}

/** Sums the estimated monthly USD savings across a list of findings. */
export function totalMonthlyUsd(findings: BleedFinding[]): number {
  return roundUsd(findings.reduce((s, f) => s + f.monthlyUsdSaved, 0));
}

/** Formats findings as a tab-separated summary table with total monthly bleed. */
export function formatFindingsTable(
  findings: BleedFinding[],
  options?: FormatFindingsOptions,
): string {
  const totalCount = options?.totalCount;
  const lines = ["kind\tregion\tUSD/mo\tid"];
  for (const f of findings) {
    lines.push(`${f.kind}\t${f.region}\t${f.monthlyUsdSaved}\t${f.id}`);
  }
  if (totalCount != null && totalCount > findings.length) {
    lines.push(`# showing ${findings.length} of ${totalCount} findings (sorted by USD/mo)`);
  }
  const bleedTotal = options?.totalMonthlyUsd ?? totalMonthlyUsd(findings);
  lines.push(`TOTAL\t\t${bleedTotal}`);
  return lines.join("\n");
}
