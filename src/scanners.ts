/** Heuristic USD/mo estimates (read-only Describe* inventory). */
export const PRICING = {
    NAT_MISSING_ENDPOINT_BLEED_USD: 45,
    LOG_STORAGE_PER_GB_USD: 0.5,
    GP2_SURCHARGE_PER_GB_USD: 0.02,
    AVAILABLE_VOLUME_PER_GB_USD: 0.08,
    IDLE_EIP_USD: 3.65,
    SNAPSHOT_PER_GB_USD: 0.05,
    SNAPSHOT_STALE_DAYS: 90,
};
function roundUsd(n) {
    return Math.round(n * 100) / 100;
}
function hasGatewayEndpoint(endpoints, vpcId, suffix) {
    return endpoints.some((e) => e.vpcId === vpcId &&
        (e.vpcEndpointType === "Gateway" || !e.vpcEndpointType) &&
        e.serviceName.endsWith(suffix));
}
function scanNatBleed(region, nats, endpoints) {
    const out = [];
    for (const nat of nats) {
        if (nat.state && nat.state !== "available")
            continue;
        const missingS3 = !hasGatewayEndpoint(endpoints, nat.vpcId, ".s3");
        const missingDdb = !hasGatewayEndpoint(endpoints, nat.vpcId, ".dynamodb");
        if (!missingS3 && !missingDdb)
            continue;
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
function scanLogs(region, groups) {
    const out = [];
    for (const g of groups) {
        if (g.retentionInDays != null)
            continue;
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
function scanVolumes(region, volumes) {
    const out = [];
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
function scanEips(region, addresses) {
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
function scanSnapshots(region, snaps, now = new Date()) {
    const out = [];
    for (const s of snaps) {
        const ageDays = (now.getTime() - new Date(s.startTime).getTime()) / 86_400_000;
        if (ageDays < PRICING.SNAPSHOT_STALE_DAYS)
            continue;
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
function hashId(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++)
        h = (h * 31 + s.charCodeAt(i)) | 0;
    return Math.abs(h).toString(36);
}
export function truncateFindingsForMcp(findings, nCtx) {
    const maxItems = Math.max(5, Math.floor(nCtx / 200));
    return [...findings].sort((a, b) => b.monthlyUsdSaved - a.monthlyUsdSaved).slice(0, maxItems);
}
export async function scanAwsWaste(client, regions) {
    const all = [];
    for (const region of regions) {
        const [nats, endpoints, volumes, addresses, snapshots, logs] = await Promise.all([
            client.describeNatGateways(region),
            client.describeVpcEndpoints(region),
            client.describeVolumes(region),
            client.describeAddresses(region),
            client.describeSnapshots(region),
            client.describeLogGroups(region),
        ]);
        all.push(...scanNatBleed(region, nats, endpoints), ...scanLogs(region, logs), ...scanVolumes(region, volumes), ...scanEips(region, addresses), ...scanSnapshots(region, snapshots));
    }
    return all.sort((a, b) => b.monthlyUsdSaved - a.monthlyUsdSaved);
}
export function totalMonthlyUsd(findings) {
    return roundUsd(findings.reduce((s, f) => s + f.monthlyUsdSaved, 0));
}
export function formatFindingsTable(findings, options = undefined) {
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
