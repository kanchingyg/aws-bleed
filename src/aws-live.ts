/**
 * Read-only AWS SDK v3 inventory adapter for EC2 and CloudWatch Logs.
 *
 * @module
 */
import {
  EC2Client,
  DescribeNatGatewaysCommand,
  DescribeVpcEndpointsCommand,
  DescribeVolumesCommand,
  DescribeAddressesCommand,
  DescribeSnapshotsCommand,
} from "@aws-sdk/client-ec2";
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import type {
  AddressItem,
  AwsScanClient,
  LogGroupItem,
  NatGatewayItem,
  SnapshotItem,
  VolumeItem,
  VpcEndpointItem,
} from "./scanners.js";

/** Paginates an AWS SDK v3 list call using a continuation token callback until exhausted. */
export async function paginateWithToken<T>(
  fetchPage: (token?: string) => Promise<{ items: T[]; nextToken?: string }>,
): Promise<T[]> {
  const all: T[] = [];
  let token: string | undefined;
  do {
    const page = await fetchPage(token);
    all.push(...page.items);
    token = page.nextToken;
  } while (token);
  return all;
}

/** Creates a live read-only AWS inventory client backed by `@aws-sdk/client-ec2` and `@aws-sdk/client-cloudwatch-logs`. */
export function createLiveAwsClient(defaultRegion: string): AwsScanClient {
  const ec2 = new EC2Client({ region: defaultRegion });
  const logs = new CloudWatchLogsClient({ region: defaultRegion });
  const clientFor = (region: string): { ec2: EC2Client; logs: CloudWatchLogsClient } => ({
    ec2: region === defaultRegion ? ec2 : new EC2Client({ region }),
    logs: region === defaultRegion ? logs : new CloudWatchLogsClient({ region }),
  });
  return {
    async describeNatGateways(region: string): Promise<NatGatewayItem[]> {
      const { ec2: c } = clientFor(region);
      return paginateWithToken(async (nextToken) => {
        const res = await c.send(
          new DescribeNatGatewaysCommand(nextToken ? { NextToken: nextToken } : {}),
        );
        return {
          items: (res.NatGateways ?? []).map((n) => ({
            natGatewayId: n.NatGatewayId ?? "",
            vpcId: n.VpcId ?? "",
            state: n.State,
          })),
          nextToken: res.NextToken,
        };
      });
    },
    async describeVpcEndpoints(region: string): Promise<VpcEndpointItem[]> {
      const { ec2: c } = clientFor(region);
      return paginateWithToken(async (nextToken) => {
        const res = await c.send(
          new DescribeVpcEndpointsCommand(nextToken ? { NextToken: nextToken } : {}),
        );
        return {
          items: (res.VpcEndpoints ?? []).map((e) => ({
            vpcId: e.VpcId ?? "",
            serviceName: e.ServiceName ?? "",
            vpcEndpointType: e.VpcEndpointType,
          })),
          nextToken: res.NextToken,
        };
      });
    },
    async describeVolumes(region: string): Promise<VolumeItem[]> {
      const { ec2: c } = clientFor(region);
      return paginateWithToken(async (nextToken) => {
        const res = await c.send(
          new DescribeVolumesCommand(nextToken ? { NextToken: nextToken } : {}),
        );
        return {
          items: (res.Volumes ?? []).map((v) => ({
            volumeId: v.VolumeId ?? "",
            sizeGiB: v.Size ?? 0,
            volumeType: v.VolumeType ?? "gp3",
            state: v.State ?? "",
          })),
          nextToken: res.NextToken,
        };
      });
    },
    async describeAddresses(region: string): Promise<AddressItem[]> {
      const { ec2: c } = clientFor(region);
      const res = await c.send(new DescribeAddressesCommand({}));
      return (res.Addresses ?? []).map((a) => ({
        allocationId: a.AllocationId ?? "",
        publicIp: a.PublicIp,
        associationId: a.AssociationId,
      }));
    },
    async describeSnapshots(region: string): Promise<SnapshotItem[]> {
      const { ec2: c } = clientFor(region);
      return paginateWithToken(async (nextToken) => {
        const res = await c.send(
          new DescribeSnapshotsCommand(
            nextToken
              ? { OwnerIds: ["self"], NextToken: nextToken }
              : { OwnerIds: ["self"] },
          ),
        );
        return {
          items: (res.Snapshots ?? []).map((s) => ({
            snapshotId: s.SnapshotId ?? "",
            volumeSizeGiB: s.VolumeSize ?? 0,
            startTime: s.StartTime?.toISOString() ?? new Date(0).toISOString(),
          })),
          nextToken: res.NextToken,
        };
      });
    },
    async describeLogGroups(region: string): Promise<LogGroupItem[]> {
      const { logs: c } = clientFor(region);
      return paginateWithToken(async (nextToken) => {
        const res = await c.send(
          new DescribeLogGroupsCommand(nextToken ? { nextToken } : {}),
        );
        return {
          items: (res.logGroups ?? []).map((g) => ({
            logGroupName: g.logGroupName ?? "",
            retentionInDays: g.retentionInDays,
            storedBytes: g.storedBytes,
          })),
          nextToken: res.nextToken,
        };
      });
    },
  };
}
