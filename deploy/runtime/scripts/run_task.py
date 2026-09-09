#!/usr/bin/env python3
"""Run an explicitly selected one-off task and require successful container exit."""
import argparse
import json
import time
from pathlib import Path

import boto3

parser = argparse.ArgumentParser()
parser.add_argument('--runtime-outputs', type=Path, required=True)
parser.add_argument('--task', choices=['migration', 'assets'], required=True)
args = parser.parse_args()
runtime = json.loads(args.runtime_outputs.read_text())['runtime']['value']
client = boto3.client('ecs', region_name='us-east-1')
result = client.run_task(cluster=runtime['cluster_arn'],
    taskDefinition=runtime['task_definitions'][args.task], launchType='FARGATE',
    platformVersion='1.4.0', count=1, startedBy='redsim-runtime-operator',
    networkConfiguration={'awsvpcConfiguration': {
        'subnets': runtime['private_subnet_ids'],
        'securityGroups': [runtime['service_security_groups'][args.task]],
        'assignPublicIp': 'DISABLED'}})
if result.get('failures'):
    raise RuntimeError(f"ECS refused the task: {result['failures']}")
arn = result['tasks'][0]['taskArn']
print('Task:', arn, flush=True)
last = None
for _ in range(120):
    task = client.describe_tasks(cluster=runtime['cluster_arn'], tasks=[arn])['tasks'][0]
    status = task['lastStatus']
    if status != last:
        print('Status:', status, flush=True)
        last = status
    if status == 'STOPPED':
        containers = task['containers']
        if not containers or any(container.get('exitCode') != 0 for container in containers):
            raise RuntimeError(f"Task failed: {task.get('stoppedReason')}; " +
                ', '.join(f"{c['name']}: {c.get('exitCode', 'no exit code')} {c.get('reason', '')}" for c in containers))
        print('All containers exited successfully.')
        break
    time.sleep(10)
else:
    raise RuntimeError(f'Task {arn} has not stopped; inspect it before retrying.')
