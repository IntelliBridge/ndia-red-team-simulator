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
parser.add_argument('--command', help='JSON list overriding the main container command (the assets task '
                    'definition runs seed_project.py and "redsim ml seed" this way; the bundle stays mounted)')
parser.add_argument('--timeout-minutes', type=int, default=20)
args = parser.parse_args()
overrides = {}
if args.command:
    command = json.loads(args.command)
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise SystemExit('--command must be a JSON list of strings')
    overrides = {'containerOverrides': [{'name': args.task, 'command': command}]}
runtime = json.loads(args.runtime_outputs.read_text())['runtime']['value']
client = boto3.client('ecs', region_name='us-east-1')
result = client.run_task(cluster=runtime['cluster_arn'],
    taskDefinition=runtime['task_definitions'][args.task], launchType='FARGATE',
    platformVersion='1.4.0', count=1, startedBy='redsim-runtime-operator', overrides=overrides,
    networkConfiguration={'awsvpcConfiguration': {
        'subnets': runtime['private_subnet_ids'],
        'securityGroups': [runtime['service_security_groups'][args.task]],
        'assignPublicIp': 'DISABLED'}})
if result.get('failures'):
    raise RuntimeError(f"ECS refused the task: {result['failures']}")
arn = result['tasks'][0]['taskArn']
print('Task:', arn, flush=True)
last = None
for _ in range(args.timeout_minutes * 6):
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
