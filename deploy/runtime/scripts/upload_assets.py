#!/usr/bin/env python3
"""Upload an operator-built asset tree; output the immutable Terraform input."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile

import boto3

parser = argparse.ArgumentParser()
parser.add_argument('--directory', type=Path, required=True)
parser.add_argument('--bucket', required=True)
args = parser.parse_args()
root = args.directory.resolve()
if not (root / 'MANIFEST.json').is_file():
    raise SystemExit('Build the real asset tree first; MANIFEST.json is required.')
with tempfile.TemporaryDirectory(prefix='redsim-asset-upload-') as temp:
    archive = Path(temp) / 'bundle.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root)
            if 'cache' in relative.parts:
                continue
            if path.is_symlink():
                raise ValueError('Asset trees must not contain symlinks')
            if path.is_file():
                bundle.add(path, arcname=str(relative), recursive=False)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    key = f'assets/bundles/{digest}.tar.gz'
    boto3.client('s3', region_name='us-east-1').upload_file(str(archive), args.bucket, key,
        ExtraArgs={'ContentType': 'application/gzip', 'Metadata': {'sha256': digest}})
print(json.dumps({'asset_bundle': {'key': key, 'sha256': digest}}, indent=2))
