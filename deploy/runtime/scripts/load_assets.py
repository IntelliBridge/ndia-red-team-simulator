"""Load a pinned asset bundle into task-local storage without importing ML."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import tarfile
import tempfile


def unpack(archive, destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if sum(member.size for member in members) > 20 * 1024**3:
            raise ValueError('Asset bundle exceeds the 20 GiB extracted limit')
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Asset bundle contains an unsafe path or non-regular member')
        bundle.extractall(root, members=members, filter='data')
    if not (root / 'MANIFEST.json').is_file():
        raise ValueError('Asset bundle has no MANIFEST.json')


def main():
    import boto3
    key = os.environ.get('REDSIM_ASSET_BUNDLE_KEY')
    expected = os.environ.get('REDSIM_ASSET_BUNDLE_SHA256')
    if not key or not expected:
        raise RuntimeError('No pinned asset bundle configured; build and upload approved assets first')
    with tempfile.TemporaryDirectory(prefix='redsim-assets-') as temp:
        archive = Path(temp) / 'bundle.tar.gz'
        boto3.client('s3', region_name='us-east-1').download_file(os.environ['REDSIM_S3_BUCKET'], key, str(archive))
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('Asset bundle SHA-256 mismatch')
        unpack(archive, os.environ['REDSIM_ML_ASSETS_DIR'])
    print('Pinned asset bundle loaded.')


if __name__ == '__main__':
    main()
