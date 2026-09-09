import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('load_assets', Path(__file__).parents[1] / 'scripts/load_assets.py')
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)


class AssetBundleTests(unittest.TestCase):
    def archive(self, root, name, kind=tarfile.REGTYPE):
        archive = root / 'test.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 2 if kind == tarfile.REGTYPE else 0
            member.linkname = '../outside'
            stream.addfile(member, io.BytesIO(b'{}') if member.size else None)
        return archive

    def test_regular_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            loader.unpack(self.archive(root, 'MANIFEST.json'), root / 'out')
            self.assertEqual((root / 'out/MANIFEST.json').read_text(), '{}')

    def test_refuses_traversal_and_links(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/outside', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with self.assertRaises(ValueError):
                    loader.unpack(self.archive(root, name, kind), root / 'out')

    def test_requires_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, 'MANIFEST'):
                loader.unpack(self.archive(root, 'model.json'), root / 'out')
