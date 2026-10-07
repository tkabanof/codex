"""A bounded, ephemeral filesystem with authenticated, opaque backing objects.

There is intentionally no reopen/key-export API. Each instance has a new key and
private namespace. Plaintext names are serialized *inside* authenticated records;
only random object IDs occur in backing paths. No plaintext staging files exist.
This is a small-file implementation: an edit decrypts/re-encrypts the whole file.
"""

import errno
import json
import os
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path, PureWindowsPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CXTEMP01"
DIRECTORY = 0x10
ARCHIVE = 0x20


class StorageFailure(OSError):
    """An integrity or backing-storage failure permanently faults this mount."""


def synchronized(fn):
    @wraps(fn)
    def call(self, *args, **kwargs):
        with self.lock:
            self.check()
            return fn(self, *args, **kwargs)

    return call


def now():
    return time.time_ns() // 100 + 116444736000000000


def path_of(value):
    text = str(value).replace("/", "\\")
    if (
        not text.startswith("\\")
        or text.startswith("\\\\")
        or len(text.encode("utf-16-le")) > 8192
    ):
        raise ValueError("Expected a volume-relative path")
    parts = text.split("\\")[1:]
    if any(
        p in (".", "..")
        or any(c in p for c in ':*?"<>|\x00')
        or len(p.encode("utf-16-le")) > 510
        for p in parts
    ):
        raise ValueError("Unsupported path or stream name")
    return PureWindowsPath(text)


@dataclass(eq=False)
class Node:
    path: PureWindowsPath
    directory: bool
    oid: str = field(default_factory=lambda: uuid.uuid4().hex)
    size: int = 0
    attributes: int = 0
    creation_time: int = field(default_factory=now)
    last_access_time: int = field(default_factory=now)
    last_write_time: int = field(default_factory=now)
    change_time: int = field(default_factory=now)
    revision: int = 0
    handles: int = 0
    deleted: bool = False
    index: int = 0

    def info(self):
        return {
            "file_attributes": self.attributes,
            "file_size": self.size,
            "allocation_size": 0
            if self.directory
            else (self.size + 4095) // 4096 * 4096,
            "creation_time": self.creation_time,
            "last_access_time": self.last_access_time,
            "last_write_time": self.last_write_time,
            "change_time": self.change_time,
            "index_number": self.index,
        }


class Store:
    def __init__(
        self,
        backing,
        max_file_size=64 * 1024**2,
        capacity=512 * 1024**2,
        max_nodes=10000,
    ):
        if max_file_size <= 0 or capacity < max_file_size or max_nodes < 2:
            raise ValueError("Invalid store limits")
        self.lock = threading.RLock()
        self.failed = False
        self.closed = False
        self.max_file_size = max_file_size
        self.capacity = capacity
        self.max_nodes = max_nodes
        self.used = 0
        self._nonce = 0
        self._cipher = AESGCM(AESGCM.generate_key(bit_length=256))
        backing = Path(backing).resolve()
        backing.mkdir(parents=True, exist_ok=True)
        self.directory = backing / ("session-" + uuid.uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.root = Node(PureWindowsPath("\\"), True, attributes=DIRECTORY, index=1)
        self.entries = {self.root.path: self.root}
        self.objects = {self.root.oid: self.root}
        self._index = 1
        self._save(self.root, b"")

    def check(self):
        if self.failed or self.closed:
            raise StorageFailure(errno.EIO, "Encrypted temporary store is unavailable")

    def _fault(self):
        self.failed = True
        return StorageFailure(
            errno.EIO, "Encrypted temporary storage failed; no fallback"
        )

    def _object_path(self, node):
        return self.directory / (node.oid + ".bin")

    def _aad(self, node, revision):
        return MAGIC + bytes.fromhex(node.oid) + revision.to_bytes(8, "big")

    def _save(self, node, content):
        # The monotonic 96-bit nonce is never reset under a key, even on failed writes.
        self._nonce += 1
        if self._nonce >= 2**96:
            raise self._fault()
        nonce = self._nonce.to_bytes(12, "big")
        revision = node.revision + 1
        metadata = json.dumps(
            {"path": str(node.path), "info": node.info()},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        plaintext = struct.pack(">I", len(metadata)) + metadata + content
        encrypted = (
            MAGIC
            + nonce
            + self._cipher.encrypt(nonce, plaintext, self._aad(node, revision))
        )
        staging = self.directory / (uuid.uuid4().hex + ".part")
        try:
            # Write ciphertext only, then atomically replace the previous object.
            with staging.open("xb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(staging, self._object_path(node))
            node.revision = revision
        except OSError:
            raise self._fault() from None
        finally:
            try:
                staging.unlink(missing_ok=True)
            except OSError:
                pass  # An orphan contains ciphertext only.

    def _load(self, node):
        try:
            # Bound reads before parsing a potentially corrupted object.
            with self._object_path(node).open("rb") as stream:
                data = stream.read(self.max_file_size + 65537)
            if len(data) > self.max_file_size + 65536 or data[:8] != MAGIC:
                raise ValueError("Invalid encrypted record")
            plain = self._cipher.decrypt(
                data[8:20], data[20:], self._aad(node, node.revision)
            )
            length = struct.unpack(">I", plain[:4])[0]
            meta = json.loads(plain[4 : 4 + length])
            content = plain[4 + length :]
            if meta["path"] != str(node.path) or len(content) != node.size:
                raise ValueError("Record does not match live metadata")
            return content
        except (OSError, InvalidTag, ValueError, KeyError, struct.error):
            raise self._fault() from None

    def _node(self, node):
        if self.objects.get(node.oid) is not node:
            raise FileNotFoundError(errno.ENOENT, "Closed file")

    def _file(self, node):
        self._node(node)
        if node.directory:
            raise IsADirectoryError(errno.EISDIR, "Expected file")

    def _limit(self, node, size):
        if size < 0:
            raise ValueError("Negative size")
        if size > self.max_file_size or self.used - node.size + size > self.capacity:
            raise OSError(errno.ENOSPC, "Encrypted temporary storage quota exceeded")

    @synchronized
    def lookup(self, path):
        try:
            return self.entries[path_of(path)]
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, "File not found") from None

    @synchronized
    def open(self, path):
        node = self.lookup(path)
        node.handles += 1
        return node

    @synchronized
    def create(self, path, directory=False, attributes=0):
        path = path_of(path)
        if path in self.entries:
            raise FileExistsError(errno.EEXIST, "File exists")
        parent = self.lookup(path.parent)
        if not parent.directory:
            raise NotADirectoryError(errno.ENOTDIR, "Parent is not a directory")
        if len(self.objects) >= self.max_nodes:
            raise OSError(errno.ENOSPC, "Too many temporary files")
        self._index += 1
        node = Node(
            path,
            directory,
            attributes=(attributes & ~DIRECTORY)
            | (DIRECTORY if directory else ARCHIVE),
            handles=1,
            index=self._index,
        )
        self._save(node, b"")
        self.entries[path] = node
        self.objects[node.oid] = node
        return node

    @synchronized
    def read(self, node, offset, length):
        self._file(node)
        if offset < 0 or length < 0:
            raise ValueError("Negative read range")
        return self._load(node)[offset : offset + length]

    @synchronized
    def write(self, node, data, offset, append=False, constrained=False):
        self._file(node)
        if offset < 0:
            raise ValueError("Negative write offset")
        offset = node.size if append else offset
        if constrained:
            data = data[: max(0, node.size - offset)]
        if not data:
            return 0
        size = max(node.size, offset + len(data))
        self._limit(node, size)
        content = bytearray(self._load(node))
        content.extend(bytes(size - len(content)))
        content[offset : offset + len(data)] = data
        self.used += size - node.size
        node.size = size
        node.change_time = node.last_write_time = now()
        self._save(node, bytes(content))
        return len(data)

    @synchronized
    def resize(self, node, size, allocation_only=False):
        self._file(node)
        self._limit(node, size)
        if allocation_only and size >= node.size:
            return  # Logical allocation; sparse zeroes materialize on extension.
        content = self._load(node)
        content = content[:size] + bytes(max(0, size - len(content)))
        self.used += size - node.size
        node.size = size
        node.change_time = node.last_write_time = now()
        self._save(node, content)

    @synchronized
    def update_info(self, node, attributes=None, **times):
        self._node(node)
        content = self._load(node)
        if attributes is not None:
            node.attributes = (attributes & ~DIRECTORY) | (
                DIRECTORY if node.directory else 0
            )
        for name in (
            "creation_time",
            "last_access_time",
            "last_write_time",
            "change_time",
        ):
            if times.get(name):
                setattr(node, name, times[name])
        self._save(node, content)

    @synchronized
    def children(self, node):
        self._node(node)
        if not node.directory:
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory")
        return sorted(
            (
                n
                for p, n in self.entries.items()
                if p != node.path and p.parent == node.path
            ),
            key=lambda n: n.path.name.upper(),
        )

    @synchronized
    def can_delete(self, node):
        self._node(node)
        if node is self.root:
            raise PermissionError(errno.EACCES, "Cannot delete root")
        if node.directory and self.children(node):
            raise OSError(errno.ENOTEMPTY, "Directory is not empty")

    def _purge(self, node):
        try:
            self._object_path(node).unlink()
        except OSError:
            raise self._fault() from None
        self.used -= node.size
        del self.objects[node.oid]

    @synchronized
    def delete(self, node):
        if node.deleted:
            return
        self.can_delete(node)
        del self.entries[node.path]
        node.deleted = True
        if not node.handles:
            self._purge(node)

    @synchronized
    def close_handle(self, node):
        self._node(node)
        if node.handles <= 0:
            raise ValueError("Handle already closed")
        node.handles -= 1
        if node.deleted and not node.handles:
            self._purge(node)

    @synchronized
    def rename(self, node, target, replace=False):
        self._node(node)
        target = path_of(target)
        if node is self.root or node.deleted or target == self.root.path:
            raise PermissionError(errno.EACCES, "Cannot rename this entry")
        parent = self.lookup(target.parent)
        if not parent.directory:
            raise NotADirectoryError(errno.ENOTDIR, "Parent is not a directory")
        if node.directory and node.path in target.parents:
            raise PermissionError(errno.EACCES, "Cannot move directory into itself")
        previous = self.entries.get(target)
        if previous is not None and previous is not node:
            if not replace:
                raise FileExistsError(errno.EEXIST, "Destination exists")
            if node.directory or previous.directory:
                raise PermissionError(errno.EACCES, "Cannot replace a directory")
            self.delete(previous)
        moving = [
            n for n in self.entries.values() if n is node or node.path in n.path.parents
        ]
        old_path = node.path
        for entry in moving:
            content = self._load(entry)
            del self.entries[entry.path]
            entry.path = target / entry.path.relative_to(old_path)
            self._save(entry, content)
            self.entries[entry.path] = entry

    def shutdown(self):
        """Drop key references. Python cannot promise physical memory erasure."""
        with self.lock:
            self.closed = True
            self._cipher = None
            self.entries.clear()
            self.objects.clear()
