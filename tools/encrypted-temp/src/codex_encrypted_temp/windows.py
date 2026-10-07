"""WinFsp adapter. No paths or file contents are logged by this module."""

import csv
import errno
import re
import subprocess
from functools import wraps

from winfspy import (
    CREATE_FILE_CREATE_OPTIONS,
    BaseFileSystemOperations,
    FileSystem,
    NTStatusEndOfFile,
    NTStatusError,
)
from winfspy.plumbing.security_descriptor import SecurityDescriptor

from .store import ARCHIVE, now

FS_NAME = "CodexTempCrypt"
VOLUME_LABEL = "Codex encrypted temp"


def operation(fn):
    @wraps(fn)
    def call(self, *args, **kwargs):
        try:
            with self.store.lock:
                self.store.check()
                return fn(self, *args, **kwargs)
        except OSError as exc:
            status = {
                errno.ENOENT: 0xC0000034,
                errno.EEXIST: 0xC0000035,
                errno.ENOTDIR: 0xC0000103,
                errno.EISDIR: 0xC00000BA,
                errno.ENOTEMPTY: 0xC0000101,
                errno.ENOSPC: 0xC000007F,
                errno.EACCES: 0xC0000022,
            }.get(exc.errno, 0xC0000185)
            raise NTStatusError(status) from None
        except ValueError:
            raise NTStatusError(0xC000000D) from None

    return call


def owner_security():
    # Use the SID, not a localized account name. Do not grant Everyone access.
    result = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
        text=True,
    )
    sid = next(iter(csv.reader(result.stdout.splitlines())))[-1]
    if not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid):
        raise RuntimeError("Cannot determine current user SID")
    return SecurityDescriptor.from_string(
        f"O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
    )


class Operations(BaseFileSystemOperations):
    def __init__(self, store):
        super().__init__()
        self.store = store
        self.security = {store.root.oid: owner_security()}

    @operation
    def get_volume_info(self):
        return {
            "total_size": self.store.capacity,
            "free_size": self.store.capacity - self.store.used,
            "volume_label": VOLUME_LABEL,
        }

    @operation
    def set_volume_label(self, volume_label):
        raise NTStatusError(0xC0000022)

    @operation
    def get_security_by_name(self, file_name):
        node = self.store.lookup(file_name)
        security = self.security[node.oid]
        return node.attributes, security.handle, security.size

    @operation
    def get_security(self, file_context):
        return self.security[file_context.oid]

    @operation
    def set_security(self, file_context, security_information, modification_descriptor):
        self.security[file_context.oid] = self.security[file_context.oid].evolve(
            security_information, modification_descriptor
        )

    @operation
    def create(
        self,
        file_name,
        create_options,
        granted_access,
        file_attributes,
        security_descriptor,
        allocation_size,
    ):
        if allocation_size > self.store.max_file_size:
            raise OSError(errno.ENOSPC, "Allocation exceeds temporary file limit")
        directory = bool(
            create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE
        )
        node = self.store.create(file_name, directory, file_attributes)
        self.security[node.oid] = (
            security_descriptor or self.security[self.store.root.oid]
        )
        return node

    @operation
    def open(self, file_name, create_options, granted_access):
        node = self.store.lookup(file_name)
        if (
            create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE
            and not node.directory
        ):
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory")
        if (
            create_options & CREATE_FILE_CREATE_OPTIONS.FILE_NON_DIRECTORY_FILE
            and node.directory
        ):
            raise IsADirectoryError(errno.EISDIR, "Not a file")
        return self.store.open(file_name)

    @operation
    def close(self, file_context):
        self.store.close_handle(file_context)
        if file_context.oid not in self.store.objects:
            self.security.pop(file_context.oid, None)

    @operation
    def get_file_info(self, file_context):
        return file_context.info()

    @operation
    def read(self, file_context, offset, length):
        if length and offset >= file_context.size:
            raise NTStatusEndOfFile()
        return self.store.read(file_context, offset, length)

    @operation
    def write(self, file_context, buffer, offset, write_to_end_of_file, constrained_io):
        return self.store.write(
            file_context, buffer, offset, write_to_end_of_file, constrained_io
        )

    @operation
    def set_file_size(self, file_context, new_size, set_allocation_size):
        self.store.resize(file_context, new_size, set_allocation_size)

    @operation
    def overwrite(
        self, file_context, file_attributes, replace_file_attributes, allocation_size
    ):
        if allocation_size > self.store.max_file_size:
            raise OSError(errno.ENOSPC, "Allocation exceeds temporary file limit")
        self.store.resize(file_context, 0)
        attributes = (
            file_attributes
            if replace_file_attributes
            else file_context.attributes | file_attributes
        )
        self.store.update_info(file_context, attributes | ARCHIVE)

    @operation
    def set_basic_info(
        self,
        file_context,
        file_attributes,
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        file_info,
    ):
        self.store.update_info(
            file_context,
            None if file_attributes == 0xFFFFFFFF else file_attributes,
            creation_time=creation_time,
            last_access_time=last_access_time,
            last_write_time=last_write_time,
            change_time=change_time,
        )
        return file_context.info()

    @operation
    def flush(self, file_context):
        # All successful mutations have already fsync'ed their ciphertext.
        pass

    @operation
    def can_delete(self, file_context, file_name):
        self.store.can_delete(file_context)

    @operation
    def cleanup(self, file_context, file_name, flags):
        if flags & 0x01:  # FspCleanupDelete; open handles keep the object alive.
            self.store.delete(file_context)
            return
        changes = {}
        if flags & 0x20:
            changes["last_access_time"] = now()
        if flags & 0x40:
            changes["last_write_time"] = now()
        if flags & 0x80:
            changes["change_time"] = now()
        attributes = file_context.attributes | ARCHIVE if flags & 0x10 else None
        if changes or attributes is not None:
            self.store.update_info(file_context, attributes, **changes)

    @operation
    def rename(self, file_context, file_name, new_file_name, replace_if_exists):
        self.store.rename(file_context, new_file_name, replace_if_exists)

    @operation
    def read_directory(self, file_context, marker):
        children = self.store.children(file_context)
        entries = []
        if file_context is not self.store.root:
            entries = [
                dict(file_name=".", **file_context.info()),
                dict(
                    file_name="..", **self.store.lookup(file_context.path.parent).info()
                ),
            ]
        entries.extend(dict(file_name=n.path.name, **n.info()) for n in children)
        entries.sort(key=lambda entry: entry["file_name"].upper())
        return [
            e
            for e in entries
            if marker is None or e["file_name"].upper() > marker.upper()
        ]

    @operation
    def get_dir_info_by_name(self, file_context, file_name):
        if not file_context.directory:
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory")
        node = self.store.lookup(file_context.path / file_name)
        return dict(file_name=node.path.name, **node.info())


def mount(store, drive):
    filesystem = FileSystem(
        drive,
        Operations(store),
        sector_size=512,
        sectors_per_allocation_unit=8,
        volume_creation_time=now(),
        volume_serial_number=int(store.root.oid[:8], 16),
        file_info_timeout=0,
        case_sensitive_search=0,
        case_preserved_names=1,
        unicode_on_disk=1,
        persistent_acls=1,
        post_cleanup_when_modified_only=1,
        um_file_context_is_user_context2=1,
        file_system_name=FS_NAME,
        reject_irp_prior_to_transact0=0,
    )
    filesystem.start()
    return filesystem
