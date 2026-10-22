"""Process-local runtime input/output firewall with an auditable access ledger.

    Not an OS sandbox for hostile Python. This protects this standalone program's
    file API use, blocks subprocess/network escapes, and fails closed on reads
    outside exact input paths. Imports finish before activation.
"""
import os
from pathlib import Path
import sys

class ReadOnlyGuard:
    def __init__(self, inputs, output):
        self.inputs = {str(Path(p).resolve()).casefold() for p in inputs}
        self.output = Path(output).resolve()
        self.active = False
        self.events = []

    def hook(self, event, args):
        if not self.active:
            return
        if event == 'open':
            target, mode, flags = args
            if isinstance(target, int):
                self.events.append(dict(operation='denied_fd_open', path=str(target)))
                raise PermissionError('prototype_fd_open_denied')
            path = Path(os.fsdecode(target)).resolve()
            writing = bool((isinstance(mode, str) and any(x in mode for x in 'wax+')) or
                           (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            allowed = (path.is_relative_to(self.output) and str(path).casefold() not in self.inputs
                       if writing else str(path).casefold() in self.inputs)
            self.events.append(dict(operation='write' if writing else 'read', path=str(path), allowed=allowed))
            if not allowed:
                raise PermissionError('prototype_file_access_denied:' + str(path))
        elif event in {'os.listdir','os.scandir'}:
            raise PermissionError('prototype_directory_enumeration_denied')
        elif event.startswith(('subprocess.', 'socket.')) or event in {
                'os.system','os.remove','os.rename','os.rmdir','os.link','os.symlink','os.truncate','os.chdir'}:
            self.events.append(dict(operation=event, allowed=False))
            raise PermissionError('prototype_operation_denied:' + event)
        elif event == 'os.mkdir':
            if not Path(args[0]).resolve().is_relative_to(self.output):
                raise PermissionError('prototype_mkdir_outside_output')

    def __enter__(self):
        sys.addaudithook(self.hook)
        self.active = True
        return self

    def __exit__(self, *_):
        self.active = False

