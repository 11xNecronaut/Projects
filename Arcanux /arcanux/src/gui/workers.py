"""
A single reusable QThread worker for anything that shouldn't block the
GUI thread — keypair generation, Argon2id derivation, LSB embedding on
a large image, or ML-KEM operations. All of these are fast individually
(well under a second) but "well under a second" is still a frozen,
unresponsive window if run on the UI thread, and that's the kind of
detail that separates a real desktop app from a script with buttons.

Usage:
    worker = Worker(orchestrator.protect_file, input_path, carrier_path, pubkey, out_path)
    worker.signals.finished.connect(on_success)
    worker.signals.error.connect(on_error)
    self._threadpool.start(worker)
"""

import traceback

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    finished = Signal(object)   # emits the callable's return value
    error = Signal(str)         # emits a human-readable error message


class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            # Deliberately pass a clean message, not a raw traceback, to
            # the GUI — but log the traceback to stderr for debugging.
            traceback.print_exc()
            self.signals.error.emit(f"{type(e).__name__}: {e}")
        else:
            self.signals.finished.emit(result)
