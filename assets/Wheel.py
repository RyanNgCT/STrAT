import threading, sys, time

class SpinnerThread(threading.Thread):
    def __init__(self, text):
        super().__init__(target=self._spin)
        self._stopevent = threading.Event()
        self.text = text
        self.completed = False

    def stop(self):
        sys.stdout.write("\nCompleted.\n")
        sys.stdout.flush()
        self.completed = True
        self._stopevent.set()

    def _spin(self):
        while not self._stopevent.isSet():
            for t in "|/-\\":
                sys.stdout.write(f"\r[ {t} ] {self.text}")
                sys.stdout.flush()
                time.sleep(0.1)
                if self.completed:
                    return