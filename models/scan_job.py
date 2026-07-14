from datetime import datetime


class ScanJob:

    def __init__(self, target):

        self.target = target

        self.status = "Pending"

        self.created = datetime.now()

        self.finished = None

        self.results = []

    def start(self):

        self.status = "Running"

    def complete(self):

        self.status = "Completed"

        self.finished = datetime.now()

    def failed(self):

        self.status = "Failed"