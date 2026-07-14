from database.scan_job import ScanJob


class ScanManager:

    def __init__(self):

        self.jobs = []

    def create_job(self, target):

        job = ScanJob(target)

        self.jobs.append(job)

        return job

    def get_jobs(self):

        return self.jobs