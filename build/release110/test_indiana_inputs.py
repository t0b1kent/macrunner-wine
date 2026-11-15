"""A successful dependency job is independently reusable; a partial or foreign one is not."""
import copy
import unittest
import indiana_inputs as step


class DependencyProvenance(unittest.TestCase):
    def setUp(self):
        self.run = dict(head_sha=step.PIN['revision'], status='in_progress', conclusion=None)
        self.jobs = [dict(name='deps', status='completed', conclusion='success'),
                     dict(name='wine', status='in_progress', conclusion=None)]
        self.artifact = dict(id=step.PIN['artifact'], expired=False, workflow_run=dict(id=step.PIN['run']),
                             digest='sha256:' + step.PIN['sha256'])

    def test_complete_dependency_output_does_not_wait_for_independent_wine_build(self):
        step.check_producer(self.run, self.jobs, self.artifact)

    def test_wrong_source_refuses(self):
        self.run['head_sha'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'revision differs'):
            step.check_producer(self.run, self.jobs, self.artifact)

    def test_incomplete_or_failed_dependency_job_refuses(self):
        for status, conclusion in [('in_progress', None), ('completed', 'failure'), ('completed', 'skipped')]:
            with self.subTest(status=status, conclusion=conclusion):
                jobs = [dict(name='deps', status=status, conclusion=conclusion)]
                with self.assertRaisesRegex(ValueError, 'must succeed'):
                    step.check_producer(self.run, jobs, self.artifact)

    def test_foreign_expired_or_corrupt_artifact_refuses(self):
        for key, value in [('id', 1), ('expired', True), ('workflow_run', dict(id=1)), ('digest', 'sha256:' + '0' * 64)]:
            with self.subTest(key=key):
                artifact = copy.deepcopy(self.artifact); artifact[key] = value
                with self.assertRaisesRegex(ValueError, 'identity differs'):
                    step.check_producer(self.run, self.jobs, artifact)


if __name__ == '__main__':
    unittest.main()
