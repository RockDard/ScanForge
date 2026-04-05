import unittest

from qa_portal.hardware import (
    GPUDevice,
    HostHardwareProfile,
    assign_gpu_ids,
    build_execution_plan,
    recommended_worker_processes,
)


class HardwarePlanningTests(unittest.TestCase):
    def test_single_job_uses_all_visible_gpus(self):
        profile = HostHardwareProfile(
            cpu_threads_total=32,
            cpu_threads_target=28,
            memory_total_mb=128000,
            memory_target_mb=115200,
            utilization_target_percent=90,
            gpus=[
                GPUDevice(index=0, name="GPU0", memory_total_mb=24576),
                GPUDevice(index=1, name="GPU1", memory_total_mb=24576),
            ],
        )

        plan = build_execution_plan(job_id="job-a", running_job_ids=["job-a"], profile=profile)

        self.assertEqual(plan.cpu_threads_for_job, 28)
        self.assertEqual(plan.assigned_gpu_ids, [0, 1])
        self.assertEqual(plan.gpu_strategy, "single-job-all-gpus")

    def test_parallel_jobs_are_distributed_across_gpus(self):
        profile = HostHardwareProfile(
            cpu_threads_total=32,
            cpu_threads_target=28,
            memory_total_mb=128000,
            memory_target_mb=115200,
            utilization_target_percent=90,
            gpus=[
                GPUDevice(index=0, name="GPU0", memory_total_mb=24576),
                GPUDevice(index=1, name="GPU1", memory_total_mb=24576),
            ],
        )

        self.assertEqual(assign_gpu_ids("job-a", ["job-a", "job-b"], profile), [0])
        self.assertEqual(assign_gpu_ids("job-b", ["job-a", "job-b"], profile), [1])

        plan = build_execution_plan(job_id="job-b", running_job_ids=["job-a", "job-b"], profile=profile)
        self.assertEqual(plan.cpu_threads_for_job, 14)
        self.assertEqual(plan.assigned_gpu_ids, [1])
        self.assertEqual(plan.gpu_strategy, "distributed-single-gpu-per-job")

    def test_recommended_worker_processes_scales_with_hardware(self):
        profile = HostHardwareProfile(
            cpu_threads_total=24,
            cpu_threads_target=21,
            memory_total_mb=64000,
            memory_target_mb=57600,
            utilization_target_percent=90,
            gpus=[GPUDevice(index=0, name="GPU0", memory_total_mb=16384)],
        )

        self.assertGreaterEqual(recommended_worker_processes(profile), 1)


if __name__ == "__main__":
    unittest.main()
