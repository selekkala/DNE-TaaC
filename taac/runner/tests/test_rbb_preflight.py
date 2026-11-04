# pyre-unsafe

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

from taac.testconfigs.routing.util.bgp_rbb_limits import (
    MAX_RBB_ADVERTISED_PREFIX_COUNT,
)


class TestRbbPreflight(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp_dir.name) / "rbb-config"
        self.repo_root = Path(__file__).resolve().parents[3]
        self.runner = self.repo_root / "scripts" / "run-rbb-srv6.sh"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _clean_environment(self):
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("TAAC_")
        }
        environment["PYTHONPATH"] = str(self.repo_root)
        return environment

    def _run_init(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                str(self.runner),
                "--config-dir",
                str(self.config_dir),
                "--init",
            ],
            cwd=self.repo_root,
            env=self._clean_environment(),
            text=True,
            capture_output=True,
            check=False,
        )

    def _run_check(
        self,
        *,
        with_traffic: bool = False,
        setup_duts: bool = False,
        setup_dut_edges: bool = False,
        suite: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        command = [
            sys.executable,
            "-m",
            "taac.runner.rbb_preflight",
            "--config-dir",
            str(self.config_dir),
        ]
        if with_traffic:
            command.append("--with-traffic")
        if setup_duts:
            command.append("--setup-duts")
        if setup_dut_edges:
            command.append("--setup-dut-edges")
        if suite:
            command.extend(("--suite", suite))
        run_environment = self._clean_environment()
        run_environment.update(environment or {})
        return subprocess.run(
            command,
            cwd=self.repo_root,
            env=run_environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def _profile_environment(self) -> dict[str, str]:
        values = {}
        for line in (
            (self.config_dir / "rbb.env").read_text(encoding="utf-8").splitlines()
        ):
            if line and not line.startswith("#"):
                name, value = line.split("=", 1)
                values[name] = value
        return values

    def _write_valid_config(
        self, *, ixia_credentials: bool = True, dut_username: str = "dut-user"
    ) -> None:
        self.config_dir.mkdir(mode=0o700)
        (self.config_dir / "rbb.env").write_text(
            "TAAC_OSS=1\nTAAC_RBB_R1_HOST=rbb-r1.lab.local\nTAAC_RBB_R2_HOST=rbb-r2.lab.local\nTAAC_RBB_R1_HARDWARE=TEST_FBOSS\nTAAC_RBB_R2_HARDWARE=TEST_FBOSS\nTAAC_RBB_IXIA_CHASSIS=10.0.0.3\nTAAC_IXIA_API_SERVER=10.0.0.4\nTAAC_RBB_IXIA_TAIL_PREFIX=2001:db8:beef::\nTAAC_RBB_IXIA_TAIL_PREFIX_LEN=64\nTAAC_RBB_IXIA_TAIL_PREFIX_COUNT=1\nTAAC_RBB_TAIL_PREFIX=2001:db8:beef::/64\n",
            encoding="utf-8",
        )
        secrets = {
            "version": 1,
            "dut": {"username": dut_username, "password": "dut-secret"},
            "ixia": {
                "username": "ixia-user" if ixia_credentials else "",
                "password": "ixia-secret" if ixia_credentials else "",
            },
        }
        secrets_path = self.config_dir / "secrets.json"
        secrets_path.write_text(json.dumps(secrets), encoding="utf-8")
        secrets_path.chmod(0o600)
        (self.config_dir / "device_info.csv").write_text(
            "rbb-r1.lab.local,,,,RBB,FBOSS,TEST_FBOSS\n"
            "rbb-r2.lab.local,,,,RBB,FBOSS,TEST_FBOSS\n",
            encoding="utf-8",
        )
        (self.config_dir / "circuit_info.csv").write_text(
            "rbb-r1.lab.local,eth1/1,FBOSS,port-channel1,"
            "rbb-r2.lab.local,eth1/1,FBOSS,port-channel1,3,\n"
            "rbb-r1.lab.local,eth1/2,FBOSS,,ixia,1/1,IXIA,,3,IXIA\n"
            "rbb-r2.lab.local,eth1/2,FBOSS,,ixia,1/2,IXIA,,3,IXIA\n",
            encoding="utf-8",
        )

    def _replace_dut_credentials(self, dut_credentials) -> None:
        secrets_path = self.config_dir / "secrets.json"
        secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
        secrets["dut"] = dut_credentials
        secrets_path.write_text(json.dumps(secrets), encoding="utf-8")
        secrets_path.chmod(0o600)

    def _add_second_core_path(self) -> None:
        circuit_path = self.config_dir / "circuit_info.csv"
        circuit_path.write_text(
            circuit_path.read_text(encoding="utf-8")
            + "rbb-r1.lab.local,eth1/3,FBOSS,port-channel2,"
            "rbb-r2.lab.local,eth1/3,FBOSS,port-channel2,3,\n",
            encoding="utf-8",
        )

    def _run_wrapper_with_fake_docker(
        self, arguments: list[str]
    ) -> tuple[subprocess.CompletedProcess, list[str]]:
        """Run the public wrapper and return the final Docker argv."""
        fake_bin = Path(self.temp_dir.name) / "suite-bin"
        fake_bin.mkdir(exist_ok=True)
        docker_args = Path(self.temp_dir.name) / "suite-docker-args"
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = image ] && [ "$2" = inspect ]; then exit 0; fi\n'
            'printf \'%s\\n\' "$@" > "$TAAC_TEST_DOCKER_ARGS"\n',
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        environment = self._clean_environment()
        environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
        environment["TAAC_TEST_DOCKER_ARGS"] = str(docker_args)
        result = subprocess.run(
            [
                str(self.runner),
                "--config-dir",
                str(self.config_dir),
                *arguments,
            ],
            cwd=self.repo_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        forwarded = (
            docker_args.read_text(encoding="utf-8").splitlines()
            if docker_args.exists()
            else []
        )
        return result, forwarded

    def test_init_creates_private_templates_without_overwriting(self) -> None:
        result = self._run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            stat.S_IMODE(self.config_dir.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE((self.config_dir / "secrets.json").stat().st_mode),
            0o600,
        )
        for filename in (
            "rbb.env",
            "secrets.json",
            "device_info.csv",
            "circuit_info.csv",
        ):
            self.assertTrue((self.config_dir / filename).is_file())

        profile_path = self.config_dir / "rbb.env"
        profile_path.write_text("sentinel\n", encoding="utf-8")
        second_result = self._run_init()
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        self.assertEqual(profile_path.read_text(encoding="utf-8"), "sentinel\n")
        self.assertIn("Kept existing file", second_result.stdout)

    def test_init_refuses_unignored_repository_directory(self) -> None:
        result = subprocess.run(
            [
                str(self.runner),
                "--config-dir",
                str(self.repo_root),
                "--init",
            ],
            cwd=self.repo_root,
            env=self._clean_environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be under .taac", result.stderr)

    def test_fresh_image_traffic_requires_edge_setup_flag(self) -> None:
        result = subprocess.run(
            [str(self.runner), "--setup-duts", "--with-traffic"],
            cwd=self.repo_root,
            env=self._clean_environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --setup-dut-edges", result.stderr)

    def test_check_accepts_device_path_without_ixia_credentials(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        result = self._run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Configuration check passed", result.stdout)
        self.assertIn("device path (no IXIA)", result.stdout)
        self.assertNotIn("dut-secret", result.stdout + result.stderr)

    def test_check_accepts_complete_traffic_configuration(self) -> None:
        self._write_valid_config()
        result = self._run_check(with_traffic=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("live IXIA traffic", result.stdout)
        self.assertNotIn("ixia-secret", result.stdout + result.stderr)

    def test_resilience_accepts_valid_numeric_inputs(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="resilience",
            environment={
                "TAAC_RBB_RESILIENCE_CORE_PC_INDEX": "0",
                "TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT": "100",
                "TAAC_RBB_RESILIENCE_MAX_LOSS_PCT": "0",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_resilience_rejects_invalid_numeric_inputs(self) -> None:
        self._write_valid_config()
        cases = (
            ("TAAC_RBB_RESILIENCE_CORE_PC_INDEX", "-1"),
            ("TAAC_RBB_RESILIENCE_CORE_PC_INDEX", "1.5"),
            ("TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT", "0"),
            ("TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT", "100.1"),
            ("TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT", "nan"),
            ("TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT", "not-a-number"),
            ("TAAC_RBB_RESILIENCE_MAX_LOSS_PCT", "-0.1"),
            ("TAAC_RBB_RESILIENCE_MAX_LOSS_PCT", "100.1"),
            ("TAAC_RBB_RESILIENCE_MAX_LOSS_PCT", "inf"),
            ("TAAC_RBB_RESILIENCE_MAX_LOSS_PCT", "not-a-number"),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                result = self._run_check(
                    with_traffic=True,
                    suite="resilience",
                    environment={name: value},
                )

                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)

    def test_traffic_foundation_accepts_valid_numeric_inputs(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="traffic-foundation",
            environment={
                "TAAC_RBB_EDGE_BANDWIDTH_GBPS": "1",
                "TAAC_RBB_TRAFFIC_LINE_RATE": "100",
                "TAAC_RBB_TRAFFIC_FRAME_SIZE": "64",
                "TAAC_RBB_TRAFFIC_SAMPLE_SECONDS": "1",
                "TAAC_RBB_TRAFFIC_DRAIN_SECONDS": "1",
                "TAAC_RBB_TRAFFIC_RATE_TOLERANCE_PCT": "100",
                "TAAC_RBB_COUNTER_TOLERANCE_PCT": "0",
                "TAAC_RBB_COUNTER_ABSOLUTE_TOLERANCE": "1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_traffic_foundation_rejects_invalid_numeric_inputs(self) -> None:
        self._write_valid_config()
        cases = (
            ("TAAC_RBB_EDGE_BANDWIDTH_GBPS", "0"),
            ("TAAC_RBB_EDGE_BANDWIDTH_GBPS", "1.5"),
            ("TAAC_RBB_TRAFFIC_LINE_RATE", "0"),
            ("TAAC_RBB_TRAFFIC_LINE_RATE", "101"),
            ("TAAC_RBB_TRAFFIC_FRAME_SIZE", "63"),
            ("TAAC_RBB_TRAFFIC_FRAME_SIZE", "64.5"),
            ("TAAC_RBB_TRAFFIC_SAMPLE_SECONDS", "0"),
            ("TAAC_RBB_TRAFFIC_DRAIN_SECONDS", "0"),
            ("TAAC_RBB_TRAFFIC_RATE_TOLERANCE_PCT", "0"),
            ("TAAC_RBB_TRAFFIC_RATE_TOLERANCE_PCT", "101"),
            ("TAAC_RBB_COUNTER_TOLERANCE_PCT", "-0.1"),
            ("TAAC_RBB_COUNTER_TOLERANCE_PCT", "100.1"),
            ("TAAC_RBB_COUNTER_TOLERANCE_PCT", "nan"),
            ("TAAC_RBB_COUNTER_TOLERANCE_PCT", "inf"),
            ("TAAC_RBB_COUNTER_ABSOLUTE_TOLERANCE", "0"),
            ("TAAC_RBB_COUNTER_ABSOLUTE_TOLERANCE", "1.5"),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                result = self._run_check(
                    with_traffic=True,
                    suite="traffic-foundation",
                    environment={name: value},
                )

                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)

    def test_traffic_foundation_accepts_multiple_nonoverlapping_prefixes(
        self,
    ) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        profile.write_text(
            profile.read_text(encoding="utf-8").replace(
                "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT=1",
                "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT=10",
            )
            + "TAAC_RBB_IXIA_HEAD_PREFIX=2001:db8:feed::\n"
            + "TAAC_RBB_IXIA_HEAD_PREFIX_LEN=64\n"
            + "TAAC_RBB_IXIA_HEAD_PREFIX_COUNT=10\n",
            encoding="utf-8",
        )

        result = self._run_check(
            with_traffic=True,
            suite="traffic-foundation",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        base_result = self._run_check(with_traffic=True)
        self.assertEqual(base_result.returncode, 1)
        self.assertIn("single prefix", base_result.stderr)

    def test_traffic_foundation_rejects_overlapping_prefix_pools(self) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        profile.write_text(
            profile.read_text(encoding="utf-8")
            + "TAAC_RBB_IXIA_HEAD_PREFIX=2001:db8:beef::\n"
            + "TAAC_RBB_IXIA_HEAD_PREFIX_LEN=64\n"
            + "TAAC_RBB_IXIA_HEAD_PREFIX_COUNT=1\n",
            encoding="utf-8",
        )

        result = self._run_check(
            with_traffic=True,
            suite="traffic-foundation",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must not overlap", result.stderr)

    def test_traffic_foundation_rejects_prefix_count_above_shared_limit(
        self,
    ) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        profile.write_text(
            profile.read_text(encoding="utf-8").replace(
                "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT=1",
                "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT="
                f"{MAX_RBB_ADVERTISED_PREFIX_COUNT + 1}",
            ),
            encoding="utf-8",
        )

        result = self._run_check(
            with_traffic=True,
            suite="traffic-foundation",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"must not exceed {MAX_RBB_ADVERTISED_PREFIX_COUNT}",
            result.stderr,
        )

    def test_dual_stack_suite_accepts_allowlisted_ipv4_defaults(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dual_stack_suite_rejects_aggregate_rate_above_port_capacity(
        self,
    ) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={"TAAC_RBB_TRAFFIC_LINE_RATE": "51"},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("2 * TAAC_RBB_TRAFFIC_LINE_RATE <= 100", result.stderr)

    def test_core_ecmp_suite_accepts_two_paths_and_safe_defaults(self) -> None:
        self._write_valid_config()
        self._add_second_core_path()

        result = self._run_check(with_traffic=True, suite="core-ecmp")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_named_nhg_suite_validates_its_isolated_test_prefix(self) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        with profile.open("a", encoding="utf-8") as stream:
            stream.write(
                "TAAC_RBB_NAMED_NHG_TEST_PREFIX=2001:db8:beef::/64\n"
            )

        result = self._run_check(suite="named-nhg-lifecycle")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("active tail service prefix", result.stderr)

    def test_core_ecmp_suite_rejects_reversed_metric_order(self) -> None:
        self._write_valid_config()
        self._add_second_core_path()

        result = self._run_check(
            with_traffic=True,
            suite="core-ecmp",
            environment={
                "TAAC_RBB_OPENR_PREFERRED_METRIC": "100",
                "TAAC_RBB_OPENR_STANDBY_METRIC": "10",
            },
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must be greater", result.stderr)

    def test_core_ecmp_suite_rejects_impossible_path_share(self) -> None:
        self._write_valid_config()
        self._add_second_core_path()

        result = self._run_check(
            with_traffic=True,
            suite="core-ecmp",
            environment={"TAAC_RBB_CORE_ECMP_MIN_PATH_SHARE_PCT": "51"},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must not exceed 100", result.stderr)

    def test_dual_stack_suite_rejects_overlapping_ipv4_pools(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={
                "TAAC_RBB_IXIA_HEAD_PREFIX_V4": "10.100.75.128",
                "TAAC_RBB_IXIA_TAIL_PREFIX_V4": "10.100.75.128",
            },
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("IPv4 advertised pools must not overlap", result.stderr)

    def test_dual_stack_suite_rejects_invalid_ipv4_edge_pair(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={
                "TAAC_RBB_IXIA_R1_EDGE_V4": "10.100.75.2",
                "TAAC_RBB_IXIA_R1_EDGE_GW_V4": "10.100.75.5",
            },
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("distinct addresses in one subnet", result.stderr)

    def test_dual_stack_suite_rejects_ipv4_pool_on_edge_subnet(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={"TAAC_RBB_IXIA_HEAD_PREFIX_V4": "10.100.75.2"},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must not overlap the R1 edge subnet", result.stderr)

    def test_dual_stack_suite_rejects_nonallowlisted_ipv4_pool(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={"TAAC_RBB_IXIA_HEAD_PREFIX_V4": "203.0.113.128"},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("outside TAAC's IXIA advertisement allowlist", result.stderr)

    def test_dual_stack_suite_allows_explicit_ipv4_allowlist_opt_out(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={
                "TAAC_RBB_IXIA_HEAD_PREFIX_V4": "203.0.113.128",
                "TAAC_RBB_SKIP_ADVERTISED_PREFIXES_CHECK": "1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dual_stack_suite_rejects_ipv4_pool_crossing_allowlist_boundary(
        self,
    ) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={
                "TAAC_RBB_IXIA_HEAD_PREFIX_V4": "10.100.75.255",
                "TAAC_RBB_IXIA_HEAD_PREFIX_COUNT_V4": "2",
            },
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("outside TAAC's IXIA advertisement allowlist", result.stderr)

    def test_dual_stack_suite_rejects_non_ipv4_edge_address(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={
                "TAAC_RBB_IXIA_R1_EDGE_V4": "2001:db8:1::2",
                "TAAC_RBB_IXIA_R1_EDGE_GW_V4": "2001:db8:1::1",
            },
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("IPv4 edge must use IPv4", result.stderr)

    def test_dual_stack_suite_rejects_ipv6_pool_on_edge_subnet(self) -> None:
        self._write_valid_config()

        result = self._run_check(
            with_traffic=True,
            suite="dual-stack-traffic",
            environment={"TAAC_RBB_IXIA_HEAD_PREFIX": "2001:db8:a:3::"},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "IPv6 advertised pool must not overlap the R1 edge subnet",
            result.stderr,
        )

    def test_check_accepts_environment_without_rbb_env(self) -> None:
        self._write_valid_config()
        environment = self._profile_environment()
        (self.config_dir / "rbb.env").unlink()

        result = self._run_check(with_traffic=True, environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("live IXIA traffic", result.stdout)

    def test_check_accepts_environment_without_secrets_file(self) -> None:
        self._write_valid_config()
        (self.config_dir / "secrets.json").unlink()
        environment = {
            "TAAC_SSH_USER": "dut-user",
            "TAAC_SSH_PASSWORD": "dut-secret",
            "TAAC_IXIA_USERNAME": "ixia-user",
            "TAAC_IXIA_PASSWORD": "ixia-secret",
        }

        result = self._run_check(with_traffic=True, environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("dut-secret", result.stdout + result.stderr)
        self.assertNotIn("ixia-secret", result.stdout + result.stderr)

    def test_check_accepts_environment_without_optional_files(self) -> None:
        self._write_valid_config()
        environment = self._profile_environment()
        environment.update(
            {
                "TAAC_SSH_USER": "dut-user",
                "TAAC_SSH_PASSWORD": "dut-secret",
                "TAAC_IXIA_USERNAME": "ixia-user",
                "TAAC_IXIA_PASSWORD": "ixia-secret",
            }
        )
        (self.config_dir / "rbb.env").unlink()
        (self.config_dir / "secrets.json").unlink()

        result = self._run_check(with_traffic=True, environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Configuration check passed", result.stdout)

    def test_wrapper_allows_optional_files_to_be_absent(self) -> None:
        self._write_valid_config()
        environment = self._clean_environment()
        environment.update(self._profile_environment())
        environment.update(
            {
                "TAAC_SSH_USER": "dut-user",
                "TAAC_SSH_PASSWORD": "dut-secret",
                "TAAC_IXIA_USERNAME": "ixia-user",
                "TAAC_IXIA_PASSWORD": "ixia-secret",
            }
        )
        (self.config_dir / "rbb.env").unlink()
        (self.config_dir / "secrets.json").unlink()

        fake_bin = Path(self.temp_dir.name) / "bin"
        fake_bin.mkdir()
        docker_args = Path(self.temp_dir.name) / "docker-args"
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = image ] && [ "$2" = inspect ]; then exit 0; fi\n'
            'printf \'%s\\n\' "$@" > "$TAAC_TEST_DOCKER_ARGS"\n',
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
        environment["TAAC_TEST_DOCKER_ARGS"] = str(docker_args)

        result = subprocess.run(
            [
                str(self.runner),
                "--config-dir",
                str(self.config_dir),
                "--check",
                "--with-traffic",
            ],
            cwd=self.repo_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        forwarded_args = docker_args.read_text(encoding="utf-8").splitlines()
        self.assertNotIn("--env-file", forwarded_args)
        self.assertIn(f"{self.config_dir}:/workspace/.taac:ro", forwarded_args)

    def test_wrapper_routes_each_suite_to_its_public_example_config(self) -> None:
        self._write_valid_config()
        cases = (
            (
                "base",
                [],
                "/workspace/examples/rbb_srv6_3_usids_config.py",
                "bgp_rbb_srv6_3_usids",
            ),
            (
                "state-audit",
                [],
                "/workspace/examples/rbb_state_audit_config.py",
                "",
            ),
            (
                "named-nhg-lifecycle",
                [],
                "/workspace/examples/rbb_named_nhg_config.py",
                "",
            ),
            (
                "traffic-foundation",
                ["--with-traffic"],
                "/workspace/examples/rbb_traffic_foundation_config.py",
                "",
            ),
            (
                "core-ecmp",
                ["--with-traffic"],
                "/workspace/examples/rbb_core_ecmp_config.py",
                "",
            ),
            (
                "dual-stack-traffic",
                ["--with-traffic"],
                "/workspace/examples/rbb_dual_stack_traffic_config.py",
                "",
            ),
            (
                "tail-decap",
                ["--with-traffic"],
                "/workspace/examples/rbb_srv6_tail_decap_config.py",
                "",
            ),
            (
                "resilience",
                ["--with-traffic"],
                "/workspace/examples/rbb_srv6_resilience_config.py",
                "",
            ),
        )
        for suite, flags, expected_config, expected_playbook in cases:
            with self.subTest(suite=suite):
                result, forwarded = self._run_wrapper_with_fake_docker(
                    ["--suite", suite, *flags]
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected_config, forwarded)
                config_index = forwarded.index(expected_config)
                self.assertEqual(forwarded[config_index + 1], expected_playbook)

    def test_wrapper_forwards_explicit_container_image(self) -> None:
        self._write_valid_config()

        result, forwarded = self._run_wrapper_with_fake_docker(
            ["--image", "localhost/fboss-taac:current"]
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("localhost/fboss-taac:current", forwarded)

    def test_wrapper_rejects_unknown_and_incompatible_suite_modes(self) -> None:
        for arguments, message in (
            (["--suite", "unknown"], "unknown suite"),
            (
                ["--suite", "traffic-foundation"],
                "requires --with-traffic",
            ),
            (
                ["--suite", "core-ecmp"],
                "requires --with-traffic",
            ),
            (
                ["--suite", "dual-stack-traffic"],
                "requires --with-traffic",
            ),
            (
                ["--suite", "state-audit", "--with-traffic"],
                "device-only",
            ),
            (
                ["--suite", "named-nhg-lifecycle", "--with-traffic"],
                "device-only",
            ),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(self.runner), *arguments],
                    cwd=self.repo_root,
                    env=self._clean_environment(),
                    text=True,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)

    def test_check_accepts_distinct_per_host_dut_credentials(self) -> None:
        self._write_valid_config()
        self._replace_dut_credentials(
            {
                "username": "",
                "password": "",
                "hosts": {
                    "rbb-r1.lab.local": {
                        "username": "r1-user",
                        "password": "r1-secret",
                    },
                    "rbb-r2.lab.local": {
                        "username": "r2-user",
                        "password": "r2-secret",
                    },
                },
            }
        )

        result = self._run_check(with_traffic=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("r1-secret", result.stdout + result.stderr)
        self.assertNotIn("r2-secret", result.stdout + result.stderr)

    def test_check_rejects_missing_effective_per_host_credential(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        self._replace_dut_credentials(
            {
                "username": "",
                "password": "",
                "hosts": {
                    "rbb-r1.lab.local": {
                        "username": "r1-user",
                        "password": "r1-secret",
                    },
                    "rbb-r2.lab.local": {"username": "r2-user"},
                },
            }
        )

        result = self._run_check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("password", result.stderr)
        self.assertIn("rbb-r2.lab.local", result.stderr)
        self.assertNotIn("r1-secret", result.stdout + result.stderr)

    def test_check_rejects_ixia_prefix_with_host_bits(self) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        profile.write_text(
            profile.read_text(encoding="utf-8").replace(
                "TAAC_RBB_IXIA_TAIL_PREFIX=2001:db8:beef::",
                "TAAC_RBB_IXIA_TAIL_PREFIX=2001:db8:beef::1",
            ),
            encoding="utf-8",
        )
        result = self._run_check(with_traffic=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be the network address", result.stderr)

    def test_check_rejects_steered_prefix_with_host_bits(self) -> None:
        self._write_valid_config()
        profile = self.config_dir / "rbb.env"
        profile.write_text(
            profile.read_text(encoding="utf-8").replace(
                "TAAC_RBB_TAIL_PREFIX=2001:db8:beef::/64",
                "TAAC_RBB_TAIL_PREFIX=2001:db8:beef::1/64",
            ),
            encoding="utf-8",
        )
        result = self._run_check(with_traffic=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("tail-prefix contract is not valid", result.stderr)

    def test_check_accepts_fresh_image_bootstrap_configuration(self) -> None:
        self._write_valid_config(ixia_credentials=False, dut_username="root")
        result = self._run_check(setup_duts=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("temporary DUT bootstrap", result.stdout)
        self.assertNotIn("dut-secret", result.stdout + result.stderr)

    def test_bootstrap_rejects_non_root_credential_before_device_contact(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        result = self._run_check(setup_duts=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires dut.username 'root'", result.stderr)

    def test_bootstrap_accepts_distinct_root_credentials(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        self._replace_dut_credentials(
            {
                "username": "",
                "password": "",
                "hosts": {
                    "rbb-r1.lab.local": {
                        "username": "root",
                        "password": "r1-secret",
                    },
                    "rbb-r2.lab.local": {
                        "username": "root",
                        "password": "r2-secret",
                    },
                },
            }
        )

        result = self._run_check(setup_duts=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("r1-secret", result.stdout + result.stderr)
        self.assertNotIn("r2-secret", result.stdout + result.stderr)

    def test_bootstrap_rejects_non_root_per_host_credential(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        self._replace_dut_credentials(
            {
                "username": "root",
                "password": "shared-secret",
                "hosts": {
                    "rbb-r2.lab.local": {"username": "operator"},
                },
            }
        )

        result = self._run_check(setup_duts=True)

        self.assertEqual(result.returncode, 1)
        self.assertIn("requires dut.username 'root'", result.stderr)
        self.assertIn("rbb-r2.lab.local", result.stderr)
        self.assertNotIn("shared-secret", result.stdout + result.stderr)

    def test_edge_setup_rejects_non_root_credential_before_device_contact(self) -> None:
        self._write_valid_config()
        result = self._run_check(with_traffic=True, setup_dut_edges=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--setup-dut-edges requires dut.username 'root'", result.stderr)

    def test_edge_setup_requires_traffic_mode(self) -> None:
        self._write_valid_config(ixia_credentials=False, dut_username="root")
        result = self._run_check(setup_dut_edges=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--setup-dut-edges requires --with-traffic", result.stderr)

    def test_fresh_image_preflight_requires_edge_setup_for_traffic(self) -> None:
        self._write_valid_config(dut_username="root")
        result = self._run_check(with_traffic=True, setup_duts=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("fresh-image traffic requires --setup-dut-edges", result.stderr)

    def test_bootstrap_rejects_multi_member_lag_before_device_contact(self) -> None:
        self._write_valid_config(ixia_credentials=False, dut_username="root")
        with (self.config_dir / "circuit_info.csv").open(
            "a", encoding="utf-8"
        ) as circuits:
            circuits.write(
                "rbb-r1.lab.local,eth1/3,FBOSS,port-channel1,"
                "rbb-r2.lab.local,eth1/3,FBOSS,port-channel1,3,\n"
            )
        result = self._run_check(setup_duts=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("exactly one member", result.stderr)

    def test_bootstrap_rejects_shell_active_device_path(self) -> None:
        self._write_valid_config(ixia_credentials=False, dut_username="root")
        with (self.config_dir / "rbb.env").open("a", encoding="utf-8") as profile:
            profile.write("TAAC_RBB_AGENT_CONFIG_PATH=/etc/coop/agent.conf;reboot\n")
        result = self._run_check(setup_duts=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("canonical absolute paths", result.stderr)

    def test_edge_setup_rejects_shell_active_device_path(self) -> None:
        self._write_valid_config(dut_username="root")
        with (self.config_dir / "rbb.env").open("a", encoding="utf-8") as profile:
            profile.write("TAAC_RBB_BGP_CONFIG_PATH=/opt/bgpd/bgp.json;reboot\n")
        result = self._run_check(with_traffic=True, setup_dut_edges=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("canonical absolute paths", result.stderr)

    def test_check_rejects_missing_traffic_credentials(self) -> None:
        self._write_valid_config(ixia_credentials=False)
        result = self._run_check(with_traffic=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("TAAC_IXIA_PASSWORD", result.stderr)
        self.assertIn("TAAC_IXIA_USERNAME", result.stderr)
        self.assertNotIn("dut-secret", result.stdout + result.stderr)

    def test_check_rejects_unmodified_endpoint_placeholders(self) -> None:
        result = self._run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        secrets_path = self.config_dir / "secrets.json"
        secrets_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "dut": {"username": "dut-user", "password": "dut-secret"},
                    "ixia": {"username": "", "password": ""},
                }
            ),
            encoding="utf-8",
        )
        result = self._run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Replace the placeholder value", result.stderr)
        self.assertNotIn("dut-secret", result.stdout + result.stderr)

    def test_check_rejects_credentials_in_nonsecret_profile(self) -> None:
        self._write_valid_config()
        with (self.config_dir / "rbb.env").open("a", encoding="utf-8") as profile:
            profile.write("TAAC_SSH_PASSWORD=must-not-be-printed\n")
        result = self._run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not contain credentials", result.stderr)
        self.assertNotIn("must-not-be-printed", result.stdout + result.stderr)


if __name__ == "__main__":
    import unittest

    unittest.main()
