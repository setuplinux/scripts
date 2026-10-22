import http.client
import importlib.util
import json
import os
import pathlib
import pty
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nodepilot.py"
SPEC = importlib.util.spec_from_file_location("nodepilot", SCRIPT)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class CatalogTests(unittest.TestCase):
    def test_embeds_all_101_advertised_non_help_paths(self):
        self.assertEqual(101, len(helper.CATALOG))
        self.assertEqual(101, len({entry["path"] for entry in helper.CATALOG}))
        self.assertTrue(all(entry["path"].startswith("hvmcli ") for entry in helper.CATALOG))

    def test_catalog_contains_only_sanitized_help_fields(self):
        forbidden_keys = {"host", "stderr", "invocation", "timestamp_utc", "return_code"}
        for entry in helper.CATALOG:
            self.assertFalse(forbidden_keys.intersection(entry))
            self.assertNotIn("10.10.10.", entry["help"])
            self.assertNotIn("/root/", entry["help"])
            self.assertNotIn("Examples:", entry["help"])

    def test_search_matches_paths_flags_and_help_case_insensitively(self):
        paths = [entry["path"] for entry in helper.search_catalog("--FORCE")]
        self.assertIn("hvmcli vm stop", paths)
        self.assertEqual(["hvmcli vm stop"], [e["path"] for e in helper.search_catalog("vm stop")])

    def test_preview_is_rendered_as_data_not_executed(self):
        preview = helper.make_preview("hvmcli vm stop", '--name "demo vm"; touch /tmp/NOPE')
        self.assertIn("hvmcli vm stop", preview)
        self.assertIn("demo vm", preview)
        self.assertFalse(pathlib.Path("/tmp/NOPE").exists())

    def test_preview_rejects_unknown_catalog_path_and_bad_quoting(self):
        with self.assertRaises(ValueError):
            helper.make_preview("hvmcli not-real", "")
        with self.assertRaises(ValueError):
            helper.make_preview("hvmcli vm stop", "'unterminated")


class WebSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.token = helper.create_web_server("127.0.0.1", 0, token="test-token")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path, *, host=None, origin=None, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if origin is not None:
            headers["Origin"] = origin
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        body = response.read()
        headers_out = dict(response.getheaders())
        conn.close()
        return response.status, headers_out, body

    def test_requires_random_session_token(self):
        self.assertEqual(403, self.request("/")[0])
        self.assertEqual(200, self.request("/?token=test-token")[0])
        self.assertEqual(403, self.request("/?token=wrong")[0])

    def test_rejects_untrusted_host_and_origin(self):
        self.assertEqual(421, self.request("/?token=test-token", host="evil.example")[0])
        self.assertEqual(403, self.request("/?token=test-token", origin="http://evil.example")[0])
        allowed = f"http://127.0.0.1:{self.port}"
        self.assertEqual(200, self.request("/?token=test-token", origin=allowed)[0])

    def test_api_is_read_only_and_has_no_cors_wildcard(self):
        status, headers, body = self.request("/api/catalog?token=test-token")
        self.assertEqual(200, status)
        self.assertEqual(101, len(json.loads(body)))
        self.assertNotEqual("*", headers.get("Access-Control-Allow-Origin"))
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(405, self.request("/execute?token=test-token", method="POST")[0])
        self.assertEqual(404, self.request("/execute?token=test-token")[0])

    def test_security_headers_are_present(self):
        status, headers, _ = self.request("/?token=test-token")
        self.assertEqual(200, status)
        self.assertEqual("DENY", headers["X-Frame-Options"])
        self.assertEqual("nosniff", headers["X-Content-Type-Options"])
        self.assertEqual("no-referrer", headers["Referrer-Policy"])
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_server_refuses_non_loopback_bind(self):
        with self.assertRaises(ValueError):
            helper.create_web_server("0.0.0.0", 0)


class LiveCommandTests(unittest.TestCase):
    def make_executable(self, body):
        directory = tempfile.TemporaryDirectory()
        path = pathlib.Path(directory.name) / "fake-hvmcli"
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(directory.cleanup)
        return str(path)

    def test_allowlist_contains_only_curated_read_only_literal_argv(self):
        expected = {
            "vm.list", "node.list", "node.config", "interfaces.list",
            "hardware.cpu", "hardware.memory", "hardware.pci", "hardware.bootvolume",
            "software.list", "virtswitch.list", "virtswitch.status", "virtswitch.show", "network.list",
            "storage.list", "storage.iscsi.sessions", "storage.iscsi.multipath",
            "storage.fc.ports", "storage.fc.multipath", "storage.multipath.status",
            "storage.multipath.validate", "cluster.status", "cluster.nodes",
            "health.check", "logs.node", "logs.cluster", "logs.morpheus",
            "node.events",
        }
        self.assertEqual(expected, set(helper.LIVE_COMMANDS))
        forbidden = {"configure", "update", "deploy", "start", "stop", "restart",
                     "reboot", "shutdown", "rescan", "apply", "watch", "--live"}
        for command in helper.LIVE_COMMANDS.values():
            self.assertIsInstance(command.argv, tuple)
            self.assertEqual("hvmcli", command.argv[0])
            self.assertFalse(forbidden.intersection(command.argv))

    def test_runner_rejects_non_allowlisted_id(self):
        with self.assertRaises(ValueError):
            helper.CommandRunner().run_sync("vm.start")

    def test_context_resource_is_one_validated_argv_element(self):
        executable = self.make_executable("import sys\nprint('\\n'.join(sys.argv[1:]))\n")
        result = helper.CommandRunner().run_sync("virtswitch.show", executable=executable, resource="vs0-safe")
        self.assertEqual("ok", result.status)
        self.assertIn("--virtswitch-name\nvs0-safe", result.output)
        with self.assertRaises(ValueError):
            helper.CommandRunner().run_sync("virtswitch.show", executable=executable, resource="vs0; reboot")

    def test_runner_returns_missing_binary_error(self):
        result = helper.CommandRunner().run_sync("vm.list", executable="/definitely/no/hvmcli")
        self.assertEqual("error", result.status)
        self.assertIn("not found", result.output.lower())

    def test_runner_times_out_and_kills_command(self):
        executable = self.make_executable("import time\ntime.sleep(2)\n")
        result = helper.CommandRunner(timeout=0.15).run_sync("vm.list", executable=executable)
        self.assertEqual("timeout", result.status)
        self.assertLess(result.elapsed, 1.5)

    def test_runner_bounds_output(self):
        executable = self.make_executable("print('x' * 10000)\n")
        result = helper.CommandRunner(max_output=512).run_sync("vm.list", executable=executable)
        self.assertEqual("truncated", result.status)
        self.assertLessEqual(len(result.output.encode()), 700)
        self.assertIn("truncated", result.output.lower())

    def test_runner_redacts_common_secret_shapes(self):
        executable = self.make_executable("print('Authorization: Bearer abc.def-123')\nprint('apikey=supersecret')\n")
        result = helper.CommandRunner().run_sync("vm.list", executable=executable)
        self.assertNotIn("abc.def-123", result.output)
        self.assertNotIn("supersecret", result.output)
        self.assertIn("[REDACTED]", result.output)

    def test_runner_strips_terminal_escape_sequences_and_control_bytes(self):
        executable = self.make_executable("import sys\nsys.stdout.buffer.write(b'good\\x1b[2Jbad\\x07\\n')\n")
        result = helper.CommandRunner().run_sync("vm.list", executable=executable)
        self.assertEqual("goodbad\n", result.output)


class MenuStateTests(unittest.TestCase):
    def test_enter_opens_submenu_and_escape_returns_before_quit(self):
        state = helper.MenuState(helper.MENU_ROOT)
        self.assertEqual("Main", state.breadcrumb)
        state.handle_key(10)
        self.assertGreater(state.depth, 1)
        self.assertIn("Main /", state.breadcrumb)
        self.assertFalse(state.handle_key(27))
        self.assertEqual(1, state.depth)
        self.assertTrue(state.handle_key(ord("q")))

    def test_output_search_and_scroll_are_bounded(self):
        view = helper.OutputView("alpha\nbeta alpha\ngamma")
        self.assertEqual(2, len(view.search("alpha")))
        view.scroll(100, page_size=2)
        self.assertEqual(1, view.offset)
        view.scroll(-100, page_size=2)
        self.assertEqual(0, view.offset)


class PtySmokeTests(unittest.TestCase):
    def test_real_curses_navigation_enter_escape_quit(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execv(sys.executable, [sys.executable, str(SCRIPT), "tui"])
        try:
            time.sleep(0.25)
            os.write(fd, b"\r")
            time.sleep(0.1)
            os.write(fd, b"\x1bq")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    self.assertEqual(0, os.waitstatus_to_exitcode(status))
                    break
                time.sleep(0.05)
            else:
                os.kill(pid, 9)
                self.fail("TUI did not exit after Enter, Esc, q navigation")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
