import ast
import importlib.util
import os
import pathlib
import pty
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

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


class TuiOnlyCliTests(unittest.TestCase):
    def test_default_invokes_tui(self):
        with mock.patch.object(helper, "run_tui", return_value=17) as run_tui:
            self.assertEqual(17, helper.main([]))
        run_tui.assert_called_once_with()

    def test_web_subcommand_is_rejected(self):
        with self.assertRaises(SystemExit) as raised:
            helper.build_parser().parse_args(["web"])
        self.assertEqual(2, raised.exception.code)

    def test_source_has_no_http_server_or_browser_imports(self):
        tree = ast.parse(SCRIPT.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("http.server", imported)
        self.assertNotIn("webbrowser", imported)
        self.assertFalse(hasattr(helper, "create_web_server"))
        self.assertFalse(hasattr(helper, "run_web"))

    def test_version_and_tui_header_are_nodepilot(self):
        source = SCRIPT.read_text()
        self.assertEqual("0.3.0", helper.VERSION)
        self.assertIn('" NODEPILOT — READ-ONLY HELPER "', source)
        self.assertNotIn("HPE VM ESSENTIALS — READ-ONLY HELPER", source)


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
    def test_default_real_curses_navigation_enter_escape_quit(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execv(sys.executable, [sys.executable, str(SCRIPT)])
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
