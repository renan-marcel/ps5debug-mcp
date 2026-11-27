import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ps5debug_mcp.ps5debug_client import DisasmEntry, ForegroundApp, MapEntry, ProcInfo, ProcessEntry, StackFrame
from ps5debug_mcp.server import DebugSession, MCPServer, parse_aob, parse_int


class FakeClient:
    def __init__(self):
        self.connected = False
        self.mem = bytearray(4096)
        struct.pack_into("<I", self.mem, 0x100, 0x12345678)
        self.mem[0x200:0x20B] = b"hello ps5\x00\x00"
        self.attached = None
        self.breakpoints = []
        self.watchpoints = []

    def connect(self, host, port=744, timeout=8.0):
        self.connected = True

    def close(self):
        self.connected = False

    def version(self):
        return "1.3"

    def fw_version(self):
        return 1001

    def branding(self):
        return "ps5debug-NG v1.3.2"

    def list_processes(self):
        return [ProcessEntry("eboot.bin", 42), ProcessEntry("SceShellCore", 10)]

    def foreground_app(self):
        return ForegroundApp(42, "PPSA99198", "UP0001-PPSA99198", "Longshot", "01.00")

    def proc_info(self, pid):
        return ProcInfo(pid, "eboot.bin", "/app0/eboot.bin", "PPSA99198", "UP0001-PPSA99198")

    def maps(self, pid):
        return [
            MapEntry("eboot.bin", 0x700000000, 0x700100000, 0, 5),
            MapEntry("eboot.bin[data]", 0x700100000, 0x700200000, 0x100000, 3),
        ]

    def read(self, pid, address, length):
        off = address - 0x700000000
        return bytes(self.mem[off : off + length])

    def write(self, pid, address, data):
        off = address - 0x700000000
        self.mem[off : off + len(data)] = data

    def scan_aob_all(self, pid, addr, length, pat, mask, max_results=32):
        return [0x700000100]

    def disasm_region(self, pid, addr, length):
        return [DisasmEntry(addr, 0, 0, 5, 0)]

    def find_xrefs_to(self, pid, start, length, target):
        return [0x700000050]

    def debug_attach(self, pid):
        self.attached = pid

    def debug_detach(self):
        self.attached = None

    def debug_set_breakpoint(self, idx, enabled, addr):
        self.breakpoints.append((idx, enabled, addr))

    def debug_set_watchpoint(self, idx, enabled, length, breaktype, addr):
        self.watchpoints.append((idx, enabled, length, breaktype, addr))

    def read_stack(self, pid, rbp, rsp, depth=16):
        return [StackFrame(rbp, rsp, rbp + 0x20, 0x700001234, 0, b"", b"")]


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.session = DebugSession(client_factory=FakeClient)
        self.server = MCPServer(self.session)

    def test_initialize_and_list_tools(self):
        init = self.server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "ps5debug-mcp")
        tools = self.server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {t["name"] for t in tools["result"]["tools"]}
        self.assertIn("ps5_connect", names)
        self.assertIn("ps5_resolve_address", names)
        self.assertIn("ps5_klog_tail", names)

    def test_connect_resolve_and_memory(self):
        res = self.server.call_tool("ps5_connect", {"host": "127.0.0.1"})
        self.assertTrue(res["connected"])
        self.assertEqual(res["fw_version"], 1001)

        resolved = self.server.call_tool(
            "ps5_resolve_address",
            {"address": "0x401234", "bn_base": "0x400000", "direction": "bn_to_ps5"},
        )
        self.assertEqual(resolved["output"], "0x700001234")

        rev = self.server.call_tool(
            "ps5_resolve_address",
            {"address": "0x700001234", "bn_base": "0x400000", "direction": "ps5_to_bn"},
        )
        self.assertEqual(rev["output"], "0x401234")

        val = self.server.call_tool("ps5_read_memory", {"address": "0x700000100", "format": "u32"})
        self.assertEqual(val["value"], 0x12345678)

        txt = self.server.call_tool("ps5_read_memory", {"address": "0x700000200", "size": 16, "format": "utf8"})
        self.assertEqual(txt["text"], "hello ps5")

        self.server.call_tool("ps5_write_memory", {"address": "0x700000100", "data_hex": "DE AD BE EF"})
        val2 = self.server.call_tool("ps5_read_memory", {"address": "0x700000100", "format": "hex", "size": 4})
        self.assertEqual(val2["hex"], "de ad be ef")

    def test_klog_ring_buffer(self):
        self.session.klog.push_line("normal boot line")
        self.session.klog.push_line("SIGSEGV in thread render")
        tail = self.server.call_tool("ps5_klog_tail", {"lines": 10, "filter_text": "sigsegv"})
        self.assertEqual(tail["count"], 1)
        self.assertEqual(tail["lines"][0], "SIGSEGV in thread render")

    def test_helpers(self):
        self.assertEqual(parse_int("0x10"), 16)
        self.assertEqual(parse_int(42), 42)
        pat, mask = parse_aob("48 ?? 05")
        self.assertEqual(pat, b"\x48\x00\x05")
        self.assertEqual(mask, b"\x01\x00\x01")


if __name__ == "__main__":
    unittest.main()
