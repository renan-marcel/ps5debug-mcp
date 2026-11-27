"""Zero-dependency stdio MCP (JSON-RPC 2.0) server for ps5debug-NG."""
from __future__ import annotations

import json
import os
import queue
import struct
import sys
import threading
from typing import Any, Callable, Optional

from .debugger_core import (
    INTERRUPT_PORT,
    WATCH_LEN,
    WATCH_TYPE,
    InterruptListener,
    StopEvent,
    flags_text,
    parse_regs,
)
from .klog import KLOG_PORT, KlogReader
from .ps5debug_client import PROT_EXEC, PROT_READ, PROT_WRITE, PS5DebugClient, SERVER_PORT

PROTOCOL_VERSION = "2024-11-05"

_SCALAR_FMTS = {
    "u8": ("<B", 1),
    "i8": ("<b", 1),
    "u16": ("<H", 2),
    "i16": ("<h", 2),
    "u32": ("<I", 4),
    "i32": ("<i", 4),
    "u64": ("<Q", 8),
    "i64": ("<q", 8),
    "f32": ("<f", 4),
    "f64": ("<d", 8),
}


def parse_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a valid address/integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 0)
    raise ValueError(f"cannot parse integer from {value!r}")


def parse_aob(pattern: str) -> tuple[bytes, bytes]:
    pat = bytearray()
    mask = bytearray()
    for tok in pattern.strip().split():
        if tok in ("?", "??", "**"):
            pat.append(0)
            mask.append(0)
        else:
            pat.append(int(tok, 16))
            mask.append(1)
    if not pat:
        raise ValueError("empty AOB pattern")
    return bytes(pat), bytes(mask)


def prot_str(prot: int) -> str:
    return (
        ("r" if prot & PROT_READ else "-")
        + ("w" if prot & PROT_WRITE else "-")
        + ("x" if prot & PROT_EXEC else "-")
    )


def format_stop_event(ev: StopEvent) -> dict[str, Any]:
    return {
        "lwpid": ev.lwpid,
        "signal": ev.signal,
        "signame": ev.signame,
        "tdname": ev.tdname,
        "dr6": hex(ev.dr6),
        "rflags_text": flags_text(ev.regs.get("rflags", 0)),
        "regs": {k: hex(v) for k, v in ev.regs.items()},
    }


class DebugSession:
    """Holds active TCP connections (744 commands, 755 interrupts, 3232 klog)."""

    def __init__(self, client_factory: Callable[[], PS5DebugClient] = PS5DebugClient) -> None:
        self._client_factory = client_factory
        self.client: Optional[PS5DebugClient] = None
        self.host: Optional[str] = None
        self.port: int = SERVER_PORT
        self.attached_pid: Optional[int] = None
        self.listener: Optional[InterruptListener] = None
        self.stop_events: queue.Queue[StopEvent] = queue.Queue(maxsize=128)
        self.klog = KlogReader()
        self._lock = threading.Lock()

    def require_client(self) -> PS5DebugClient:
        if self.client is None or not self.client.connected:
            raise RuntimeError("Not connected to ps5debug-NG. Call ps5_connect first.")
        return self.client

    def resolve_pid(self, pid: Optional[int]) -> int:
        if pid is not None:
            return int(pid)
        if self.attached_pid is not None:
            return self.attached_pid
        c = self.require_client()
        fg = c.foreground_app()
        if fg.pid > 0:
            return fg.pid
        raise RuntimeError("No pid provided, not attached, and no foreground app detected.")

    def connect(self, host: str, port: int = SERVER_PORT, timeout: float = 8.0) -> dict[str, Any]:
        self.disconnect()
        c = self._client_factory()
        c.connect(host, port=port, timeout=timeout)
        self.client = c
        self.host = host
        self.port = port
        return {
            "connected": True,
            "host": host,
            "port": port,
            "version": c.version(),
            "fw_version": c.fw_version(),
            "branding": c.branding(),
        }

    def disconnect(self) -> dict[str, Any]:
        if self.attached_pid is not None and self.client is not None and self.client.connected:
            try:
                self.client.debug_detach()
            except Exception:
                pass
        self.attached_pid = None
        if self.listener is not None:
            try:
                self.listener.stop()
            except Exception:
                pass
            self.listener = None
        self.klog.stop()
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        return {"connected": False}

    def _on_stop_event(self, ev: StopEvent) -> None:
        if self.stop_events.full():
            try:
                self.stop_events.get_nowait()
            except queue.Empty:
                pass
        self.stop_events.put(ev)

    def module_base(self, pid: int, module: str = "eboot.bin") -> dict[str, Any]:
        c = self.require_client()
        maps = c.maps(pid)
        needle = module.lower()
        matches = [m for m in maps if needle in m.name.lower()]
        if not matches:
            raise RuntimeError(f"Module {module!r} not found in maps for pid {pid}")
        base = min(m.start for m in matches)
        end = max(m.end for m in matches)
        return {
            "pid": pid,
            "module": module,
            "base": hex(base),
            "end": hex(end),
            "size": end - base,
            "segments": [
                {
                    "name": m.name,
                    "start": hex(m.start),
                    "end": hex(m.end),
                    "size": m.end - m.start,
                    "prot": prot_str(m.prot),
                }
                for m in matches
            ],
        }


class MCPServer:
    def __init__(self, session: Optional[DebugSession] = None) -> None:
        self.session = session or DebugSession()
        self.tools = self._build_tools()

    def _build_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "ps5_connect",
                "description": "Connect to ps5debug-NG on a PS5 console (TCP port 744).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "PS5 IP address (or PS5_DEBUG_HOST env var)"},
                        "port": {"type": "integer", "default": SERVER_PORT},
                        "timeout": {"type": "number", "default": 8.0},
                    },
                },
            },
            {
                "name": "ps5_disconnect",
                "description": "Detach debugger, stop klog/interrupt listeners, and close connection.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_status",
                "description": "Return connection, attached PID, interrupt listener, and klog status.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_list_processes",
                "description": "List running PS5 processes (name and pid).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_foreground_app",
                "description": "Get the currently focused foreground PS5 app (pid, titleid, contentid, name, app_ver).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_proc_info",
                "description": "Get metadata (name, path, titleid, contentid) for a process.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"pid": {"type": "integer"}},
                },
            },
            {
                "name": "ps5_proc_maps",
                "description": "List virtual memory maps for a process (optional substring filter on segment name).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "filter_name": {"type": "string"},
                    },
                },
            },
            {
                "name": "ps5_resolve_address",
                "description": "Translate between a Binary Ninja / ELF address (given bn_base) and live PS5 ASLR address for a module (default eboot.bin).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "address": {"type": "string", "description": "Hex or int address to translate"},
                        "module": {"type": "string", "default": "eboot.bin"},
                        "bn_base": {"type": "string", "default": "0x0", "description": "Module image base in Binary Ninja (e.g. 0x0 or 0x400000)"},
                        "direction": {"type": "string", "enum": ["bn_to_ps5", "ps5_to_bn"], "default": "bn_to_ps5"},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "ps5_read_memory",
                "description": "Read memory from a PS5 process as hex, utf8, ascii, or scalar (u8/u16/u32/u64/i8/i16/i32/i64/f32/f64).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "address": {"type": "string", "description": "Target virtual address (hex or int)"},
                        "size": {"type": "integer", "default": 64},
                        "format": {
                            "type": "string",
                            "enum": ["hex", "utf8", "ascii", "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64"],
                            "default": "hex",
                        },
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "ps5_write_memory",
                "description": "Write raw bytes (hex string) to target process memory (verified write).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "address": {"type": "string"},
                        "data_hex": {"type": "string", "description": "Hex bytes, e.g. '90 90 90' or '909090'"},
                    },
                    "required": ["address", "data_hex"],
                },
            },
            {
                "name": "ps5_aob_scan",
                "description": "Scan a memory range (or module) for an AOB byte pattern with '??' wildcards.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "pattern": {"type": "string", "description": "e.g. '48 8B 05 ?? ?? ?? ??'"},
                        "start": {"type": "string", "description": "Start address (defaults to module base)"},
                        "length": {"type": "integer", "description": "Byte length to scan (defaults to module size)"},
                        "module": {"type": "string", "default": "eboot.bin"},
                        "max_results": {"type": "integer", "default": 32},
                    },
                    "required": ["pattern"],
                },
            },
            {
                "name": "ps5_disasm_region",
                "description": "Server-side Zydis disassembly of a memory region on the PS5.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "address": {"type": "string"},
                        "length": {"type": "integer", "default": 128},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "ps5_find_xrefs_to",
                "description": "Find instructions in a memory range whose RIP-relative operand targets a specific address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "target": {"type": "string"},
                        "start": {"type": "string", "description": "Defaults to module base"},
                        "length": {"type": "integer", "description": "Defaults to module size"},
                        "module": {"type": "string", "default": "eboot.bin"},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "ps5_debug_attach",
                "description": "Start TCP 755 interrupt listener and attach ptrace debugger to pid.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "listen_port": {"type": "integer", "default": INTERRUPT_PORT},
                    },
                },
            },
            {
                "name": "ps5_debug_detach",
                "description": "Detach ptrace debugger and stop interrupt listener.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_debug_continue",
                "description": "Resume execution of the attached debuggee.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_debug_step",
                "description": "Single-step the attached debuggee (or a specific lwpid).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"lwpid": {"type": "integer"}},
                },
            },
            {
                "name": "ps5_debug_set_breakpoint",
                "description": "Set or clear a software breakpoint (0xCC, slots 0..29).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer", "default": 0},
                        "address": {"type": "string"},
                        "enabled": {"type": "boolean", "default": True},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "ps5_debug_set_watchpoint",
                "description": "Set or clear a hardware watchpoint/breakpoint (DR0..DR3).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer", "default": 0},
                        "address": {"type": "string"},
                        "watch_type": {"type": "string", "enum": ["exec", "write", "read/write"], "default": "write"},
                        "length": {"type": "integer", "enum": [1, 2, 4, 8], "default": 4},
                        "enabled": {"type": "boolean", "default": True},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "ps5_debug_wait_stop",
                "description": "Wait for the next breakpoint/watchpoint/signal stop event from TCP 755.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"timeout": {"type": "number", "default": 10.0}},
                },
            },
            {
                "name": "ps5_debug_threads",
                "description": "List threads (lwpid, priority, name) of the attached debuggee.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_debug_suspend_thread",
                "description": "Suspend a thread by lwpid.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"lwpid": {"type": "integer"}},
                    "required": ["lwpid"],
                },
            },
            {
                "name": "ps5_debug_resume_thread",
                "description": "Resume a thread by lwpid.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"lwpid": {"type": "integer"}},
                    "required": ["lwpid"],
                },
            },
            {
                "name": "ps5_debug_get_regs",
                "description": "Read GP registers for a thread (lwpid).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"lwpid": {"type": "integer"}},
                    "required": ["lwpid"],
                },
            },
            {
                "name": "ps5_debug_read_stack",
                "description": "Perform server-side RBP stack walk (up to 64 frames).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "rbp": {"type": "string"},
                        "rsp": {"type": "string"},
                        "depth": {"type": "integer", "default": 16},
                    },
                    "required": ["rbp", "rsp"],
                },
            },
            {
                "name": "ps5_klog_start",
                "description": "Start background /dev/klog reader on TCP port 3232.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "default": KLOG_PORT},
                    },
                },
            },
            {
                "name": "ps5_klog_stop",
                "description": "Stop background /dev/klog reader.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "ps5_klog_tail",
                "description": "Return the most recent /dev/klog lines (with optional case-insensitive filter).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "lines": {"type": "integer", "default": 50},
                        "filter_text": {"type": "string"},
                    },
                },
            },
        ]

    def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        s = self.session
        if name == "ps5_connect":
            host = args.get("host") or os.environ.get("PS5_DEBUG_HOST")
            if not host:
                raise ValueError("Provide 'host' or set PS5_DEBUG_HOST")
            return s.connect(host, port=int(args.get("port", SERVER_PORT)), timeout=float(args.get("timeout", 8.0)))

        if name == "ps5_disconnect":
            return s.disconnect()

        if name == "ps5_status":
            return {
                "connected": bool(s.client and s.client.connected),
                "host": s.host,
                "port": s.port,
                "attached_pid": s.attached_pid,
                "interrupt_listener": s.listener is not None,
                "queued_stops": s.stop_events.qsize(),
                "klog_running": s.klog.running,
                "klog_error": s.klog.last_error,
            }

        c = s.require_client()

        if name == "ps5_list_processes":
            return [{"pid": p.pid, "name": p.name} for p in c.list_processes()]

        if name == "ps5_foreground_app":
            fg = c.foreground_app()
            return {"pid": fg.pid, "titleid": fg.titleid, "contentid": fg.contentid, "name": fg.name, "app_ver": fg.app_ver}

        if name == "ps5_proc_info":
            pid = s.resolve_pid(args.get("pid"))
            info = c.proc_info(pid)
            return {"pid": info.pid, "name": info.name, "path": info.path, "titleid": info.titleid, "contentid": info.contentid}

        if name == "ps5_proc_maps":
            pid = s.resolve_pid(args.get("pid"))
            filt = (args.get("filter_name") or "").lower()
            maps = c.maps(pid)
            if filt:
                maps = [m for m in maps if filt in m.name.lower()]
            return [
                {"name": m.name, "start": hex(m.start), "end": hex(m.end), "size": m.end - m.start, "offset": hex(m.offset), "prot": prot_str(m.prot)}
                for m in maps
            ]

        if name == "ps5_resolve_address":
            pid = s.resolve_pid(args.get("pid"))
            module = args.get("module", "eboot.bin")
            bn_base = parse_int(args.get("bn_base", "0x0"))
            addr = parse_int(args["address"])
            mod = s.module_base(pid, module)
            ps5_base = int(mod["base"], 16)
            direction = args.get("direction", "bn_to_ps5")
            if direction == "bn_to_ps5":
                offset = addr - bn_base
                translated = ps5_base + offset
            else:
                offset = addr - ps5_base
                translated = bn_base + offset
            return {
                "direction": direction,
                "module": module,
                "ps5_base": hex(ps5_base),
                "bn_base": hex(bn_base),
                "offset": hex(offset),
                "input": hex(addr),
                "output": hex(translated),
            }

        if name == "ps5_read_memory":
            pid = s.resolve_pid(args.get("pid"))
            addr = parse_int(args["address"])
            fmt = args.get("format", "hex")
            if fmt in _SCALAR_FMTS:
                sfmt, sz = _SCALAR_FMTS[fmt]
                raw = c.read(pid, addr, sz)
                val = struct.unpack(sfmt, raw)[0]
                return {"address": hex(addr), "format": fmt, "value": val, "hex": hex(val) if isinstance(val, int) else None}
            size = int(args.get("size", 64))
            raw = c.read(pid, addr, size)
            if fmt == "utf8":
                return {"address": hex(addr), "size": len(raw), "text": raw.split(b"\x00", 1)[0].decode("utf-8", "replace")}
            if fmt == "ascii":
                return {"address": hex(addr), "size": len(raw), "text": "".join(chr(b) if 32 <= b < 127 else "." for b in raw)}
            return {"address": hex(addr), "size": len(raw), "hex": raw.hex(" ")}

        if name == "ps5_write_memory":
            pid = s.resolve_pid(args.get("pid"))
            addr = parse_int(args["address"])
            data = bytes.fromhex(args["data_hex"].replace(" ", ""))
            c.write(pid, addr, data)
            return {"written": len(data), "address": hex(addr)}

        if name == "ps5_aob_scan":
            pid = s.resolve_pid(args.get("pid"))
            pat, mask = parse_aob(args["pattern"])
            if "start" in args and "length" in args:
                start = parse_int(args["start"])
                length = int(args["length"])
            else:
                mod = s.module_base(pid, args.get("module", "eboot.bin"))
                start = int(mod["base"], 16)
                length = int(mod["size"])
            hits = c.scan_aob_all(pid, start, length, pat, mask, max_results=int(args.get("max_results", 32)))
            return {"count": len(hits), "addresses": [hex(a) for a in hits]}

        if name == "ps5_disasm_region":
            pid = s.resolve_pid(args.get("pid"))
            addr = parse_int(args["address"])
            length = int(args.get("length", 128))
            insns = c.disasm_region(pid, addr, length)
            return [
                {
                    "addr": hex(i.addr),
                    "length": i.length,
                    "rip_rel_target": hex(i.rip_rel_target) if i.rip_rel_target else None,
                    "mem_disp": hex(i.mem_disp) if i.mem_disp else None,
                    "flags": i.flags,
                }
                for i in insns
            ]

        if name == "ps5_find_xrefs_to":
            pid = s.resolve_pid(args.get("pid"))
            target = parse_int(args["target"])
            if "start" in args and "length" in args:
                start = parse_int(args["start"])
                length = int(args["length"])
            else:
                mod = s.module_base(pid, args.get("module", "eboot.bin"))
                start = int(mod["base"], 16)
                length = int(mod["size"])
            hits = c.find_xrefs_to(pid, start, length, target)
            return {"target": hex(target), "count": len(hits), "xrefs": [hex(a) for a in hits]}

        if name == "ps5_debug_attach":
            pid = s.resolve_pid(args.get("pid"))
            listen_port = int(args.get("listen_port", INTERRUPT_PORT))
            if s.listener is None:
                s.listener = InterruptListener(s._on_stop_event, port=listen_port)
                s.listener.start()
            c.debug_attach(pid)
            s.attached_pid = pid
            return {"attached": True, "pid": pid, "listen_port": listen_port}

        if name == "ps5_debug_detach":
            c.debug_detach()
            s.attached_pid = None
            if s.listener is not None:
                s.listener.stop()
                s.listener = None
            return {"attached": False}

        if name == "ps5_debug_continue":
            c.debug_continue()
            return {"resumed": True}

        if name == "ps5_debug_step":
            lwpid = args.get("lwpid")
            if lwpid is not None:
                c.debug_step_thread(int(lwpid))
            else:
                c.debug_step()
            return {"stepped": True, "lwpid": lwpid}

        if name == "ps5_debug_set_breakpoint":
            idx = int(args.get("index", 0))
            addr = parse_int(args["address"])
            enabled = bool(args.get("enabled", True))
            c.debug_set_breakpoint(idx, enabled, addr)
            return {"index": idx, "address": hex(addr), "enabled": enabled}

        if name == "ps5_debug_set_watchpoint":
            idx = int(args.get("index", 0))
            addr = parse_int(args["address"])
            wtype = WATCH_TYPE[args.get("watch_type", "write")]
            wlen = WATCH_LEN[int(args.get("length", 4))]
            enabled = bool(args.get("enabled", True))
            c.debug_set_watchpoint(idx, enabled, wlen, wtype, addr)
            return {"index": idx, "address": hex(addr), "enabled": enabled}

        if name == "ps5_debug_wait_stop":
            timeout = float(args.get("timeout", 10.0))
            ev = s.stop_events.get(timeout=timeout)
            return format_stop_event(ev)

        if name == "ps5_debug_threads":
            lwpids = c.debug_threads()
            out = []
            for tid in lwpids:
                prio, tname = c.debug_thread_info(tid)
                out.append({"lwpid": tid, "priority": prio, "name": tname})
            return out

        if name == "ps5_debug_suspend_thread":
            tid = int(args["lwpid"])
            c.debug_suspend_thread(tid)
            return {"suspended": tid}

        if name == "ps5_debug_resume_thread":
            tid = int(args["lwpid"])
            c.debug_resume_thread(tid)
            return {"resumed": tid}

        if name == "ps5_debug_get_regs":
            tid = int(args["lwpid"])
            blob = c.debug_getregs(tid)
            regs = parse_regs(blob)
            return {"lwpid": tid, "rflags_text": flags_text(regs.get("rflags", 0)), "regs": {k: hex(v) for k, v in regs.items()}}

        if name == "ps5_debug_read_stack":
            pid = s.resolve_pid(args.get("pid"))
            rbp = parse_int(args["rbp"])
            rsp = parse_int(args["rsp"])
            depth = int(args.get("depth", 16))
            frames = c.read_stack(pid, rbp, rsp, depth=depth)
            return [
                {"rbp": hex(fr.rbp), "rsp": hex(fr.rsp), "saved_rbp": hex(fr.saved_rbp), "ret_addr": hex(fr.ret_addr), "flags": fr.flags}
                for fr in frames
            ]

        if name == "ps5_klog_start":
            host = args.get("host") or s.host or os.environ.get("PS5_DEBUG_HOST")
            if not host:
                raise ValueError("Provide 'host' or connect first")
            port = int(args.get("port", KLOG_PORT))
            s.klog.start(host, port=port)
            return {"klog_running": True, "host": host, "port": port}

        if name == "ps5_klog_stop":
            s.klog.stop()
            return {"klog_running": False}

        if name == "ps5_klog_tail":
            lines = s.klog.tail(count=int(args.get("lines", 50)), filter_text=args.get("filter_text"))
            return {"count": len(lines), "lines": lines}

        raise KeyError(f"Unknown tool: {name}")

    def handle_request(self, msg: dict[str, Any]) -> Optional[dict[str, Any]]:
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ps5debug-mcp", "version": "0.1.0"},
                },
            }
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.tools}}
        if method == "tools/call":
            tname = params.get("name", "")
            targs = params.get("arguments") or {}
            try:
                res = self.call_tool(tname, targs)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {exc}"}],
                        "isError": True,
                    },
                }

        if req_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def main() -> None:
    server = MCPServer()
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = server.handle_request(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
