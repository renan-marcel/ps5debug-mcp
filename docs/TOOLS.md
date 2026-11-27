# MCP Tools Reference

All tools return JSON text payloads. Addresses accept either integers or hex strings (`"0x700001234"`). When `pid` is omitted, the server uses the currently attached PID or queries `ps5_foreground_app`.

## Connection & Status

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `ps5_connect` | `host` (or `PS5_DEBUG_HOST`), `port=744`, `timeout=8.0` | Connects to `ps5debug-NG` and fetches protocol version, FW version, and branding. |
| `ps5_disconnect` | — | Detaches debugger (if attached), stops klog/interrupt listeners, closes TCP socket. |
| `ps5_status` | — | Shows connection state, attached PID, listener state, queued stop events, and klog status. |

## Processes, Maps & ASLR Translation

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `ps5_list_processes` | — | Lists all running processes (`pid`, `name`). |
| `ps5_foreground_app` | — | Returns the active foreground title (`pid`, `titleid`, `contentid`, `name`, `app_ver`). |
| `ps5_proc_info` | `pid` (optional) | Returns `name`, `path`, `titleid`, and `contentid`. |
| `ps5_proc_maps` | `pid`, `filter_name` | Lists virtual memory segments (`start`, `end`, `size`, `offset`, `prot`). |
| `ps5_resolve_address` | `address`, `pid`, `module="eboot.bin"`, `bn_base="0x0"`, `direction="bn_to_ps5"` | Converts between Binary Ninja / ELF addresses and live PS5 ASLR addresses. |

## Memory, AOB Scan & Server-Side Disassembly

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `ps5_read_memory` | `address`, `pid`, `size=64`, `format="hex"` | Reads bytes as `hex`, `utf8`, `ascii`, or scalars (`u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`f32`/`f64`). |
| `ps5_write_memory` | `address`, `data_hex`, `pid` | Writes hex bytes with server-side verification (`write` / `v1.1+`). |
| `ps5_aob_scan` | `pattern`, `pid`, `start`, `length`, `module="eboot.bin"`, `max_results=32` | Scans module or range for byte patterns with `??` wildcards. |
| `ps5_disasm_region` | `address`, `pid`, `length=128` | Server-side Zydis disassembly (returns address, length, `rip_rel_target`, `mem_disp`). |
| `ps5_find_xrefs_to` | `target`, `pid`, `start`, `length`, `module="eboot.bin"` | Finds RIP-relative instructions referencing `target`. |

## Live Debugging (`ptrace` + Port 755)

> [!NOTE]
> `ps5_debug_attach` binds TCP port `755` on the host PC so `ps5debug-NG` can connect back with stop events. Ensure your firewall permits TCP `755` from the PS5.

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `ps5_debug_attach` | `pid`, `listen_port=755` | Starts interrupt listener and attaches to `pid`. |
| `ps5_debug_detach` | — | Detaches and stops the interrupt listener. |
| `ps5_debug_continue` | — | Resumes all threads. |
| `ps5_debug_step` | `lwpid` (optional) | Single-steps the stopped process or a specific thread. |
| `ps5_debug_set_breakpoint` | `address`, `index=0`, `enabled=true` | Sets/clears a software breakpoint (`0xCC`, slots `0..29`). |
| `ps5_debug_set_watchpoint` | `address`, `index=0`, `watch_type="write"`, `length=4`, `enabled=true` | Sets/clears hardware `DR0..DR3` watchpoint (`exec`, `write`, `read/write`; `1/2/4/8` bytes). |
| `ps5_debug_wait_stop` | `timeout=10.0` | Waits for next `StopEvent` (`lwpid`, `signame`, `tdname`, `dr6`, all GP registers). |
| `ps5_debug_threads` | — | Lists `lwpid`, priority, and thread name. |
| `ps5_debug_suspend_thread` | `lwpid` | Suspends a thread. |
| `ps5_debug_resume_thread` | `lwpid` | Resumes a thread. |
| `ps5_debug_get_regs` | `lwpid` | Reads FreeBSD amd64 GP registers (`rip`, `rsp`, `rbp`, `rax`..`r15`, `rflags`). |
| `ps5_debug_read_stack` | `rbp`, `rsp`, `pid`, `depth=16` | Server-side RBP stack walk (up to 64 frames). |

## Kernel Log (`/dev/klog`, Port 3232)

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `ps5_klog_start` | `host` (optional), `port=3232` | Starts background `/dev/klog` ring buffer (2,000 lines). |
| `ps5_klog_stop` | — | Stops background `/dev/klog` reader. |
| `ps5_klog_tail` | `lines=50`, `filter_text` | Returns the newest kernel log lines (with optional substring filter). |
