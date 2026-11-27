# Combining `ps5debug-mcp` with Binary Ninja MCP

Using `binary-ninja` MCP for static analysis alongside `ps5debug-mcp` for live PS5 inspection gives you a full static + dynamic debugging loop for `eboot.bin`.

## 1. Load the Unstripped ELF in Binary Ninja

When debugging a Longshot PS5 build, open the unstripped ELF (`llvm-pie.elf` or `eboot.elf.new`) in Binary Ninja rather than the signed `eboot.bin`, so all runtime symbols (`hos_oot_heap_free`, `memory_guest_discard`, `f_803b44e0`, etc.) are preserved.

Note Binary Ninja's image base (`bn_binary_view_info` -> typically `0x0` or `0x400000`).

## 2. Connect & Resolve ASLR Base

1. `ps5_connect(host="<PS5_IP>")`
2. `ps5_klog_start()` (captures any kernel/page-fault messages while testing)
3. `ps5_foreground_app()` -> gets the live `pid` of `eboot.bin`
4. `ps5_resolve_address(address="<bn_func_va>", bn_base="0x400000", direction="bn_to_ps5")`
   - Queries `ps5_proc_maps` for `eboot.bin` and returns `ps5_base + (bn_func_va - bn_base)`.

## 3. Inspect Live State Without Stopping the Game

- Read global counters, structs, or guest memory directly with `ps5_read_memory`.
- Verify code bytes or hooks with `ps5_disasm_region`.
- Tail `/dev/klog` with `ps5_klog_tail(filter_text="SIG")` if the title closes unexpectedly.

## 4. Breakpoints, Watchpoints & Stack Translation

1. `ps5_debug_attach(pid=<pid>)`
2. `ps5_debug_set_breakpoint(index=0, address="<ps5_va>")` or `ps5_debug_set_watchpoint(...)`
3. `ps5_debug_wait_stop(timeout=30)`
4. Take `rip` and `ret_addr` frames from `ps5_debug_read_stack`, and translate them back with:
   `ps5_resolve_address(address="<rip>", bn_base="0x400000", direction="ps5_to_bn")`
5. Pass the resulting address to Binary Ninja's `bn_function_info` / `bn_function_decompile` to see the exact C/C++ source context.
6. Always call `ps5_debug_detach()` before closing the session so the game resumes cleanly.
