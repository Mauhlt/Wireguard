//! The tunnel service's status as the service control manager sees it, as
//! a small state machine behind a reporting seam: the real service reports
//! through SetServiceStatus, the tests through a recording fake.
//!
//!   stopped --starting--> start_pending --running--> running
//!   start_pending|running --stopping--> stop_pending
//!   any --stopped(exit)--> stopped (final)
//!
//! Rules (from the SCM documentation):
//! * pending states carry a wait hint and a checkpoint that grows with every
//!   progress report; non-pending states report checkpoint 0;
//! * controls are accepted only while running (STOP, SHUTDOWN);
//! * a stop that arrives while starting is remembered: `running` then goes
//!   straight to stop_pending, so the SCM never sees "running" after it
//!   asked us to stop;
//! * stopped is final: later reports are ignored.
//! Not thread-safe by itself; the Windows wrapper serialises the service
//! thread and the control handler.

const std = @import("std");

pub const State = enum(u32) {
    stopped = 1,
    start_pending = 2,
    stop_pending = 3,
    running = 4,
};

pub const accept_stop: u32 = 0x1;
pub const accept_shutdown: u32 = 0x4;
pub const error_service_specific: u32 = 1066; // ERROR_SERVICE_SPECIFIC_ERROR

pub const start_wait_hint_ms: u32 = 30_000; // DNS + adapter creation
pub const stop_wait_hint_ms: u32 = 10_000;

/// Why the service stopped (its service-specific exit code; 0 = clean).
/// `zwg installtunnel` maps these back to messages.
pub const Exit = enum(u32) {
    ok = 0,
    config_unreadable = 1,
    config_invalid = 2,
    endpoint_unresolved = 3,
    wintun_missing = 4,
    adapter_failed = 5,
    address_failed = 6,
    device_failed = 7,
    control_pipe_failed = 8,
    bad_arguments = 9,

    pub fn message(e: Exit) []const u8 {
        return switch (e) {
            .ok => "stopped",
            .config_unreadable => "the stored configuration could not be read or decrypted",
            .config_invalid => "the stored configuration is invalid",
            .endpoint_unresolved => "a peer endpoint could not be resolved (DNS)",
            .wintun_missing => "wintun.dll was not found next to the service's zwg.exe or in System32",
            .adapter_failed => "the Wintun adapter could not be created",
            .address_failed => "an interface address could not be set",
            .device_failed => "the WireGuard device failed",
            .control_pipe_failed => "the control pipe could not be created",
            .bad_arguments => "the service was registered with bad arguments",
        };
    }
};

pub const Report = struct {
    state: State,
    controls_accepted: u32,
    win32_exit_code: u32 = 0,
    service_exit_code: u32 = 0,
    checkpoint: u32 = 0,
    wait_hint_ms: u32 = 0,
};

pub const Reporter = struct {
    ctx: *anyopaque,
    report: *const fn (ctx: *anyopaque, r: Report) void,
};

pub const Machine = struct {
    reporter: Reporter,
    state: State = .stopped,
    checkpoint: u32 = 0,
    stop_requested: bool = false,
    final: bool = false,

    pub fn init(reporter: Reporter) Machine {
        return .{ .reporter = reporter };
    }

    /// Start (or another start step done): start_pending, checkpoint + 1.
    pub fn starting(m: *Machine) void {
        if (m.final) return;
        switch (m.state) {
            .stopped, .start_pending => {
                m.state = .start_pending;
                m.checkpoint += 1;
                m.emit(start_wait_hint_ms);
            },
            .running, .stop_pending => {},
        }
    }

    /// Up: running, or straight to stop_pending if a stop came in meanwhile.
    pub fn running(m: *Machine) void {
        if (m.final or m.state != .start_pending) return;
        m.checkpoint = 0;
        if (m.stop_requested) {
            m.state = .stop_pending;
            m.checkpoint = 1;
            m.emit(stop_wait_hint_ms);
            return;
        }
        m.state = .running;
        m.emit(0);
    }

    /// Stop progress: stop_pending, checkpoint + 1.
    pub fn stopping(m: *Machine) void {
        if (m.final) return;
        switch (m.state) {
            .running => {
                m.state = .stop_pending;
                m.checkpoint = 1;
                m.emit(stop_wait_hint_ms);
            },
            .stop_pending => {
                m.checkpoint += 1;
                m.emit(stop_wait_hint_ms);
            },
            .start_pending => m.stop_requested = true,
            .stopped => {},
        }
    }

    /// Final report.
    pub fn stopped(m: *Machine, exit: Exit) void {
        if (m.final) return;
        m.final = true;
        m.state = .stopped;
        m.checkpoint = 0;
        m.reporter.report(m.reporter.ctx, .{
            .state = .stopped,
            .controls_accepted = 0,
            .win32_exit_code = if (exit == .ok) 0 else error_service_specific,
            .service_exit_code = @intFromEnum(exit),
        });
    }

    pub const Control = enum(u32) { stop = 1, interrogate = 4, shutdown = 5, _ };
    pub const ControlResult = enum { handled_stop, handled, not_implemented };

    /// A control from the SCM. `handled_stop` = the caller must now signal
    /// the device to stop.
    pub fn control(m: *Machine, c: Control) ControlResult {
        switch (c) {
            .stop, .shutdown => {
                if (m.final) return .handled;
                const was = m.state;
                m.stopping();
                return if (was == .stopped) .handled else .handled_stop;
            },
            .interrogate => {
                if (!m.final) m.emit(m.hint());
                return .handled;
            },
            _ => return .not_implemented,
        }
    }

    fn hint(m: *const Machine) u32 {
        return switch (m.state) {
            .start_pending => start_wait_hint_ms,
            .stop_pending => stop_wait_hint_ms,
            else => 0,
        };
    }

    fn emit(m: *Machine, wait_hint_ms: u32) void {
        m.reporter.report(m.reporter.ctx, .{
            .state = m.state,
            .controls_accepted = if (m.state == .running) accept_stop | accept_shutdown else 0,
            .checkpoint = m.checkpoint,
            .wait_hint_ms = wait_hint_ms,
        });
    }
};

// ---- tests: a fake SCM that records every report ---------------------------

const FakeScm = struct {
    reports: [32]Report = undefined,
    n: usize = 0,

    fn record(ctx: *anyopaque, r: Report) void {
        const f: *FakeScm = @ptrCast(@alignCast(ctx));
        f.reports[f.n] = r;
        f.n += 1;
    }

    fn reporter(f: *FakeScm) Reporter {
        return .{ .ctx = f, .report = record };
    }

    fn states(f: *const FakeScm, buf: []State) []State {
        for (f.reports[0..f.n], 0..) |r, i| buf[i] = r.state;
        return buf[0..f.n];
    }

    /// Invariants every SCM report must satisfy.
    fn check(f: *const FakeScm) !void {
        var last_cp: u32 = 0;
        var last_state: ?State = null;
        for (f.reports[0..f.n]) |r| {
            switch (r.state) {
                .start_pending, .stop_pending => {
                    try std.testing.expect(r.wait_hint_ms > 0);
                    try std.testing.expect(r.checkpoint > 0);
                    if (last_state == r.state) try std.testing.expect(r.checkpoint > last_cp);
                    try std.testing.expectEqual(@as(u32, 0), r.controls_accepted);
                },
                .running => {
                    try std.testing.expectEqual(@as(u32, 0), r.checkpoint);
                    try std.testing.expectEqual(accept_stop | accept_shutdown, r.controls_accepted);
                },
                .stopped => {
                    try std.testing.expectEqual(@as(u32, 0), r.checkpoint);
                    try std.testing.expectEqual(@as(u32, 0), r.controls_accepted);
                },
            }
            last_cp = r.checkpoint;
            last_state = r.state;
        }
        if (f.n > 0) try std.testing.expectEqual(State.stopped, f.reports[f.n - 1].state);
    }
};

test "normal start, stop control, clean exit" {
    var f: FakeScm = .{};
    var m = Machine.init(f.reporter());
    m.starting();
    m.starting(); // progress
    m.running();
    try std.testing.expectEqual(Machine.ControlResult.handled_stop, m.control(.stop));
    m.stopping(); // progress while tearing down
    m.stopped(.ok);
    var buf: [32]State = undefined;
    try std.testing.expectEqualSlices(State, &.{ .start_pending, .start_pending, .running, .stop_pending, .stop_pending, .stopped }, f.states(&buf));
    try std.testing.expectEqual(@as(u32, 2), f.reports[1].checkpoint);
    try std.testing.expectEqual(@as(u32, 0), f.reports[5].win32_exit_code);
    try f.check();
}

test "failure while starting reports a service-specific exit code" {
    var f: FakeScm = .{};
    var m = Machine.init(f.reporter());
    m.starting();
    m.stopped(.adapter_failed);
    m.running(); // ignored: stopped is final
    m.stopping();
    _ = m.control(.interrogate);
    var buf: [32]State = undefined;
    try std.testing.expectEqualSlices(State, &.{ .start_pending, .stopped }, f.states(&buf));
    try std.testing.expectEqual(error_service_specific, f.reports[1].win32_exit_code);
    try std.testing.expectEqual(@intFromEnum(Exit.adapter_failed), f.reports[1].service_exit_code);
    try f.check();
}

test "stop during start never shows running" {
    var f: FakeScm = .{};
    var m = Machine.init(f.reporter());
    m.starting();
    try std.testing.expectEqual(Machine.ControlResult.handled_stop, m.control(.shutdown));
    m.running();
    m.stopped(.ok);
    var buf: [32]State = undefined;
    try std.testing.expectEqualSlices(State, &.{ .start_pending, .stop_pending, .stopped }, f.states(&buf));
    try f.check();
}

test "interrogate repeats the current state; unknown controls are refused" {
    var f: FakeScm = .{};
    var m = Machine.init(f.reporter());
    m.starting();
    m.running();
    try std.testing.expectEqual(Machine.ControlResult.handled, m.control(.interrogate));
    try std.testing.expectEqual(Machine.ControlResult.not_implemented, m.control(@enumFromInt(0x7f)));
    try std.testing.expectEqual(Machine.ControlResult.handled_stop, m.control(.stop));
    try std.testing.expectEqual(Machine.ControlResult.handled_stop, m.control(.stop)); // repeated: still stopping
    m.stopped(.ok);
    try std.testing.expectEqual(Machine.ControlResult.handled, m.control(.stop)); // after the end
    var buf: [32]State = undefined;
    try std.testing.expectEqualSlices(State, &.{ .start_pending, .running, .running, .stop_pending, .stop_pending, .stopped }, f.states(&buf));
    try f.check();
}
