const std = @import("std");

const mach = @import("mach.zig");

pub const ErrorCode = enum(std.c.kern_return_t) {
    NOT_PRIVILEGED = 1100,
    NAME_IN_USE = 1101,
    UNKNOWN_SERVICE = 1102,
    SERVICE_ACTIVE = 1103,
    BAD_COUNT = 1104,
    NO_MEMORY = 1105,
    NO_CHILDREN = 1106,
};

pub fn register2(bp: mach.Port, service_name: [*:0]const u8, sp: mach.Port, flags: u64) !void {
    const rt = bootstrap_register2(bp, service_name, sp, flags);
    if (rt == ErrorCode.NAME_IN_USE) {
        return error.NameInUse;
    }
    if (rt == ErrorCode.NOT_PRIVILEGED) {
        return error.AccessDenied;
    }
    try mach.checkKernOrMachReturn(rt);
}

pub extern "C" fn bootstrap_register2(
    bp: mach.Port,
    service_name: [*:0]const u8,
    sp: mach.Port,
    flags: u64,
) mach.kern_or_mach_msg_return_t;

pub extern "C" fn bootstrap_look_up(
    bp: mach.Port,
    service_name: [*:0]const u8,
    sp: *mach.Port,
) mach.kern_or_mach_msg_return_t;
