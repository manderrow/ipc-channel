const mach = @import("mach.zig");

pub const name_t = *const c_char;

pub extern "C" fn bootstrap_register2(
    bp: mach.mach_port_t,
    service_name: name_t,
    sp: mach.mach_port_t,
    flags: u64,
) mach.kern_return_t;

pub extern "C" fn bootstrap_look_up(
    bp: mach.mach_port_t,
    service_name: name_t,
    sp: *mach.mach_port_t,
) mach.kern_return_t;
