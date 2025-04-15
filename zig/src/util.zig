const std = @import("std");

pub const alloc = std.heap.smp_allocator;

pub fn MergeEnums(comptime A: type, comptime a_prefix: ?[]const u8, comptime B: type, comptime b_prefix: ?[]const u8) type {
    comptime {
        const aInfo = @typeInfo(A).@"enum";
        const bInfo = @typeInfo(B).@"enum";
        if (aInfo.tag_type != bInfo.tag_type) {
            @compileError("Cannot merge enums with different tag types: " ++ @typeName(aInfo.tag_type) ++ " != " ++ @typeName(bInfo.tag_type));
        }
        var fields = (aInfo.fields ++ bInfo.fields).*;
        if (a_prefix) |prefix| {
            for (fields[0..aInfo.fields.len]) |*field| {
                field.name = prefix ++ field.name;
            }
        }
        if (b_prefix) |prefix| {
            for (fields[aInfo.fields.len..]) |*field| {
                field.name = prefix ++ field.name;
            }
        }
        return @Type(.{ .@"enum" = .{
            .tag_type = aInfo.tag_type,
            .fields = &fields,
            .decls = &.{},
            .is_exhaustive = aInfo.is_exhaustive and bInfo.is_exhaustive,
        } });
    }
}

pub fn ExcludeEnumVariant(comptime T: type, comptime variant: T) type {
    comptime {
        const info = @typeInfo(T).@"enum";
        var fields = info.fields;
        for (fields, 0..) |field, i| {
            if (field.value == @intFromEnum(variant)) {
                fields = fields[0..i] ++ fields[i + 1 ..];
                break;
            }
        }
        return @Type(.{ .@"enum" = .{
            .tag_type = info.tag_type,
            .fields = fields,
            .decls = &.{},
            .is_exhaustive = info.is_exhaustive,
        } });
    }
}
