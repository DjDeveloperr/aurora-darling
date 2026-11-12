// OWN public IOKit boundary harness; opaque reply bytes are never interpreted.
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOServiceNameMatching("IOSurfaceRoot"));
    if (!service) {
        puts("{\"schema\":\"iosurface_init_boundary_v1\",\"matched\":false}");
        return 0;
    }
    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t opened = IOServiceOpen(service, mach_task_self(), 0, &connection);
    kern_return_t released = IOObjectRelease(service);
    if (opened != KERN_SUCCESS) {
        printf("{\"schema\":\"iosurface_init_boundary_v1\",\"matched\":true,"
               "\"open_status\":%u,\"service_release_status\":%u}\n",
               (uint32_t)opened, (uint32_t)released);
        return 0;
    }
    struct {
        uint64_t before;
        uint8_t bytes[24];
        uint64_t after;
    } reply;
    reply.before = UINT64_C(0x6259474144525547);
    reply.after = reply.before;
    memset(reply.bytes, 0xa5, sizeof(reply.bytes));
    size_t length = sizeof(reply.bytes);
    kern_return_t status = IOConnectCallMethod(connection, 13, NULL, 0,
        NULL, 0, NULL, NULL, reply.bytes, &length);
    size_t changed = 0, zeros = 0;
    for (size_t i=0; i<sizeof(reply.bytes); ++i) {
        changed += reply.bytes[i] != 0xa5;
        zeros += reply.bytes[i] == 0;
    }
    int guards = reply.before == UINT64_C(0x6259474144525547)
        && reply.after == UINT64_C(0x6259474144525547);
    kern_return_t closed = IOServiceClose(connection);
    printf("{\"schema\":\"iosurface_init_boundary_v1\",\"matched\":true,"
           "\"open_status\":%u,\"service_release_status\":%u,\"call_status\":%u,"
           "\"returned_size\":%zu,\"changed_bytes\":%zu,\"zero_bytes\":%zu,"
           "\"guards_intact\":%s,\"close_status\":%u}\n",
           (uint32_t)opened, (uint32_t)released, (uint32_t)status,
           length, changed, zeros, guards ? "true" : "false", (uint32_t)closed);
    return guards ? 0 : 2;
}
