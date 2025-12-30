// Needed for the write syscall, which is exclusively used for writing to stdout
#define STDOUT_FD 1
// Socket consts
#define AF_INET 2
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_BROADCAST 6
// Syscalls
#if defined(__x86_64__)
    #define SYS_WRITE 1
    #define SYS_SOCKET 41
    #define SYS_SETSOCKOPT 54
    #define SYS_SENDTO 44
#elif defined(__aarch64__)
    #define SYS_WRITE 64
    #define SYS_SOCKET 198
    #define SYS_SETSOCKOPT 208
    #define SYS_SENDTO 206
#endif

// We dont get size_t for free :(
typedef unsigned long size_t;

// A manual creation of sockaddr_in from <arpa/inet.h>
// This way we don't need any Pesky Structs, also I thought it'd be fun to manually create it :)
// This is why I love C, I can just do this and it makes sense
const unsigned char sockaddr[] = {
    0x02, 0x00, // short sin_family = AF_INET = 2
    0x15, 0x83, // unsigned short port = 0x8315 (port doesn't matter with WOL so it can be anything) (also network order)
    255,255,255,255, // Dest IP is the broadcast IP (255.255.255.255)
    0,0,0,0,0,0,0,0, // Padding with 8 0s
};

// GCC on my phone was winging
// Thus strings are hardcoded here
const char help[] = "Usage: ./wol MAC\n\tMAC\tThe target device's MAC address in the form of XX:XX:XX:XX:XX:XX\n";
const char sent[] = "WOL packet sent to ";
const char err_socket[] = "Failed to create socket!\n";
const char err_setsockopt[] = "Failed to enable broadcast!\n";
const char err_sendto[] = "Failed to send WOL packet!\n";

// I LOVE REIMPLEMENTING STANDARD LIBRARY FUNCTIONS
void *memcpy(void *dest, const void *src, size_t n) {
    for (size_t i = 0; i < n; i++)
        ((char*)dest)[i] = ((char*)src)[i];
    return dest;
}
size_t strlen(const char *str) {
    size_t len = 0;
    for (; str[len] != '\0'; len++);
    return len;
}

// Generic syscall function, can popupate unused args with whatever you want, should be able to execute any and all syscalls in x64/amd64
static inline long syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret = -1;

    #if defined (__x86_64__)
        register long r10_a4 asm("r10") = a4;
        register long r8_a5  asm("r8")  = a5;
        register long r9_a6  asm("r9")  = a6;

        asm volatile (
            "syscall"
            : "=a"(ret) // Return val is in rax
            : "a"(n),   // Syscall number in rax
              "D"(a1),  // arg 1 in rdi
              "S"(a2),  // arg 2 in rsi
              "d"(a3),  // arg 3 in rdx
              "r"(r10_a4),
              "r"(r8_a5),
              "r"(r9_a6)
            : "rcx", "r11", "memory"
        );
    #elif defined (__aarch64__)
        register long x0_a1 asm("x0") = a1;
        register long x1_a2 asm("x1") = a2;
        register long x2_a3 asm("x2") = a3;
        register long x3_a4 asm("x3") = a4;
        register long x4_a5 asm("x4") = a5;
        register long x5_a6 asm("x5") = a6;
        register long x8_n  asm("x8") = n;

        asm volatile (
            "svc #0"
            : "+r"(x0_a1) // Return value is in x0
            : "r"(x1_a2),
              "r"(x2_a3),
              "r"(x3_a4),
              "r"(x4_a5),
              "r"(x5_a6),
              "r"(x8_n)  // Syscall num is in x8
            : "memory"
        );
        ret = x0_a1;
    #endif

    return ret;
}

// Helpful syscall macros, now I don't need 4 duplicate functions that do almost the same thing but use ~50 lines each
#define sys_write(fd, buf, count) syscall(SYS_WRITE, (long)fd, (long)buf, (long)count, 0, 0, 0)
#define sys_socket(family, type, protocol) syscall(SYS_SOCKET, (long)family, (long)type, (long)protocol, 0, 0, 0)
#define sys_setsockopt(fd, level, optname, optval, optlen) syscall(SYS_SETSOCKOPT, (long)fd, (long)level, (long)optname, (long)optval, (long)optlen, 0)
#define sys_sendto(fd, buf, len, flags, addr, addr_len) syscall(SYS_SENDTO, (long)fd, (long)buf, (long)len, (long)flags, (long)addr, (long)addr_len)

// Print would be nice
#define print(s) sys_write(STDOUT_FD, s, sizeof(s)-1)

// Convenient error check macro that's definetly not inspired by ESP_ERR_CHECK
#define ERR_CHECK(x, s) \
{ \
    int errno = x; \
    if (errno < 0) { \
        print(s); \
        return -errno; \
    } \
}

/* ==== The actual program! ==== */
// Converts a nibble character to its corresponding byte
unsigned char nibble_to_byte(char nibble) {
    // 0-9
    if (nibble >= 48 && nibble <= 57)
        return nibble - 48;
    // A-F
    if (nibble >= 65 && nibble <= 70)
        return nibble - 65 + 0xA;
    // a-f (just in case)
    if (nibble >= 97 && nibble <= 102)
        return nibble - 97 + 0xa;
    // Default, return 255 since its certainly invalid for a nibble
    return 0xFF;
}
// Converts the characters at *hex and *(hex+1) to a single byte
static inline unsigned char hex_to_byte(char *hex) {
    return (nibble_to_byte(hex[0]) << 4) | nibble_to_byte(hex[1]);
}

// Helper func so I can pass a MAC address in via command line
// Takes in the MAC string and a pointer to a 6-byte buffer for the MAC address
// The MAC can be either of format XX:XX:... or XXXXXX..., anything else is invalid
int parse_mac(const char *str, unsigned char *out) {
    // A valid MAC is either 17 chars for XX_XX:... (where _ is any character), or 12 chars for XXxxXX...
    size_t mac_len = strlen(str);
    if (mac_len != 17 && mac_len != 12)
        return 1;
    int seg_len = mac_len == 17 ? 3 : 2;

    for (int i = 0; i < 6; i++)
        out[i] = hex_to_byte((char*)str + i*seg_len);
    return 0;
}

int main(int argc, char **argv) {
    // Can't run the program if we don't have a MAC address lmao
    if (argc < 2) {
invalid_arg:
        print(help);
        return 1;
    }

    // Need to convert the string MAC addr to its actual byte representation
    char *mac_str = argv[1];
    unsigned char MAC[6];
    if (parse_mac(mac_str, MAC) != 0)
        goto invalid_arg; // I LOVE GOTO

    // Create the socket, without <sys/socket.h>, because syscalls are awesome
    int sock = sys_socket(AF_INET, SOCK_DGRAM, 0);
    ERR_CHECK(sock, err_socket);

    // Enable broadcast on the socket, as per WOL
    int broadcast = 1;
    ERR_CHECK(sys_setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)), err_setsockopt);

    // The WOL packet contains an FF:FF:FF:FF:FF:FF MAC addr, followed by the target MAC repeated 16 times
    unsigned char packet[102];
    ((long*)packet)[0] = -1; // Cheap trick to set the first 6 bytes to the FF MAC addr (plus the next two but who cares they get overwritten)
    for (int i = 0; i < 16; i++)
        for (int m = 0; m < sizeof(MAC); m++)
            packet[6 + i*6 + m] = MAC[m];
    ERR_CHECK(sys_sendto(sock, packet, sizeof(packet), 0, sockaddr, sizeof(sockaddr)), err_sendto);

    // A nice message is always appreciated, even if its a pain without printf
    char nice_message[sizeof(sent)-1 + 17 + 2]; // 17 max chars for the MAC address, 1 for the newline and 1 extra byte since the print() macro assumes a null byte and prints sizeof-1
    size_t mac_len = strlen(mac_str);
    mac_str[mac_len] = '\n'; // We don't need the \0 anymore, discard it

    // Constructing it myself to save 2 extra write syscalls, bit of a nightmare but I mean c'mon look at this project lmao
    memcpy(nice_message, sent, sizeof(sent)-1);
    memcpy(nice_message+sizeof(sent)-1, mac_str, mac_len+1);
    print(nice_message);

    return 0;
}

// Custom _start entrypoint as a naked function since a prologue could mess up the stack
__attribute__((naked)) void _start(void) {
    #if defined(__x86_64__)
        asm volatile (
            // Load argc (*rsp) and argv (rsp+8) into the argument registers
            "mov rdi, [rsp]\n"
            "lea rsi, [rsp+8]\n"

            // Offset the stack by 8 so it's aligned to 16 bytes
            "sub rsp, 8\n"
            
            // Call main!
            "call main\n"

            // Execute exit syscall, copying the return code from main into rdi and setting the syscall number into rax
            "mov rdi, rax\n"
            "mov rax, 60\n"
            "syscall\n"
        );
    #elif defined(__aarch64__)
        asm volatile (
            // Load argc (*sp) and argv (sp+8) into the argument registers
            "ldr x0, [sp]\n"
            "add x1, sp, #8\n"

            // Call main!
            "bl main\n"

            // Execute exit syscall, x0 (exit code) is already populated by the main() call
            "mov x8, #93\n"
            "svc #0\n"
        );
    #endif
}