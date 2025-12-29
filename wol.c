// I LOVE WRITE
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

// From <arpa/inet.h>, but more streamlined
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int s_addr;
    char sin_zero[8];
};

// GCC on my phone was winging
// Thus strings are hardcoded here
const char help[] = "Usage: ./wol MAC\n\tMAC\tThe target device's MAC address in the form XX:XX:XX:XX:XX:XX\n";
const char sent[] = "WOL packet sent to ";
const char newline[] = "\n";
const char err_socket[] = "Failed to create socket!\n";
const char err_setsockopt[] = "Failed to enable broadcast!\n";
const char err_sendto[] = "Failed to send WOL packet!\n";

// I LOVE REIMPLEMENTING STANDARD LIBRARY FUNCTIONS
void* memset(void *s, int c, size_t n) {
    for (size_t i = 0; i < n; i++)
        ((char*)s)[i] = (char)c;
    return s;
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
    unsigned char MAC[6];
    if (parse_mac(argv[1], MAC) != 0)
        goto invalid_arg; // I LOVE GOTO

    // Create the socket, without <sys/socket.h>, because syscalls are awesome
    int sock = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        print(err_socket);
        return 1;
    }

    // Enable broadcast on the socket, as per WOL
    int broadcast = 1;
    if (sys_setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1) {
        print(err_setsockopt);
        return 1;
    }

    // Config the socket
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0x8315; // Can be whatever for WOL
    addr.s_addr = 0xFFFFFFFF; // 255.255.255.255

    // The WOL packet contains an FF:FF:FF:FF:FF:FF MAC addr, followed by the target MAC repeated 16 times
    unsigned char packet[102];
    memset(packet, 0xFF, 6);
    for (int i = 0; i < 16; i++)
        for (int m = 0; m < sizeof(MAC); m++)
            packet[6 + i*6 + m] = MAC[m];
    if (sys_sendto(sock, packet, sizeof(packet), 0, &addr, sizeof(addr)) == -1) {
        print(err_sendto);
        return -1;
    }

    // A nice message is always appreciated, even if its a pain without printf
    print(sent);
    sys_write(STDOUT_FD, argv[1], strlen(argv[1]));
    print(newline);

    return 0;
}

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