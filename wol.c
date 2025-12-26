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
const char help[] = "Usage: ./wol MAC\n\tMAC\tThe target device's MAC address in the form XX:XX:XX:XX:XX:XX\n";
const char sent[] = "WOL packet sent to ";
const char newline[] = "\n";

// I LOVE REIMPLEMENTING STANDARD LIBRARY FUNCTIONS
void* memset(void *s, int c, size_t n) {
    char *p = s;
    for (size_t i = 0; i < n; i++)
        p[i] = (char)c;
    return s;
}
size_t strlen(const char *str) {
    size_t len = 0;
    for (; str[len] != '\0'; len++);
    return len;
}

/* ==== Syscall time! ==== */

static inline long sys_write(unsigned int fd, const char *buf, size_t count) {
    long ret = -1;
    #if defined(__x86_64__)
        asm volatile (
            "syscall"
            : "=a"(ret)  // Return value (=) is placed into RAX
            : "a"(SYS_WRITE), // sys_write is syscall number 1, placed into RAX
            "D"(fd),   // File descriptor goes into RDI
            "S"(buf),  // Buffer pointer goes into RSI
            "d"(count) // Byte count goes into rdx
            : "rcx", "r11", "memory" // "syscall" clobbers rcx/r11, also this writes into mem so techincally cloberred too!
        );
    #elif defined(__aarch64__)
        register long r_fd asm("x0") = fd;
        register long r_buf asm("x1") = (long)buf;
        register long r_count asm("x2") = count;
        register long r_syscall_num asm("x8") = SYS_WRITE;

        asm volatile (
            "svc #0"
            : "+r"(r_fd) // x0 contains the return val
            : "r"(r_buf), "r"(r_count), "r"(r_syscall_num)
            : "memory" // Unlike x86, aarch64 only clobbers memory here!
        );
        ret = r_fd;
    #endif
    return ret;
}

static inline long sys_socket(int family, int type, int protocol) {
    long ret = -1;
    #if defined(__x86_64__)
        asm volatile (
            "syscall"
            : "=a"(ret)   // Return value (=) is placed into RAX
            : "a"(SYS_SOCKET), // syscall num, placed into RAX
            "D"(family),  // family goes into RDI
            "S"(type),    // type goes into RSI
            "d"(protocol) // protocol goes into rdx
            : "rcx", "r11", "memory" // "syscall" clobbers rcx/r11, also this writes into mem so techincally cloberred too!
        );
    #elif defined(__aarch64__)
        register long r_family asm("x0") = family;
        register long r_type asm("x1") = type;
        register long r_protocol asm("x2") = protocol;
        register long r_syscall_num asm("x8") = SYS_SOCKET;

        asm volatile (
            "svc #0"
            : "+r"(r_family)
            : "r"(r_type), "r"(r_protocol), "r"(r_syscall_num)
            : "memory"
        );
        ret = r_family;
    #endif
    return ret;
}

static inline long sys_setsockopt(int fd, int level, int optname, const void *optval, int optlen) {
    long ret = -1;
    #if defined(__x86_64__)
        // No mneumonics for these registers, so gotta do it manually
        register long r_optval asm("r10") = (long)optval;
        register long r_optlen asm("r8")  = optlen;

        asm volatile (
            "syscall"
            : "=a"(ret)
            : "a"(SYS_SETSOCKOPT),
            "D"(fd),
            "S"(level),
            "d"(optname),
            "r"(r_optval),
            "r"(r_optlen)
            : "rcx", "r11", "memory"
        );
    #elif defined(__aarch64__)
        register long r_fd asm("x0") = fd;
        register long r_level asm("x1") = level;
        register long r_optname asm("x2") = optname;
        register long r_optval asm("x3") = (long)optval;
        register long r_optlen asm("x4") = optlen;
        register long r_syscall_num asm("x8") = SYS_SETSOCKOPT;

        asm volatile (
            "svc #0"
            : "+r"(r_fd)
            : "r"(r_level), "r"(r_optname), "r"(r_optval), "r"(r_optlen), "r"(r_syscall_num)
            : "memory"
        );
        ret = r_fd;
    #endif
    return ret;
}

static inline long sys_sendto(int fd, const void *buf, size_t len, int flags, const void *addr, unsigned int addr_len) {
    long ret = -1;
    #if defined(__x86_64__)
        register long r_flags asm("r10") = flags;
        register long r_addr  asm("r8")  = (long)addr;
        register long r_addr_len  asm("r9")  = addr_len;

        asm volatile (
            "syscall"
            : "=a"(ret)
            : "a"(SYS_SENDTO),
            "D"(fd),
            "S"(buf),
            "d"(len),
            "r"(r_flags),
            "r"(r_addr),
            "r"(r_addr_len)
            : "rcx", "r11", "memory"
        );
    #elif defined(__aarch64__)
        register long r_fd asm("x0") = fd;
        register long r_buf asm("x1") = (long)buf;
        register long r_len asm("x2") = len;
        register long r_flags asm("x3") = flags;
        register long r_addr asm("x4") = (long)addr;
        register long r_addr_len asm("x5") = addr_len;
        register long r_syscall_num asm("x8") = SYS_SENDTO;

        asm volatile (
            "svc #0"
            : "+r"(r_fd)
            : "r"(r_buf), "r"(r_len), "r"(r_flags), "r"(r_addr), "r"(r_addr_len), "r"(r_syscall_num)
            : "memory"
        );
        ret = r_fd;
    #endif
    return ret;
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
unsigned char hex_to_byte(char *hex) {
    return (nibble_to_byte(hex[0]) << 4) | nibble_to_byte(hex[1]);
}

// Helper func so I can pass a MAC address in via command line
// Takes in the MAC string and a pointer to a 6-byte buffer for the MAC address
// The MAC can be either of format XX:XX:... or XXXXXX..., anything else is invalid
int parse_mac(const char *str, unsigned char *out) {
    // A valid MAC is either 17 chars for XX:XX:..., or 12 chars for XXxxXX...
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
        sys_write(STDOUT_FD, help, strlen(help));
        return 1;
    }

    // Need to convert the string MAC addr to its actual byte representation
    unsigned char MAC[6];
    if (parse_mac(argv[1], MAC) != 0)
        goto invalid_arg; // I LOVE GOTO

    // Enable broadcast on the socket, as per WOL
    int sock = sys_socket(AF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    sys_setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

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
    sys_sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr));

    // A nice message is always appreciated, even if its a pain without printf
    sys_write(STDOUT_FD, sent, strlen(sent));
    sys_write(STDOUT_FD, argv[1], strlen(argv[1]));
    sys_write(STDOUT_FD, newline, strlen(newline));

    return 0;
}