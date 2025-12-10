/*
 * DPDK Packet Processor - High-performance Deep Packet Inspection
 *
 * Replacement for Scapy-based packet inspection with DPDK fast-path.
 * Extracts packet features and exports to Python ML pipeline via shared memory.
 *
 * Features:
 * - Zero-copy packet processing
 * - TCP/UDP/ICMP protocol analysis
 * - Payload entropy calculation
 * - HTTP/DNS/SSH application detection
 * - Flow tracking and statistics
 * - Lock-free ring buffer for Python consumer
 */

#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <math.h>
#include <time.h>
#include <ctype.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048

#define NUM_MBUFS 16384
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_PAYLOAD_SAMPLE 500
#define FEATURE_RING_SIZE 8192

// Packet feature structure (matches Python PacketFeatures)
struct packet_features
{
    char timestamp[32];
    char src_ip[46]; // IPv6 max
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[16];
    uint8_t protocol_num;
    uint32_t size;
    uint32_t payload_size;
    uint8_t ttl;

    // TCP specific
    char tcp_flags[16];
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t window_size;

    // Application layer
    char app_proto[16];
    char http_method[16];
    char http_uri[256];
    char http_host[128];
    char dns_query[256];

    // Payload analysis
    double payload_entropy;
    double payload_printable_ratio;
    uint8_t has_payload;

    // Suspicious flags
    uint8_t suspicious;

    // Payload sample (hex encoded)
    char payload_hex[MAX_PAYLOAD_SAMPLE * 2 + 1];
} __rte_cache_aligned;

// Flow tracking key
struct flow_key
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __rte_cache_aligned;

// Flow statistics
struct flow_stats
{
    uint64_t start_time;
    uint64_t last_seen;
    uint64_t packets_forward;
    uint64_t packets_backward;
    uint64_t bytes_forward;
    uint64_t bytes_backward;
    uint8_t flags_seen;
} __rte_cache_aligned;

// Global statistics
static struct
{
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t features_extracted;
    uint64_t features_exported;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t suspicious_packets;
    uint64_t errors;
} stats;

// Port configuration
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

// Feature export ring (shared with Python)
static struct rte_ring *feature_ring = NULL;

// Flow hash table
static struct rte_hash *flow_table = NULL;

// Running flag
static volatile bool force_quit = false;

/* Signal handler */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Calculate Shannon entropy of payload */
static double
calculate_entropy(const uint8_t *data, uint32_t len)
{
    if (len == 0)
        return 0.0;

    uint32_t freq[256] = {0};

    for (uint32_t i = 0; i < len; i++)
        freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* Calculate printable ASCII ratio */
static double
calculate_printable_ratio(const uint8_t *data, uint32_t len)
{
    if (len == 0)
        return 0.0;

    uint32_t printable = 0;
    for (uint32_t i = 0; i < len; i++)
    {
        if (data[i] >= 32 && data[i] <= 126)
            printable++;
    }

    return (double)printable / len;
}

/* Convert bytes to hex string */
static void
bytes_to_hex(const uint8_t *data, uint32_t len, char *hex_out, uint32_t max_out)
{
    uint32_t out_len = len * 2;
    if (out_len >= max_out)
        out_len = max_out - 1;

    for (uint32_t i = 0; i < out_len / 2; i++)
    {
        sprintf(hex_out + i * 2, "%02x", data[i]);
    }
    hex_out[out_len] = '\0';
}

/* Extract TCP flags as string */
static void
extract_tcp_flags(const struct rte_tcp_hdr *tcp, char *flags_out)
{
    flags_out[0] = '\0';
    char buf[16] = {0};

    if (tcp->tcp_flags & RTE_TCP_SYN_FLAG)
        strcat(buf, "S");
    if (tcp->tcp_flags & RTE_TCP_ACK_FLAG)
        strcat(buf, "A");
    if (tcp->tcp_flags & RTE_TCP_FIN_FLAG)
        strcat(buf, "F");
    if (tcp->tcp_flags & RTE_TCP_RST_FLAG)
        strcat(buf, "R");
    if (tcp->tcp_flags & RTE_TCP_PSH_FLAG)
        strcat(buf, "P");
    if (tcp->tcp_flags & RTE_TCP_URG_FLAG)
        strcat(buf, "U");

    strcpy(flags_out, buf);
}

/* Detect application protocol from payload and ports */
static void
detect_app_protocol(uint16_t src_port, uint16_t dst_port,
                    const uint8_t *payload, uint32_t payload_len,
                    struct packet_features *features)
{
    // HTTP detection
    if ((dst_port == 80 || dst_port == 8080 || dst_port == 8000 ||
         src_port == 80 || src_port == 8080 || src_port == 8000) &&
        payload_len > 0)
    {

        strcpy(features->app_proto, "HTTP");

        // Try to parse HTTP request
        if (payload_len > 16)
        {
            char buf[32];
            snprintf(buf, sizeof(buf), "%.*s", 16, payload);

            // Check for HTTP methods
            if (strncmp((char *)payload, "GET ", 4) == 0)
            {
                strcpy(features->http_method, "GET");
            }
            else if (strncmp((char *)payload, "POST ", 5) == 0)
            {
                strcpy(features->http_method, "POST");
            }
            else if (strncmp((char *)payload, "PUT ", 4) == 0)
            {
                strcpy(features->http_method, "PUT");
            }
            else if (strncmp((char *)payload, "DELETE ", 7) == 0)
            {
                strcpy(features->http_method, "DELETE");
            }
            else if (strncmp((char *)payload, "HEAD ", 5) == 0)
            {
                strcpy(features->http_method, "HEAD");
            }

            // Extract URI (simplified)
            if (features->http_method[0] != '\0')
            {
                const char *uri_start = strchr((char *)payload, ' ');
                if (uri_start)
                {
                    uri_start++;
                    const char *uri_end = strchr(uri_start, ' ');
                    if (uri_end)
                    {
                        size_t uri_len = uri_end - uri_start;
                        if (uri_len >= sizeof(features->http_uri))
                            uri_len = sizeof(features->http_uri) - 1;
                        strncpy(features->http_uri, uri_start, uri_len);
                        features->http_uri[uri_len] = '\0';
                    }
                }
            }

            // Extract Host header (simplified)
            const char *host_hdr = strstr((char *)payload, "\r\nHost: ");
            if (host_hdr)
            {
                host_hdr += 8; // strlen("\r\nHost: ")
                const char *host_end = strstr(host_hdr, "\r\n");
                if (host_end)
                {
                    size_t host_len = host_end - host_hdr;
                    if (host_len >= sizeof(features->http_host))
                        host_len = sizeof(features->http_host) - 1;
                    strncpy(features->http_host, host_hdr, host_len);
                    features->http_host[host_len] = '\0';
                }
            }
        }
    }
    // HTTPS detection
    else if (dst_port == 443 || src_port == 443)
    {
        strcpy(features->app_proto, "HTTPS");
    }
    // SSH detection
    else if (dst_port == 22 || src_port == 22)
    {
        strcpy(features->app_proto, "SSH");
        features->suspicious = 1; // SSH can be suspicious
    }
    // DNS detection (UDP port 53)
    else if (dst_port == 53 || src_port == 53)
    {
        strcpy(features->app_proto, "DNS");
        // TODO: Parse DNS query name
    }
    // Telnet
    else if (dst_port == 23 || src_port == 23)
    {
        strcpy(features->app_proto, "TELNET");
        features->suspicious = 1;
    }
    // RDP
    else if (dst_port == 3389 || src_port == 3389)
    {
        strcpy(features->app_proto, "RDP");
        features->suspicious = 1;
    }
}

/* Extract packet features */
static int
extract_packet_features(struct rte_mbuf *m, struct packet_features *features)
{
    memset(features, 0, sizeof(*features));

    // Timestamp
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(features->timestamp, sizeof(features->timestamp),
             "%Y-%m-%dT%H:%M:%SZ", tm_info);

    // Packet size
    features->size = rte_pktmbuf_pkt_len(m);

    // Parse Ethernet header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    // Only process IPv4 for now (IPv6 support can be added)
    if (eth_type != RTE_ETHER_TYPE_IPV4)
        return -1;

    // Parse IP header
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    // Extract IP addresses
    uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
    uint32_t dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);

    sprintf(features->src_ip, "%u.%u.%u.%u",
            (src_ip >> 24) & 0xFF,
            (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF,
            src_ip & 0xFF);

    sprintf(features->dst_ip, "%u.%u.%u.%u",
            (dst_ip >> 24) & 0xFF,
            (dst_ip >> 16) & 0xFF,
            (dst_ip >> 8) & 0xFF,
            dst_ip & 0xFF);

    features->protocol_num = ip_hdr->next_proto_id;
    features->ttl = ip_hdr->time_to_live;

    // Calculate IP header length
    uint8_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
    uint8_t *l4_hdr = (uint8_t *)ip_hdr + ip_hdr_len;

    uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);
    uint32_t l4_len = ip_total_len - ip_hdr_len;

    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;

    // Parse L4 protocol
    switch (ip_hdr->next_proto_id)
    {
    case IPPROTO_TCP:
    {
        strcpy(features->protocol, "TCP");
        stats.tcp_packets++;

        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
        features->src_port = rte_be_to_cpu_16(tcp->src_port);
        features->dst_port = rte_be_to_cpu_16(tcp->dst_port);

        extract_tcp_flags(tcp, features->tcp_flags);
        features->seq_num = rte_be_to_cpu_32(tcp->sent_seq);
        features->ack_num = rte_be_to_cpu_32(tcp->recv_ack);
        features->window_size = rte_be_to_cpu_16(tcp->rx_win);

        // Calculate TCP header length
        uint8_t tcp_hdr_len = ((tcp->data_off & 0xF0) >> 4) * 4;

        if (l4_len > tcp_hdr_len)
        {
            payload = (uint8_t *)tcp + tcp_hdr_len;
            payload_len = l4_len - tcp_hdr_len;
        }
        break;
    }

    case IPPROTO_UDP:
    {
        strcpy(features->protocol, "UDP");
        stats.udp_packets++;

        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
        features->src_port = rte_be_to_cpu_16(udp->src_port);
        features->dst_port = rte_be_to_cpu_16(udp->dst_port);

        if (l4_len > sizeof(struct rte_udp_hdr))
        {
            payload = (uint8_t *)udp + sizeof(struct rte_udp_hdr);
            payload_len = l4_len - sizeof(struct rte_udp_hdr);
        }
        break;
    }

    case IPPROTO_ICMP:
    {
        strcpy(features->protocol, "ICMP");
        stats.icmp_packets++;
        break;
    }

    default:
        strcpy(features->protocol, "OTHER");
        break;
    }

    // Payload analysis
    if (payload && payload_len > 0)
    {
        features->has_payload = 1;
        features->payload_size = payload_len;

        // Calculate entropy
        features->payload_entropy = calculate_entropy(payload, payload_len);

        // High entropy might indicate encryption/obfuscation
        if (features->payload_entropy > 7.0)
        {
            features->suspicious = 1;
        }

        // Calculate printable ratio
        features->payload_printable_ratio = calculate_printable_ratio(payload, payload_len);

        // Convert payload to hex (sample)
        uint32_t sample_len = payload_len < MAX_PAYLOAD_SAMPLE ? payload_len : MAX_PAYLOAD_SAMPLE;
        bytes_to_hex(payload, sample_len, features->payload_hex, sizeof(features->payload_hex));

        // Detect application protocol
        detect_app_protocol(features->src_port, features->dst_port,
                            payload, payload_len, features);
    }

    return 0;
}

/* Export features to Python via ring buffer */
static void
export_features(struct packet_features *features)
{
    if (!feature_ring)
        return;

    // Allocate feature object (will be freed by Python consumer)
    struct packet_features *feat_copy = (struct packet_features *)rte_malloc(
        NULL, sizeof(struct packet_features), 0);

    if (!feat_copy)
    {
        stats.errors++;
        return;
    }

    memcpy(feat_copy, features, sizeof(*features));

    // Enqueue to ring
    if (rte_ring_enqueue(feature_ring, feat_copy) < 0)
    {
        // Ring full - drop packet features
        rte_free(feat_copy);
        stats.errors++;
    }
    else
    {
        stats.features_exported++;
    }
}

/* Initialize port */
static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error getting device info: %s\n", rte_strerror(-retval));
        return retval;
    }

    // Configure device
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    // Setup RX queues
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    // Setup TX queues
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    // Start device
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    // Enable promiscuous mode
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/* Main packet processing loop */
static void
lcore_main(uint16_t port)
{
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("Core %u processing packets from port %u\n",
           rte_lcore_id(), port);

    while (!force_quit)
    {
        // Receive burst of packets
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        stats.rx_packets += nb_rx;

        // Process each packet
        for (uint16_t i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *m = bufs[i];
            stats.rx_bytes += rte_pktmbuf_pkt_len(m);

            // Extract features
            struct packet_features features;
            if (extract_packet_features(m, &features) == 0)
            {
                stats.features_extracted++;

                // Export to Python
                export_features(&features);

                // Log suspicious packets
                if (features.suspicious)
                {
                    stats.suspicious_packets++;
                    printf("🚨 Suspicious: %s:%u -> %s:%u [%s]\n",
                           features.src_ip, features.src_port,
                           features.dst_ip, features.dst_port,
                           features.protocol);
                }
            }

            // Free mbuf
            rte_pktmbuf_free(m);
        }
    }
}

/* Print statistics */
static void
print_stats(void)
{
    printf("\n=== DPDK Packet Processor Statistics ===\n");
    printf("RX Packets:         %" PRIu64 "\n", stats.rx_packets);
    printf("RX Bytes:           %" PRIu64 "\n", stats.rx_bytes);
    printf("Features Extracted: %" PRIu64 "\n", stats.features_extracted);
    printf("Features Exported:  %" PRIu64 "\n", stats.features_exported);
    printf("TCP Packets:        %" PRIu64 "\n", stats.tcp_packets);
    printf("UDP Packets:        %" PRIu64 "\n", stats.udp_packets);
    printf("ICMP Packets:       %" PRIu64 "\n", stats.icmp_packets);
    printf("Suspicious:         %" PRIu64 "\n", stats.suspicious_packets);
    printf("Errors:             %" PRIu64 "\n", stats.errors);
    printf("=========================================\n");
}

/*
 * Main function
 */
int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;

    // Initialize EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Check that we have at least one port
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Found %u Ethernet ports\n", nb_ports);

    // Create mbuf pool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Create feature export ring (shared with Python)
    feature_ring = rte_ring_create("feature_ring", FEATURE_RING_SIZE,
                                   rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (feature_ring == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create feature ring\n");

    printf("Created feature ring: %p\n", (void *)feature_ring);

    // Initialize port (use first available port)
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    printf("Port %u initialized successfully\n", portid);
    printf("Starting packet processing...\n");
    printf("Press Ctrl+C to stop\n\n");

    // Launch main processing loop
    lcore_main(portid);

    // Cleanup
    printf("\nShutting down...\n");
    print_stats();

    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);

    printf("Done.\n");
    return 0;
}
