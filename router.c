#include <queue.h>
#include "skel.h"
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/**
 * @brief Parses routing table
 * 
 * @param rtable array of route_table_entries
 * @param file_name of file with route_table_entries
 * 	
 * @return size of routing table
 */
int read_rtable(struct route_table_entry *rtable, char *file_name) {
	char buf[MAX_LEN];
	char *token;

	int i = 0;
	int status = 1;

	// Open rtable file
	FILE *f = fopen(file_name, "r");

	// Parse each line of rtable
	while (fgets(buf, sizeof(buf), f)) {
		// Prefix
		token = strtok(buf, DELIM);
		DIE((status = inet_pton(AF_INET, token, &rtable[i].prefix)) != 1, "rtable parsing - convert prefix");
		// Convert to host endianness
		rtable[i].prefix = ntohl(rtable[i].prefix);

		// Next_hop
		token = strtok(NULL, DELIM);
		DIE((status = inet_pton(AF_INET, token, &rtable[i].next_hop)) != 1, "rtable parsing - convert next_hop");
		// Convert to host endianness
		rtable[i].next_hop = ntohl(rtable[i].next_hop);
		
		// Mask
		token = strtok(NULL, DELIM);
		DIE((status = inet_pton(AF_INET, token, &rtable[i].mask)) != 1, "rtable parsing - convert mask");
		// Convert to host endianness
		rtable[i].mask = ntohl(rtable[i].mask);

		// Interface
		token = strtok(NULL, DELIM);
		rtable[i].interface = atoi(token);

		// Proceed to next entry
		i++;
	}

	// Close rtable file
	fclose(f);

	return i;
}

/**
 * @brief compare function for route table sorting: sort ASC by prefix and mask
 * 
 * @param a first element - to be compared
 * @param b second element - to compare with
 * @return int 1 if swap is needed, else 0
 */
int route_entry_cmp(const void* a, const void* b) {
	struct route_table_entry e1 = *(struct route_table_entry *) a;
	struct route_table_entry e2 = *(struct route_table_entry *) b;

	// Ascending prefix
	if ((e1.prefix > e2.prefix) 
		// Ascending mask: if prefix = equal, we want to pick the maximum mask
		|| (e1.prefix == e2.prefix && e1.mask > e2.mask)) {
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	// Parse routing table
	struct route_table_entry *rtable = calloc(MAX_RTABLE_SIZE, sizeof(struct route_table_entry));
	int rtable_size = read_rtable(rtable, argv[1]);

	// Sort routing table --> prepping binary search for get_best_route
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), route_entry_cmp);

	// Create  ARP Request queue
	queue arp_queue = queue_create();

	while (1) {
		// Receive package
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// Determine type of packet
		bool arp_packet = false;
		struct arp_header *arp_hdr = parse_arp(m.payload);

		if (arp_hdr) {
			arp_packet = true;
		}

		if (arp_packet) {
			// ARP request -> send an ARP reply
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				//Modify current eth_hdr in order to send it
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				// Destination eth addr = hardware address of sender
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, ETH_ALEN);
				// Source eth addr = hardware address of target (me)
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				uint32_t machine_addr = inet_addr(get_interface_ip(m.interface));

				// daddr = IP of host who requested
				send_arp(arp_hdr->spa,
						// saddr = my IP
						machine_addr,
						// eth_hdr
						eth_hdr,
						// interface
						m.interface,
						// arp_op
						htons(ARPOP_REPLY));
			} else {
				// ARP reply
				//TODO: update ARP table

				if (queue_empty(arp_queue)) {
					continue;
				} else {
					// If queue != empty: forward the first packet in the queue
					packet *to_send = (packet *) queue_deq(arp_queue);
					send_packet(m.interface, to_send);
				}
			}
		} else {
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);
			struct iphdr *ip_hdr = (struct iphdr *)icmp_hdr;
			uint32_t machine_addr = inet_addr(get_interface_ip(m.interface));

			// If packet is destined for me
			if (ip_hdr->daddr == machine_addr) {
				// if ()
				// If ICMP_ECHO : send_icmp
				// Else : continue
			}

			// If ttl <= 1
		}
	}
}
