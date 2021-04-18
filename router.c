// Copyright 2021 Radu-Stefan Minea 324CA

#include <queue.h>
#include "skel.h"

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	// Create ARP Request queue
	queue arp_queue = queue_create();
	// Declare dynamic ARP table
	struct arp_entry *arp_table = calloc(MAX_ARP_TABLE_SIZE, sizeof(struct arp_entry));
	int arp_table_index = 0;

	// Parse routing table
	struct route_table_entry *rtable = calloc(MAX_RTABLE_SIZE, sizeof(struct route_table_entry));
	int rtable_size = read_rtable(rtable, argv[1]);

	// Sort routing table --> prepping binary search for get_best_route
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), route_entry_cmp);

	// Get eth_hdr
	struct ether_header *eth_hdr = (struct ether_header *) m.payload;

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

		// Get machine data
		uint32_t machine_addr = inet_addr(get_interface_ip(m.interface));
		uint8_t machine_mac[ETH_ALEN];
		memset(machine_mac, 0, sizeof(machine_mac));
		get_interface_mac(m.interface, machine_mac);

		// ARP Packet
		if (arp_packet) {
			// ARP request -> send an ARP reply
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {				
				/*	
					Update Ethernet addresses:
						* Destination eth addr = hardware address of sender
						* Source eth addr = hardware address of target (me)
				*/
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, ETH_ALEN);
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				send_arp(
					// daddr = IP of host who requested
					arp_hdr->spa,
					// saddr = my IP
					machine_addr,
					// eth_hdr
					eth_hdr,
					// interface
					m.interface,
					// arp_op
					htons(ARPOP_REPLY)
				);
			// ARP reply
			} else {

				if (queue_empty(arp_queue)) {
					continue;
				} else {
					update_arp_table(arp_table, &arp_table_index, machine_addr, machine_mac);

					//TODO: best_route

					// If queue != empty: forward the first packet in the queue
					packet *to_send = (packet *) queue_deq(arp_queue);
					send_packet(m.interface, to_send);
				}
			}
		// ICMP Packet
		} else {
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// If packet is destined for me
			if (ip_hdr->daddr == machine_addr) {
				// If ICMP
				if (icmp_hdr) {
					// If ICMP_ECHO : send_icmp
					if (icmp_hdr->type == ICMP_ECHO) {
						send_icmp(
							// daddr = IP of host who requested
							ip_hdr->saddr,
							// saddr
							ip_hdr->daddr,
							// sha
							eth_hdr->ether_dhost,
							// dha
							eth_hdr->ether_shost,
							// type
							ICMP_ECHOREPLY,
							// code
							ICMP_ECHOREPLY,
							// interface
							m.interface,
							// id
							icmp_hdr->un.echo.id,
							// seq
							icmp_hdr->un.echo.sequence
						);
						continue;
					}

					continue;
				} else {
					continue;
				}
			}

			if (ip_hdr->ttl <= 1) {
				// Send TLE ICMP error
				send_icmp_error(
					// daddr
					ip_hdr->saddr,
					// saddr
					machine_addr,
					// sha
					eth_hdr->ether_dhost, //! sau machine_mac
					// dha
					eth_hdr->ether_shost,
					// type
					ICMP_TIME_EXCEEDED,	//! poate si fara htons
					// code
					ICMP_EXC_TTL,		//! poate si fara htons
					// interface
					m.interface
				);

				// Proceed to next package
				continue;
			}

			// Failed checksum -> continue
			if (ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			// Update TTL and recalculate the checksum
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_size - 1);

			if (!best_route) {
				// No route available found --> destination unreachable
				send_icmp_error(
					// daddr
					ip_hdr->saddr,
					// saddr
					ip_hdr->daddr,
					// sha
					eth_hdr->ether_dhost,
					// dha
					eth_hdr->ether_shost,
					// type
					ICMP_DEST_UNREACH,
					// code
					ICMP_NET_UNREACH,
					// interface
					m.interface
				);

				continue;
			} else {
				// Find matching ARP entry
				struct arp_entry *entry = get_arp_entry(ip_hdr->daddr, arp_table, arp_table_index);

				// Preemptive update of source Ethernet address (always me)
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);

				// No ARP entry found
				if (!entry) {
					//! modify for moss
					// Allocate memory for enqueued packet
					packet *m_aux = calloc(1, sizeof(packet));
					memcpy(m_aux, &m, sizeof(packet));

					//Enqueue packet
					queue_enq(arp_queue, m_aux);

					// Fetch broadcast MAC
					uint8_t broadcast_mac[ETH_ALEN];
					hwaddr_aton(BROADCAST_ADDR, broadcast_mac);

					// Update Ethernet dest address for broadcast
					memcpy(eth_hdr->ether_dhost, broadcast_mac, sizeof(broadcast_mac));
					// Update Ethernet type
					eth_hdr->ether_type = htons(ETHERTYPE_ARP);

					/**
					 * @brief cine sunt daddr si saddr?
					 * best_route -> urmatorul router din tabela din rutare (interfata prin care trb sa se duca pachetul)
					 */

					// Send ARP Request in order to get MAC of target
					send_arp(
						// daddr = next hop
						best_route->next_hop,
						// saddr = my IP
						inet_addr(get_interface_ip(best_route->interface)), //! voi pleca prin interfata pe care o spune best_route
						// eth_hdr
						eth_hdr,
						// interface --> ! voi pleca prin interfata pe care o spune best_route
						best_route->interface,
						// arp_op
						htons(ARPOP_REQUEST)
					);

					continue;
				} else {
					// Update Ethernet dest address for forwarding
					memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(entry->mac));
					// Forward the packet to best_route->interface
					send_packet(best_route->interface, &m);

					continue;
				}
			}
		}
	}

	return 0;
}
