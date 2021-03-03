#include "skel.h"
#include "arp.c"
#include "icmp.c"
#include "ip.c"

struct route_table_entry* rtable;
struct arp_table_info_line *arp_table;

int arp_table_size;
int rtable_size;
queue q;

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	q = queue_create();

	init();
	rtable = malloc(sizeof(struct route_table_entry) * 10000000); // tabela de rutare
	arp_table = malloc(sizeof(struct arp_table_info_line) * 1000); // tabela de arp

	DIE(rtable == NULL, "memory");
	rtable_size = read_rtable(rtable);

	arp_table_size = 0;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		// verifică dacă este pachet ARP
		if (ntohs(eth_hdr->ether_type) == 0x0806) {
		struct my_arphdr *arp = (struct my_arphdr *)(m.payload + sizeof(struct ether_header));

		// primește ARP REQUEST și trebuie să trimită un ARP REPLY
		if (arp->ar_op == htons(1)) {
			arp_reply(&m);
		} else if (arp->ar_op == htons(2)) {
			// primește un ARP REPLY și trebuie să facă update tabelui de arp
			fprintf(stderr, "ARP REPLY\n");
			arp_table_size = add_new_arp(arp_table,arp_table_size, arp->sender_mac, arp->sender_ip);
			// verifică existența pachetelor în coada de așteptare și le trimite mai departe
			send_packetS_from_queue(&m, q, arp_table,arp_table_size);
			}
		} else {  // pachet IP
			struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header)); ///daca nu e de tip ARP;
			char *ip = get_interface_ip(m.interface);
			// verifică dacă este un pachet adresat routerului
			if (ip_hdr->daddr == inet_addr(ip)) {
				// dacă este un pachet ICMP ECHO request
				if (ip_hdr->protocol == 1) {
					// trimite un pachet ICMP ECHO reply
					icmp_packet(m, 0,0);
					continue;
				}
			} else {
				// avem un pachet normal
				if (ip_hdr->ttl <= 1) {
					// Time exceeded
					icmp_packet(m, 11, 0);
					continue;
				}
				// verificare checksum
				if (0 != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
					continue;
				}
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				ip_reply(m, q, rtable, arp_table, arp_table_size, rtable_size);
			}
		}
	}
}
