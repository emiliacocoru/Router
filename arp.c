#include <stdio.h>
#include "skel.h"
#include "queue.h"

struct my_arphdr {
	uint16_t		ar_hrd;		// ormat of hardware address
	uint16_t		ar_pro;		// format of protocol address
	unsigned char	ar_hln;	// length of hardware address
	unsigned char	ar_pln;	// length of protocol address
	uint16_t		ar_op;		// ARP opcode (command)
	uint8_t sender_mac[6]; // mac sursă
	uint8_t sender_ip[4];  // ip sursă
	uint8_t target_mac[6]; // mac destinație
	uint8_t target_ip[4];  // ip destinație
};

struct arp_table_info_line {
  	uint8_t ip[4];
	  uint8_t mac[6];
};

// adaugă o nouă entitate în tabela de arp
int add_new_arp(struct arp_table_info_line *arp, int len, uint8_t* mac, uint8_t *prefix) {
		for (int i = 0; i < 4; i++) {
			arp[len].ip[i] = prefix[i];
		}
  	for (int j = 0; j < 6 ; j++) {
  		arp[len].mac[j] = mac[j];
	}
  return len + 1;
}
// caută în tabela de arp poziția mac-ul în aceasta pentru adresa cunoscută
int search_mac(uint32_t p,  int len, struct arp_table_info_line* arp_table) {
  // trecerea de la 32 de biți la 8 biți
	uint8_t prefix[4];
	prefix[0] = p & 0xFF;
	prefix[1] = (p >> 8) & 0xFF;
	prefix[2] = (p >> 16) & 0xFF;
	prefix[3] = (p >> 24) & 0xFF;
	for (int i = 0; i < len; i++) {
		if (arp_table[i].ip[0] == prefix[0] && arp_table[i].ip[1] == prefix[1] && arp_table[i].ip[2] == prefix[2] &&
				arp_table[i].ip[3] == prefix[3]) {
				return i;
			}
		}
	return -1;
}

void arp_reply(packet *m) {
	struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct my_arphdr *arp = (struct my_arphdr *)(m->payload + sizeof(struct ether_header));
	struct in_addr this_r;

	char *ip = get_interface_ip(m->interface);
	inet_aton(ip, &this_r);

	//arp header

	arp->ar_op = htons(2); // ARP REPLY
  // modifică ip-ul și mac-ul destinației cu cel al sursei de unde provine pachetul
	memcpy(arp->target_mac, arp->sender_mac ,6 * sizeof(uint8_t));
	memcpy(arp->target_ip, arp->sender_ip ,4 * sizeof(uint8_t));
  // modifică ip-ul și mac-ul sursei cu cele alocate routerului
	get_interface_mac(m->interface, arp->sender_mac);
	memcpy(&arp->sender_ip, &this_r, 4*sizeof(uint8_t));

	// ether_header
  // mac-ul destinației este mac-ul sursei de unde provine pachetul
  // mac-ul sursei este cel al routerului.
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	get_interface_mac(m->interface, eth_hdr->ether_shost);
	send_packet(m->interface, m);
}

void send_packetS_from_queue(packet *m, queue q, struct arp_table_info_line *arp_table, int arp_table_size) {
	struct my_arphdr *arp = (struct my_arphdr *)(m->payload + sizeof(struct ether_header));
  // dacă există pachete
	while (!queue_empty(q)) {
			packet* for_sending = queue_deq(q);
			struct ether_header *eth_sending = (struct ether_header *)for_sending->payload;
      // modifică adresa mac a destinației cu abia primită prin ARP reply.
			memcpy(eth_sending->ether_dhost, arp->sender_mac, 6 * sizeof(uint8_t));
			send_packet(for_sending->interface, for_sending);
	}
}
