#include "myparser.c"

void ip_reply(packet m, queue q, struct route_table_entry* rtable, struct arp_table_info_line *arp_table, int arp_table_size, int rtable_size) {
  struct ether_header *eth_hdr = (struct ether_header *)m.payload;
  struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
  struct route_table_entry *bestEntry = get_best_route2(rtable, ip_hdr->daddr, rtable_size);
  if (bestEntry == NULL) {
    // Destination unreachable
    icmp_packet(m, 3, 0);
  } else  {
    m.interface = bestEntry->interface;
    int pozition_mac_in_arp_table = search_mac(ip_hdr->daddr, arp_table_size, arp_table);
    if (pozition_mac_in_arp_table != -1 ) {
      // dacă se găsește mac-ul destinației,
      for (int i = 0; i < 6; i++) {
        eth_hdr->ether_dhost[i] = arp_table[pozition_mac_in_arp_table].mac[i];
      }
      // se trimite pachetul
      send_packet(m.interface, &m);
    } else {
      // în caz contrar, se trimite un ARP REQUEST

      // se creează o copie a pachetul și se introduce în coadă
      packet copy;
      copy.len = m.len;
      for (int i = 0; i < m.len; i++) {
        copy.payload[i] = m.payload[i];
      }
      copy.interface = m.interface;
      queue_enq(q, &copy);

      // se creează un pachet arp
      packet arp;
      struct ether_header *arp_eth = (struct ether_header *)arp.payload;
      struct my_arphdr *arp_arp = (struct my_arphdr *)(arp.payload + sizeof(struct ether_header));

      // se introduc caracteristicile pachetului
      arp.len = sizeof(struct ether_header) + sizeof(struct my_arphdr);
      arp.interface = m.interface; // interfață

      arp_arp->ar_pro = htons(0x0800); // formatul adresei protocol
      arp_arp->ar_hln = 6; // formatul adresei hardware
      arp_arp->ar_pln = 4; // lungimea adresei protocol
      arp_arp->ar_hrd = htons(1); // lungimea adresei hardware
      arp_arp->ar_op = htons(1); // tipul de comandă/pachet --> ARP REQUEST
      arp_eth->ether_type = htons(0x0806); // tipul ARP

      // modifică adresele ip și mac
      // pentru ether_header:
      memset(arp_eth->ether_dhost, 0xff, 6*sizeof(uint8_t));
      get_interface_mac(m.interface, arp_eth->ether_shost);

      // pntru arp header:
      struct in_addr this_r;
      char * ip = get_interface_ip(m.interface);
      inet_aton(ip, &this_r);
      memcpy(&arp_arp->sender_ip, &this_r, 4 * sizeof(uint8_t));
      memcpy(&arp_arp->target_ip, &ip_hdr->daddr, 4*sizeof(uint8_t));
      get_interface_mac(m.interface, arp_arp->sender_mac);

      memset(arp_arp->target_mac, 0x00, 6*sizeof(uint8_t));
      send_packet(arp.interface, &arp);
    }
  }
}
