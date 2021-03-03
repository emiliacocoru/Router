
void icmp_packet (packet m, int type, int code ) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	// pachet de tip icmp
	m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// modifica adresele sursă și destinați
	// astfel încât
	// vechea adresă sursă este destinația,
	// iar vechea adresă destinație este sursa
	uint32_t aux = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux;

	// inițializare iphdr
	ip_hdr->protocol = 1;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(m.len - sizeof(struct ether_header));
	ip_hdr->id = htons(getpid());
	ip_hdr->ttl = 255;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

	// inițializare icmphdr
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->un.echo.id = htons(getpid());
	icmp_hdr->un.echo.sequence = htons(1);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

	// inversarea ca la ip, a adreselor de mac
	u_int8_t mac[6];
	memcpy(mac, eth_hdr->ether_shost , 6*sizeof(uint8_t));
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost , 6*sizeof(uint8_t));
	memcpy(eth_hdr->ether_dhost, mac, 6*sizeof(uint8_t));

	send_packet(m.interface, &m);
}
