#include <stdio.h>

struct route_table_entry {
  uint32_t prefix;
  uint32_t next_hop;
  uint32_t mask;
  int interface;
} __attribute__((packed));

int read_rtable(struct route_table_entry *rtable) {
    FILE *fp;
    fp = fopen("rtable.txt", "r");
    char buff [30];
    int i = 0;
    while (fscanf(fp, "%s", buff) != EOF) {
        rtable[i].prefix = inet_addr(buff);
        fscanf(fp, "%s", buff);
        rtable[i].next_hop = inet_addr(buff);
        fscanf(fp, "%s", buff);
        rtable[i].mask = inet_addr(buff);
        fscanf(fp, "%s", buff);
        rtable[i].interface = atoi(buff);
        i++;
    }
    return i;
}

struct route_table_entry *get_best_route2(struct route_table_entry *rtable,
    __u32 dest_ip, int len_route_table) {
	int max_mask_len = 0;
	int max_entry_len = -1;
	for (int i = 0; i < len_route_table; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
		 	if (rtable[i].mask > max_mask_len) {
					max_mask_len = rtable[i].mask;
					max_entry_len = i;
			}
		}
	}
	if (max_entry_len == -1) {
		return NULL;
	} else {
		return &rtable[max_entry_len];
	}
}
