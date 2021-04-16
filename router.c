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
		DIE((status = inet_pton(AF_INET, buf, rtable[i].prefix)) != 1, "rtable parsing - convert prefix");

		// Next_hop
		token = strtok(NULL, DELIM);
		DIE((status = inet_pton(AF_INET, buf, rtable[i].next_hop)) != 1, "rtable parsing - convert next_hop");

		// Mask
		token = strtok(NULL, DELIM);
		DIE((status = inet_pton(AF_INET, buf, rtable[i].mask)) != 1, "rtable parsing - convert mask");

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

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	// Parse routing table
	struct route_table_entry *rtable = calloc(MAX_RTABLE_SIZE, sizeof(struct route_table_entry));
	int rtable_size = read_rtable(rtable, argv[1]);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
	}
}
