#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#define BUFSIZE 2048
#define PARAMS "cdhst"
#define USAGE "Usage: %s [-" PARAMS "] [interface] [maclist...]\n"
#define HELP USAGE "\nSimple wifi interface monitoring\n\n" \
"[maclist...] which mac addresses to monitor, empty = all\n" \
"[interface]  which interface to monitor\n" \
"  -c    enables colors\n" \
"  -d    include differential timestamps\n" \
"  -h    display this help and exit\n" \
"  -s    simple names\n" \
"  -t    include timestamps\n" \
""
#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_FTYPE_CTL             0x0004
#define IEEE80211_FTYPE_DATA            0x0008

#define IEEE80211_STYPE_CTL_EXT         0x006
#define IEEE80211_STYPE_BACK_REQ        0x008
#define IEEE80211_STYPE_BACK            0x009
#define IEEE80211_STYPE_PSPOLL          0x00A
#define IEEE80211_STYPE_RTS             0x00B
#define IEEE80211_STYPE_CTS             0x00C
#define IEEE80211_STYPE_ACK             0x00D
#define IEEE80211_STYPE_CFEND           0x00E
#define IEEE80211_STYPE_CFENDACK        0x00F

#define IEEE80211_STYPE_ASSOC_REQ       0x000
#define IEEE80211_STYPE_ASSOC_RESP      0x001
#define IEEE80211_STYPE_REASSOC_REQ     0x002
#define IEEE80211_STYPE_REASSOC_RESP    0x003
#define IEEE80211_STYPE_PROBE_REQ       0x004
#define IEEE80211_STYPE_PROBE_RESP      0x005
#define IEEE80211_STYPE_BEACON          0x008
#define IEEE80211_STYPE_ATIM            0x009
#define IEEE80211_STYPE_DISASSOC        0x00A
#define IEEE80211_STYPE_AUTH            0x00B
#define IEEE80211_STYPE_DEAUTH          0x00C
#define IEEE80211_STYPE_ACTION          0x00D

#define CNORMAL  "\033[0m"
#define CRED     "\033[31m"
#define CGREEN   "\033[32m"
#define CYELLOW  "\033[33m"
#define CBLUE    "\033[34m"
#define CMAGENTA "\033[35m"
#define CCYAN    "\033[36m"
#define CWHITE   "\033[37m"

//char * colors[] = {CRED, CGREEN, CYELLOW, CBLUE, CMAGENTA, CCYAN, CWHITE};

int sock;

bool opt_timestamp = false;
bool opt_diffstamp = false;
bool opt_simpleaddr = false;
bool opt_color = false;
int ccolor = 0;
clock_t lastts = 0;

int maclist_count;
unsigned char * maclist = NULL; //contains mac list

bool isinmaclist(unsigned char * addr)
{
	if(maclist == NULL) return true;
	for(int i = 0; i < maclist_count; i++)
	{
		if(memcmp(maclist + i*6, addr, 6) == 0) return true;
	}
	return false;
}

struct station
{
	int color;
	unsigned char addr[6];
	int txcount;
	int rxcount;
	struct station * next;
};
struct station * sta_head = NULL;

void sta_add(struct station ** head, int color, unsigned char * addr)
{
	if (*head == NULL)
	{
		*head = (struct station*)malloc(sizeof(station));
		memset(*head, 0, sizeof(station));
		(*head)->color = color;
		(*head)->next = NULL;
		memcpy((*head)->addr, addr, 6);
	} else sta_add(&((*head)->next), color, addr);
}

struct station* sta_find(struct station * head, unsigned char addr[6])
{
	if(head == NULL) return NULL;
	else if (head->addr != NULL && memcmp(head->addr, addr, 6) == 0) return head;
	else return sta_find(head->next, addr);
}

struct wframe
{
	bool nowifi;
	int ts, diffts;
	int type;
	int stype;
	uint16_t nav; //nav in usec
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];
	unsigned char* rxaddr;
	struct station * rxsta;
	unsigned char* txaddr;
	struct station * txsta;

	bool retry;
	bool powermgmt;
};

static bool keepRunning = true;

void print_stalist(struct station*);

void intHandler(int dummy = 0) 
{
	if(keepRunning == false)
	{
		printf("Station List: \n");
		print_stalist(sta_head->next);
		exit(0);
	}
    keepRunning = false;
}

timespec tsdiff(timespec start, timespec end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

const char * subtype_name(int type, int stype)
{
	if (type == IEEE80211_FTYPE_CTL) {
		if (stype == IEEE80211_STYPE_RTS)
			return "RTS";
		if (stype == IEEE80211_STYPE_CTS)
			return "CTS";
		if (stype == IEEE80211_STYPE_ACK)
			return "ACK";
		else
			return "Unknown Control";
	}
	else if (type == IEEE80211_FTYPE_MGMT) {
		if (stype == IEEE80211_STYPE_BEACON)
			return "Beacon";
		if (stype == IEEE80211_STYPE_PROBE_REQ)
			return "Probe Req";
		if (stype == IEEE80211_STYPE_PROBE_RESP)
			return "Probe Resp";
		if (stype == IEEE80211_STYPE_ASSOC_REQ)
			return "Assoc Req";
		if (stype == IEEE80211_STYPE_ASSOC_RESP)
			return "Assoc Resp";
		if (stype == IEEE80211_STYPE_AUTH)
			return "Auth";
		if (stype == IEEE80211_STYPE_DEAUTH)
			return "Deauth";
		else
			return "Unknown Management";
	}
	else
		return "Data";
}

int sock_bind(const char * ifname) { 
    struct sockaddr_ll sll;
    struct ifreq ifr; bzero(&sll , sizeof(sll));
    bzero(&ifr , sizeof(ifr)); 
    strncpy((char *)ifr.ifr_name , ifname, IFNAMSIZ); 
    //copy device name to ifr 
    if((ioctl(sock, SIOCGIFINDEX, &ifr)) == -1)
    { 
        perror("Unable to find interface index");
        exit(-1); 
    }
    sll.sll_family = AF_PACKET; 
    sll.sll_ifindex = ifr.ifr_ifindex; 
    sll.sll_protocol = htons(ETH_P_ALL); 
    if((bind(sock , (struct sockaddr *)&sll , sizeof(sll))) ==-1)
    {
        perror("bind: ");
        exit(-1);
    }
    return 0;
}

int sock_open()
{
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock == -1) {
		if(errno == EPERM)
			printf("You require root priviliges to monitor network data. ");
		else
			printf("Socket creation failed: %d", errno);
		return errno;
	}
	return 0;
}

void sock_close()
{
	close(sock);
}

void print_addr(unsigned char* addr)
{
	for(int i = 0; i < 6; i++)
		i == 5 ? printf("%02x", addr[i]) : printf("%02x:", addr[i]);
}

struct wframe buffertowframe(char * buffer, int size)
{
	//Let's process the packet. 
	//First remove radiotap. 
	struct wframe frame;
	memset(&frame, 0, sizeof(wframe));
	int pos = 0;
	clock_t ts = clock();
	frame.ts = ts;
	frame.diffts = ts - lastts;
	lastts = ts;
	uint8_t radiotap_version = buffer[pos++];
	uint8_t radiotap_pad = buffer[pos++];
	uint16_t radiotap_length = buffer[pos];
	if (radiotap_version != 0 || radiotap_pad != 0 || radiotap_length > 1000) {
		frame.nowifi = true;
		return frame;
	}

	//Skip Radiotap
	pos += radiotap_length - 4 + 2;

	//Decode packet type
	uint16_t fc = buffer[pos]; //frame control info
	pos += 2;
	if((fc & 0x04) != 0) frame.type  += 0x2;
	if((fc & 0x08) != 0) frame.type  += 0x1;
	if((fc & 0x10) != 0) frame.stype += 0x1;
	if((fc & 0x20) != 0) frame.stype += 0x2;
	if((fc & 0x40) != 0) frame.stype += 0x4;
	if((fc & 0x80) != 0) frame.stype += 0x8;
	frame.retry = (fc & 0x400);
	frame.powermgmt = (fc & 0x800);
	frame.nav = buffer[pos];
	pos += 2;
	memcpy(&frame.addr1, buffer+pos, 6); //This address is always there
	pos += 6;
	if (frame.type == IEEE80211_FTYPE_CTL)
		if (frame.type == IEEE80211_STYPE_CTS || 
		    frame.type == IEEE80211_STYPE_ACK)
			goto FCS;
	memcpy(&frame.addr2, buffer+pos, 6);
	pos += 6;
	if (frame.type == IEEE80211_FTYPE_CTL)
		goto FCS;
	memcpy(&frame.addr3, buffer+pos, 6);
	pos += 6;

FCS:
	pos += 2; //TODO: Parse sequence number (fcs)

	if (frame.type == IEEE80211_FTYPE_CTL)
	{
		switch (frame.stype)
		{
			case IEEE80211_STYPE_RTS:
				frame.rxaddr = frame.addr1;
				frame.txaddr = frame.addr2;
				break;
			case IEEE80211_STYPE_CTS:
				frame.rxaddr = frame.addr1;
				break;
			case IEEE80211_STYPE_ACK:
				frame.rxaddr = frame.addr1;
				break;
		}
	}
	else
	{
		frame.rxaddr = frame.addr1;
		frame.txaddr = frame.addr2;
	}

	if(frame.txaddr != NULL)
	{
		struct station * sta = sta_find(sta_head, frame.txaddr);
		if (sta != NULL)
			frame.txsta = sta;
		else
		{
			sta_add(&sta_head, ccolor++, frame.txaddr);
			frame.txsta = sta_find(sta_head, frame.txaddr);
		}
		frame.txsta->txcount++;
	}
	if(frame.rxaddr != NULL)
	{
		struct station * sta = sta_find(sta_head, frame.rxaddr);
		if (sta != NULL)
			frame.rxsta = sta;
		else
		{
			sta_add(&sta_head, ccolor++, frame.rxaddr);
			frame.rxsta = sta_find(sta_head, frame.rxaddr);
		}
		frame.rxsta->rxcount++;
	}

	return frame;
}

void print_nowifi(struct wframe *frame)
{
	printf("Non-wifi packet");
	if(opt_timestamp)
		printf(" (t %d)", frame->ts);
	if(opt_diffstamp)
		printf(" (d %d)", frame->diffts);
	printf("\n");
}

void print_colormark(int color)
{
	if (opt_color)
	{
		switch (color % 6)
		{
			case 0: printf(CRED); break;
			case 1: printf(CGREEN); break;
			case 2: printf(CYELLOW); break;
			case 3: printf(CBLUE); break;
			case 4: printf(CMAGENTA); break;
			case 5: printf(CCYAN); break;
		}
	}
}
void reset_colormark()
{
	if (opt_color)
		printf(CWHITE);
}

void print_node(struct station *sta)
{
	if (sta->color != 0)
		print_colormark(sta->color);
	if (opt_simpleaddr)
	{
		if (sta->color == 0)
			printf("Broadcast");
		else
			printf("Node %c", sta->color+64);
	}
	else
	{
		if (sta->color == 0)
			printf("Broadcast");
		else
			print_addr(sta->addr);
	}
	reset_colormark();
}

void print_wifi(struct wframe *frame)
{
	if(!isinmaclist(frame->txaddr) && !isinmaclist(frame->rxaddr))
		return;
	if(frame->txsta != NULL)
	{
		print_node(frame->txsta);
		printf(" sent ");
	}
	else printf("someone sent ");

	printf("%-12s ", subtype_name(frame->type, frame->stype));

	if(frame->rxsta != NULL)
	{
		printf("-> ");
		print_node(frame->rxsta);
	}
	else printf("-> someone ");


	reset_colormark();
	if (opt_timestamp)
		printf(" (t %d)", frame->ts);
	if (opt_diffstamp)
		printf(" (d %d)", frame->diffts);
	printf("\n");
	fflush(stdout);
}

void analyze(char* buffer, int size)
{
	wframe frame = buffertowframe(buffer, size);
	if(frame.nowifi)
		print_nowifi(&frame);
	else
		print_wifi(&frame);
}

void print_stalist(struct station * head)
{
	if(head == NULL) return;
	if(isinmaclist(head->addr))
	{
		bool old = opt_simpleaddr;
		opt_simpleaddr = true;
		print_node(head);
		printf(" = ");
		opt_simpleaddr = false;
		print_node(head);
		printf(" (tx: %d, rx: %d)", head->txcount, head->rxcount);
		printf("\n");
		opt_simpleaddr = old;
	}
	print_stalist(head->next);
}

int main(int argc, char *argv[])
{
	char buffer[BUFSIZE];
	struct sockaddr saddr;
	int opt;
	timespec starttime, endtime;
	clock_gettime(CLOCK_MONOTONIC, &starttime);

	unsigned char bcast[] = "\xFF\xFF\xFF\xFF\xFF\xFF";
	sta_add(&sta_head, ccolor++, bcast);
	signal(SIGINT, intHandler);

	while ((opt = getopt(argc, argv, PARAMS)) != -1)
	{
		switch (opt)
		{
			case 'h':
				fprintf(stdout, HELP, argv[0]);
				exit(EXIT_SUCCESS);
			case 'c':
				opt_color = true;
				break;
			case 'd':
				opt_diffstamp = true;
				break;
			case 's':
				opt_simpleaddr = true;
				break;
			case 't':
				opt_timestamp = true;
				break;
			default:
				fprintf(stderr, USAGE, argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc)
	{
		fprintf(stderr, USAGE, argv[0]);
		exit(EXIT_FAILURE);
	}

	char * iface = argv[optind];
	int macs = argc - optind - 1;
	if(macs > 0)
	{
		maclist = (unsigned char*)malloc(6*macs);
		unsigned char * pos = maclist;
		for(int i = optind + 1; i < argc; i++)
		{
			unsigned int iMac[6];
			unsigned char mac[6];

			sscanf(argv[i], "%x:%x:%x:%x:%x:%x", &iMac[0], &iMac[1], &iMac[2], &iMac[3], &iMac[4], &iMac[5]);
			for(int j=0;j<6;j++)
				mac[j] = (unsigned char)iMac[j];
			memcpy(pos, mac, 6);
			pos += 6;
		}
	}
	maclist_count = macs;

	if (sock_open()) return 0;
	if (sock_bind(argv[optind])) return 0;
	while(keepRunning) {
		socklen_t saddr_size = sizeof saddr;
		int size = recvfrom(sock, buffer, BUFSIZE, 0, &saddr, &saddr_size);
		analyze(buffer, size);
	}
	clock_gettime(CLOCK_MONOTONIC, &endtime);
	printf(CNORMAL);
	sock_close();
	printf("Station List: \n");
	print_stalist(sta_head->next);
	timespec ts = tsdiff(starttime, endtime);
	printf("Total Running Time: %ld.%lds\n", ts.tv_sec, ts.tv_nsec / 1000);
	return 0;
}



