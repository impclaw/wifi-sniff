#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nl80211.h"

#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_FTYPE_CTL             0x0004
#define IEEE80211_FTYPE_DATA            0x0008
#define IEEE80211_STYPE_PROBE_REQ       0x004
#define IEEE80211_STYPE_PROBE_RESP      0x005
#define DEVICE_BUSY -16
#define ETH_ALEN 6
#define BUFSIZE 2048
#define PARAMS "h"
#define USAGE "Usage: %s [-" PARAMS "] [managed iface] [monitor iface] [ssid]\n"
#define HELP USAGE "\nSimple wifi interface monitoring\n\n" \
"[managed iface] which interface to send probe request on\n" \
"[monitor iface] which interface to monitor for probe response\n" \
"[ssid]          probe request ssid\n" \
"  -h    display this help and exit\n" \
""
#define u8 unsigned char
#define bool int
#define false 0
#define true !false

struct wframe
{
	int ts, diffts;
	int type;
	int stype;
	uint16_t nav; //nav in usec
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];
	unsigned char* rxaddr;
	unsigned char* txaddr;

	bool retry;
	bool powermgmt;
};
static int handle_id;
int sock;
pthread_t monthread;

void die(const char* msg)
{
	fprintf(stderr,"%s\n", msg);
	exit(-1);
}

struct timespec tsdiff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
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

struct wframe * buffertowframe(char * buffer, int size)
{
	//Let's process the packet. 
	//First remove radiotap. 
	struct wframe *frame;
	frame = (struct wframe *) malloc(sizeof(struct wframe));
	memset(frame, 0, sizeof(struct wframe));
	int pos = 0;
	uint8_t radiotap_version = buffer[pos++];
	uint8_t radiotap_pad = buffer[pos++];
	uint16_t radiotap_length = buffer[pos];
	if (radiotap_version != 0 || radiotap_pad != 0 || radiotap_length > 1000) {
		return NULL;
	}

	//Skip Radiotap
	pos += radiotap_length - 4 + 2;

	//Decode packet type
	uint16_t fc = buffer[pos]; //frame control info
	pos += 2;
	if((fc & 0x04) != 0) frame->type  += 0x2;
	if((fc & 0x08) != 0) frame->type  += 0x1;
	if((fc & 0x10) != 0) frame->stype += 0x1;
	if((fc & 0x20) != 0) frame->stype += 0x2;
	if((fc & 0x40) != 0) frame->stype += 0x4;
	if((fc & 0x80) != 0) frame->stype += 0x8;
	if(frame->type != IEEE80211_FTYPE_MGMT)
		return NULL;
	if(frame->stype != IEEE80211_STYPE_PROBE_REQ && frame->stype != IEEE80211_STYPE_PROBE_RESP)
		return NULL;
	frame->retry = (fc & 0x400);
	frame->powermgmt = (fc & 0x800);
	frame->nav = buffer[pos];
	pos += 2;
	memcpy(&frame->addr1, buffer+pos, 6); //This address is always there
	pos += 6;
	memcpy(&frame->addr2, buffer+pos, 6);
	pos += 6;
	memcpy(&frame->addr3, buffer+pos, 6);
	pos += 6;

FCS:
	pos += 2; //TODO: Parse sequence number (fcs)
	return frame;
}

static struct nl_msg *gen_msg(int iface, char* ssid, int chan){
	struct nl_msg *msg, *ssids, *freqs;

	msg  = nlmsg_alloc();
	ssids = nlmsg_alloc();
	freqs = nlmsg_alloc();

	if (!msg || !ssids || !freqs){
		fprintf(stderr, "Failed to allocate netlink message");
	if(msg)
		nlmsg_free(msg);
	if(ssids)
		nlmsg_free(ssids);
	if(freqs)
		nlmsg_free(freqs);
		return NULL;
	}

	genlmsg_put(msg, 0, 0, handle_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, iface);

	NLA_PUT(ssids, 1, strlen(ssid), ssid);
	nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

	NLA_PUT_U32(freqs, 1, chan*5 + 2407);
	nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);


	return msg;
	nla_put_failure:

	nlmsg_free(msg);
	return NULL;
}

static int ack_handler(struct nl_msg *msg, void *arg){
	int *err = arg;
	*err = 0;
	return NL_STOP;
}
static int finish_handler(struct nl_msg *msg, void *arg){
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg){
	int *ret = arg;
	fprintf(stderr, "Err: %d\n", err->error);
	*ret = err->error;
	return NL_SKIP;
}

static int send_and_recv(struct nl_handle* handle, struct nl_msg* msg, struct nl_cb* cb){
	int err = -1;
	struct nl_cb *tmp_cb;
	tmp_cb = nl_cb_clone(cb);
	if (!cb)
		goto out;
	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		goto out;

	err = 1;
	nl_cb_err(tmp_cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(tmp_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(tmp_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	while(err > 0)
		nl_recvmsgs(handle, tmp_cb);

	out:
	nlmsg_free(msg);
	nl_cb_put(tmp_cb);
	return err;
}

volatile int state = 0;
char* ssid;
char* monifname;
char* ifacename;

void *mon_run()
{
	static struct timespec starttime, endtime;
	char buffer[BUFSIZE];
	struct sockaddr saddr;
	if (sock_open()) return 0;
	if (sock_bind(monifname)) return 0;
	state = 1;
	while(state == 1) {
		socklen_t saddr_size = sizeof saddr;
		int size = recvfrom(sock, buffer, BUFSIZE, 0, &saddr, &saddr_size);
		struct wframe * frame = buffertowframe(buffer, size);
		if (frame == NULL)
			continue;
		if(frame->stype == IEEE80211_STYPE_PROBE_REQ)
			clock_gettime(CLOCK_MONOTONIC, &starttime);
		if(frame->stype == IEEE80211_STYPE_PROBE_RESP)
		{
			clock_gettime(CLOCK_MONOTONIC, &endtime);
			struct timespec ts = tsdiff(starttime, endtime);
			printf("Probe Reponse Time: %ld.%lds\n", ts.tv_sec, ts.tv_nsec / 1000);
			state = 2;
		}
		free(frame);
	}
	state = 2;
}


int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, PARAMS)) != -1)
	{
		switch (opt)
		{
			case 'h':
				fprintf(stdout, HELP, argv[0]);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, USAGE, argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc - 2)
	{
		fprintf(stderr, USAGE, argv[0]);
		exit(EXIT_FAILURE);
	}

	pthread_create(&monthread, NULL, mon_run, NULL);

	ssid = argv[optind+2];
	monifname = argv[optind+1];
	ifacename = argv[optind];
	int iface = if_nametoindex(ifacename);

	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	if(!cb)
		die("Can't allocate cb");
	struct nl_handle *handle;
	handle = nl_handle_alloc_cb(cb);
	if(!handle)
		die("Can't allocate handle");
	if(genl_connect(handle))
		die("Can't connect to generic netlink");

	if ((handle_id = genl_ctrl_resolve(handle, "nl80211")) < 0)
		die("Can't resolve generic netlink");
	
	usleep(1000);

	int ret;
	struct nl_msg* msg;
	do
	{
		msg = gen_msg(iface, ssid, 3);
		ret = send_and_recv(handle, msg, cb);
	}while(ret == DEVICE_BUSY);
	
	if (ret)
		printf("Sending failed %s\n", strerror(-ret));
	
	while(state != 2)
	{
		usleep(100);
	}

}
