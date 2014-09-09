#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nl80211.h"

#define DEVICE_BUSY -16
#define ETH_ALEN 6
#define PARAMS "h"
#define USAGE "Usage: %s [-" PARAMS "] [managed iface] [monitor iface] [ssid]\n"
#define HELP USAGE "\nSimple wifi interface monitoring\n\n" \
"[managed iface] which interface to send probe request on\n" \
"[monitor iface] which interface to monitor for probe response\n" \
"[ssid]          probe request ssid\n" \
"  -h    display this help and exit\n" \
""
#define u8 unsigned char

static int handle_id;
struct timespec starttime, endtime;
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

int probereq(char* ssid, unsigned char** req)
{
	//char * req = malloc(BUFSIZE);
	int sz = 0;
	sz += 4 + 6*3 + 2; //header
	sz += 2 + strlen(ssid); //ssid param
	sz += (4+2)*2; //rates + ext. rates param

	*req = malloc(sz);
	int p = 0;
	(*req)[p++] = 0x40; //Prob Req
	(*req)[p++] = 0x0; //Frame control flags
	(*req)[p++] = 0x0;
	(*req)[p++] = 0x0;
	(*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF;
	(*req)[p++] = 0xDE; (*req)[p++] = 0xAD; (*req)[p++] = 0xBE; (*req)[p++] = 0xEF; (*req)[p++] = 0x00; (*req)[p++] = 0x01;
	(*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF; (*req)[p++] = 0xFF;
	(*req)[p++] = 0x40;
	(*req)[p++] = 0x48;
	//Tagged params
	(*req)[p++] = 0x00; //SSID
	(*req)[p++] = strlen(ssid); //LEN
	strcpy((char*)(*req+p), ssid);
	p+= (*req)[p-1];

	(*req)[p++] = 0x01; //Std. Rates
	(*req)[p++] = 0x04; //Len
	(*req)[p++] = 0x0c;
	(*req)[p++] = 0x12;
	(*req)[p++] = 0x18;
	(*req)[p++] = 0x24;

	(*req)[p++] = 0x32; //Ext. Rates
	(*req)[p++] = 0x04; //Len
	(*req)[p++] = 0x30;
	(*req)[p++] = 0x48;
	(*req)[p++] = 0x60;
	(*req)[p++] = 0x6c;


	//raise(SIGABRT);
	return sz;
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
	clock_gettime(CLOCK_MONOTONIC, &endtime);
	struct timespec ts = tsdiff(starttime, endtime);
	printf("Probe Reponse Time: %ld.%lds\n", ts.tv_sec, ts.tv_nsec / 1000);
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
	clock_gettime(CLOCK_MONOTONIC, &starttime);
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

	char* ssid = argv[optind+2];
	char* monifname = argv[optind+1];
	char* ifacename = argv[optind];
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
	
	printf("Sending one probe request\n");

	int ret;
	struct nl_msg* msg;
	do
	{
		msg = gen_msg(iface, ssid, 3);
		ret = send_and_recv(handle, msg, cb);
	}while(ret == DEVICE_BUSY);
	
	if (ret)
		printf("Sending failed %s\n", strerror(-ret));
	else
		printf("Sending OK\n");
	


}
