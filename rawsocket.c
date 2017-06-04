#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>       // close() getopt_long()
#include <getopt.h>  
#include <string.h>       // strcpy, memset(), and memcpy()
#include <netdb.h>         // struct addrinfo
#include <sys/types.h>     // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>     // needed for socket()
#include <netinet/in.h>     // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>     // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h> // struct icmp, ICMP_ECHO
#include <arpa/inet.h>     // inet_pton() and inet_ntop()
#include <sys/ioctl.h>     // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>       // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>         // errno, perror()
#include <fcntl.h>

static union {char c[4]; unsigned long mylong;} endian_test = {'l', '?', '?', 'b'};
#define ENDIANNESS ((char)endian_test.mylong)
#define BIGENDIAN 'b'
#define LITTLEENDIAN 'l'

#define UDP 17
#define TCP 6
#define ICMP 1
#define ARP	100
#define RARP 101

#define DEFAULT_ARGS \
	{NULL, NULL, "eth0", 0, 0, \
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, \
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0}

typedef struct st_ethhdr
{
	unsigned char dmac[6];
	unsigned char smac[6]; 
	unsigned short proto;

} ETH_HDR;

typedef struct st_iphdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned char ihl:4;
	unsigned char version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char version:4;
	unsigned char ihl:4;
#endif
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags; 
    unsigned char ttl;  
    unsigned char proto; 
    unsigned short checksum; 
    unsigned int saddr; 
    unsigned int daddr; 

} IP_HDR;

typedef struct st_udphdr
{
	unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short sum;

} UDP_HDR;

typedef struct st_udp_pkg {
	ETH_HDR ethhdr;
	unsigned short zero;
	IP_HDR iphdr;
	UDP_HDR udphdr;
	unsigned char data[1440];
} st_udp_pkg;

typedef struct st_args {
	char *rd_path;
	char *wrt_path;
	char *interface;

	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned char src_mac[6];
	unsigned char auto_src_mac;
	unsigned char dst_mac[6];
	unsigned char auto_dst_mac;

} st_args;

static char rd_path[64];
static char wrt_path[64];
static char interface[32];
static int length;
static unsigned char package[IP_MAXPACKET];
static unsigned char type;
static unsigned char is_debug;
static unsigned char is_dump;
static unsigned char auto_check;

unsigned char hexchar_to_int(unsigned char c)
{
	if ((c >= '0') && (c <= '9')) return (c - '0');
	if ((c >= 'A') && (c <= 'F')) return (c - 'A' + 0x0a);
	if ((c >= 'a') && (c <= 'f')) return (c - 'a' + 0x0a);
	return 0;
}	

int parse_mac(const unsigned char *from_mac, unsigned char *to_mac)
{
	int ret = -1;
	int i, j;
	
	for (i = 0, j = 0; i < 17; i++)
	{
		if(from_mac[i] == ':')
			continue;
		to_mac[j++] = (hexchar_to_int(from_mac[i]) << 4) | hexchar_to_int(from_mac[++i]);
	}

	return ret;
}

unsigned short checksum(const unsigned char *buff, const int buff_len)
{
	int i;
	unsigned short num;
	unsigned int sum;

	for (i = 0, sum = 0; i < buff_len; i += 2)
	{
		memcpy((unsigned char *)&num, buff + i, 2);
		sum += num;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)~sum;
}

int read_file(unsigned char *pkg, int *pkg_len, const char *path)
{
	int fd = -1;
	int len = -1;
	unsigned char buff[IP_MAXPACKET];
	int i, j; 

	type = UDP;
	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		printf("file open error!");
	}
	len = read(fd, buff, IP_MAXPACKET);
	if (len < 0)
	{
		printf("file read error!");
	}
	for (i = 0, j = 0; i < len; i++)
	{
		if(buff[i] == ' ' || buff[i] == '\t' || buff[i] == '\n')
			continue;
		pkg[j++] = (hexchar_to_int(buff[i]) << 4) | hexchar_to_int(buff[++i]);
	}
	*pkg_len = j;	
	close(fd);
	return len;
}

int write_file(const unsigned char *pkg, const int pkg_len, const char *path)
{
	int ret = -1;
	return ret;
}


static void data_print(unsigned char *pdata, int len)  
{  
    int i = 0;  
    printf("packet(len = %d) >> \n", len);  
    for(i = 0;  i < len; ++i)  
    {  
        printf("%02X ", *(pdata + i));  
        if((i + 1) % 16 == 0)  
            printf("\n"); 
		else if ((i + 1) % 4 == 0)
			printf(" ");
		 
    }
	if (i % 32 != 0)
	{
		printf("\n"); 
	}  
}  

static void usage(void)
{
	printf("Usage: rawsocket [options]\n"
			"options:\n"
			"-r,            read file path\n"
			"-w,            write file path\n"
			"-i,            net interface\n"
			"-s, --saddr    source IP address\n"
			"-d, --daddr    destination IP address\n"
			"-n,            source MAC address\n"
			"-m,            destination MAC address\n"
			"-p,            print send package\n"
			"-u,            dump receive package\n"
			"-c,            caculate checksum automatically\n"
			"-h, --help     help\n");
}	

static void parse_args(int argc, char *argv[], st_args *args)
{
	struct in_addr addr;
	int8_t arg = 0; 
	const char short_options[] = "r:w:i:s:d:n:m:puch";
	const struct option long_options[] = {
		{"saddr", required_argument, NULL, 's'},
		{"daddr", required_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while((arg = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)  
    {  
        switch(arg)  
        {  
		case 0:
			break;
        case 'r':
			strcpy(rd_path, optarg);
			args->rd_path = rd_path;
            break;  
        case 'w':  
			strcpy(wrt_path, optarg);
			args->wrt_path = wrt_path;
            break; 
		case 'i':
			strcpy(interface, optarg);   
			args->interface = interface;
            break;  
        case 's': 
			inet_aton(optarg, &addr);
			memcpy(&args->src_addr, &addr, sizeof(addr));
            break;  
        case 'd':  
			inet_aton(optarg, &addr);
			memcpy(&args->dst_addr, &addr, sizeof(addr));
            break; 
		case 'n':  
            parse_mac(optarg, args->src_mac); 	
			args->auto_src_mac = 1;
            break; 
		case 'm':  
            parse_mac(optarg, args->dst_mac);
			args->auto_dst_mac = 1; 
            break; 
		case 'p':
			is_debug = 1;
            break; 
		case 'u':  
            is_dump = 1; 
            break; 
		case 'c':  
            auto_check = 1;
            break; 
		case 'h':  
            usage(); 
            exit(EXIT_SUCCESS); 
        default:  
			usage(); 
            exit(EXIT_FAILURE); 
        }  
    } 
	if (args->rd_path != NULL)
	{
		read_file(package, &length, args->rd_path);
	}
	if (args->auto_dst_mac)
	{
		switch (type)
		{
		case UDP:
			memcpy(((st_udp_pkg *)package)->ethhdr.dmac, args->dst_mac, sizeof(args->dst_mac));
			break;
		default:
			break;
		}
	}
	if (args->auto_src_mac)
	{
		switch (type)
		{
		case UDP:
			memcpy(((st_udp_pkg *)package)->ethhdr.smac, args->src_mac, sizeof(args->src_mac));
			break;
		default:
			break;
		}
	}
	else
	{
		int sd;
		// Submit request for a socket descriptor to look up interface.
		if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) 
		{
			perror ("socket() failed to get socket descriptor for using ioctl() ");
		    exit (EXIT_FAILURE);
		}
		// Use ioctl() to look up interface name and get its MAC address.
		struct ifreq ifr;
		memset (&ifr, 0, sizeof (ifr));
		snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
		if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) 
		{
		    perror ("ioctl() failed to get source MAC address ");
		    exit(EXIT_FAILURE);
		}
		close (sd);
		switch (type)
		{
		case UDP:
			memcpy (((st_udp_pkg *)package)->ethhdr.smac, ifr.ifr_hwaddr.sa_data, 6); 
			break;
		default:
			break;
		}
	}
	if (args->src_addr != 0)
	{
		switch (type)
		{
		case UDP:
			((st_udp_pkg *)package)->iphdr.saddr = args->src_addr;
			break;
		default:
			break;
		}
		if (is_debug)
		{
			memcpy(&addr, &((st_udp_pkg *)package)->iphdr.saddr, sizeof(unsigned int));
			printf("src addr:%s\n", inet_ntoa(addr));
		}
	}
	if (args->dst_addr != 0)
	{
		switch (type)
		{
		case UDP:
			((st_udp_pkg *)package)->iphdr.daddr = args->dst_addr;
			break;
		default:
			break;
		}
	}
}	


static int pack_package(unsigned char *buff, int *buff_len)
{
	int ret = -1;
	int len;
	unsigned char tmp_buff[IP_MAXPACKET];

	switch (type)
	{
	case UDP:
		memcpy(buff, package, sizeof(ETH_HDR));
		len = sizeof(ETH_HDR);
		memcpy(buff + len, package + len + 2, sizeof(IP_HDR));
		len = sizeof(ETH_HDR); + sizeof(IP_HDR);
		memcpy(buff + len, package + len + 2, length - len - 2);
		*buff_len = length - 2;

		//change udp length
		unsigned short udp_len;
		len = sizeof(ETH_HDR) + sizeof(IP_HDR);
		udp_len = length - len - 2;
		if (ENDIANNESS == LITTLEENDIAN)
		{	
			udp_len = htons(udp_len);
		}
		memcpy(buff + len + 4, (unsigned char*)&udp_len, 2);
	
		//change ip length
		unsigned short ip_len;
		len = sizeof(ETH_HDR);
		ip_len = length - 2 - len;
		if (ENDIANNESS == LITTLEENDIAN)
		{	
			ip_len = htons(ip_len);
		}
		memcpy(buff + len + 2, (unsigned char*)&ip_len, 2);

		//change ip checksum
		unsigned short ip_sum;
		len = sizeof(ETH_HDR);
		ip_sum = checksum(buff + len, sizeof(IP_HDR));
		memcpy(buff + len + 10, (unsigned char*)&ip_sum, 2);
		 
		if (auto_check)
		{
			//change udp checksum
			unsigned short udp_sum;
			len = sizeof(ETH_HDR);
			memcpy(tmp_buff, buff + len + 12, 8);
			tmp_buff[8] = 0x00;
			tmp_buff[9] = 0x11;
			memcpy(tmp_buff + 10, (unsigned char*)&udp_len, 2);
			len = sizeof(ETH_HDR) + sizeof(IP_HDR);
			memcpy(tmp_buff + 12, buff + len, length - len - 2);
			if (is_debug)
			{
				data_print(tmp_buff, length - len - 2 + 12);
			}
			udp_sum = checksum(tmp_buff, length - len - 2 + 12);
			memcpy(buff + len + 6, (unsigned char*)&udp_sum, 2);		
		}
		break;
	case TCP:
		break;
	case ICMP:
		break;
	case ARP:
		break;
	case RARP:
		break;
	default:
		break;
	}

	return ret;
} 

int main (int argc, char **argv)
{
	int sd, len;
	unsigned char buff[IP_MAXPACKET];
	int buff_len;
	struct sockaddr_ll device;
	st_args args = DEFAULT_ARGS;

	parse_args(argc, argv, &args);
	
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0) 
	{
    	perror ("if_nametoindex() failed to obtain interface index ");
    	exit (EXIT_FAILURE);
	}

	device.sll_family = AF_PACKET;
  	memcpy (device.sll_addr, ((st_udp_pkg *)package)->ethhdr.smac, 6);
  	device.sll_halen = htons (6);

	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) 
	{
    	perror("socket() failed ");
    	exit(EXIT_FAILURE);
	}

	pack_package(buff, &buff_len);

  	if ((len = sendto(sd, buff, buff_len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) 
	{
        perror("sendto() failed");
        exit(EXIT_FAILURE);
	}  

	if (is_debug)
	{
		data_print(buff, buff_len);
	}
  	close(sd);

  	return (EXIT_SUCCESS);
}
