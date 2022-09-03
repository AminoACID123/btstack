#include "hci_transport_fuzz.h"
#include "btstack_run_loop.h"
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

static void (*packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size);
static uint8_t hci_packet_out[1 + HCI_OUTGOING_PACKET_BUFFER_SIZE]; // packet type + max(acl header + acl payload, cmd header   +   cmd data)
static uint8_t hci_packet_in[1 + HCI_INCOMING_PACKET_BUFFER_SIZE]; // packet type + max(acl header + acl payload, event header + event data)
static btstack_data_source_t* ds;

static int hci_transport_fuzz_set_baudrate(uint32_t baudrate)
{ 
    return 0;
}

static int hci_transport_fuzz_can_send_now(uint8_t packet_type)
{ 
    return 1;
}

static int hci_transport_fuzz_send_packet(uint8_t packet_type, uint8_t * packet, int size){
    printf("Sending packet\n");
    if (ds == NULL) return -1;

    // preapare packet
    hci_packet_out[0] = packet_type;
    memcpy(&hci_packet_out[1], packet, size);

    // send
    // int res = mtk_bt_write(hci_transport_h4->ds->source.fd, hci_packet_out, size + 1);

	struct iovec iv[1];
	iv[0].iov_base = hci_packet_out;
	iv[0].iov_len = size + 1;
    if( writev(ds->source.fd, iv, 1) <= 0){
        perror("Failed to open send packet");
		return -1;
    }
    printf("Sent\n");
    
    static const uint8_t packet_sent_event[] = { HCI_EVENT_TRANSPORT_PACKET_SENT, 0};
    packet_handler(HCI_EVENT_PACKET, (uint8_t *) &packet_sent_event[0], sizeof(packet_sent_event));
    
    return 0;
}

static void hci_transport_fuzz_init(const void * transport_config){ }

static void fuzz_process(btstack_data_source_t *_ds, btstack_data_source_callback_type_t callback_type) {
    if (ds->source.fd == 0) return;

    // read up to bytes_to_read data in
    ssize_t bytes_read = read(ds->source.fd, &hci_packet_in[0], sizeof(hci_packet_in));

    if (bytes_read == 0) return;

    // iterate over packets
    uint16_t pos = 0;
    while (pos < bytes_read) {
        uint16_t packet_len;
        switch(hci_packet_in[pos]){
            case HCI_EVENT_PACKET:
                packet_len = hci_packet_in[pos+2] + 3;
                break;
            case HCI_ACL_DATA_PACKET:
                 packet_len = little_endian_read_16(hci_packet_in, pos + 3) + 5;
                 break;
            default:
                // log_error("h4_process: invalid packet type 0x%02x\n", hci_packet_in[pos]);
                return;
        }

       // if(hci_packet_in[pos+4] == 0x01 && hci_packet_in[pos+5] == 0x13)
      //  {
                    printf("%02x %02x\n", hci_packet_in[pos+4], hci_packet_in[pos+5]);
      //  }
        packet_handler(hci_packet_in[pos], &hci_packet_in[pos+1], packet_len-1);
        pos += packet_len;
    }
    
}


static int hci_transport_fuzz_open(void)
{
    const char* unix_path = "/tmp/bt-server-bredr";
	struct sockaddr_un addr;
	size_t len;
	int fd;

	len = strlen(unix_path);
	if (len > sizeof(addr.sun_path) - 1) {
		fprintf(stderr, "Path too long\n");
		return -1;
	}

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to open Unix server socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);
	// if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	// 	perror("Failed to bind Unix server socket");
	// 	close(fd);
	// 	return -1;
	// }

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
  		perror("Failed to connect");
		close(fd);
		return -1;      
    }

    // set up data_source
    ds = (btstack_data_source_t*) malloc(sizeof(btstack_data_source_t));
    if (!ds) return -1;
    memset(ds, 0, sizeof(btstack_data_source_t));
    btstack_run_loop_set_data_source_fd(ds, fd);
    btstack_run_loop_set_data_source_handler(ds, &fuzz_process);
    btstack_run_loop_enable_data_source_callbacks(ds, DATA_SOURCE_CALLBACK_READ);
    btstack_run_loop_add_data_source(ds);
    return 0;
}


static int hci_transport_fuzz_close(void)
{ 
    return 0; 
}

static void hci_transport_fuzz_register_packet_handler(void (*handler)(uint8_t packet_type, uint8_t *packet, uint16_t size))
{
    packet_handler = handler;
}

void recv_packet(arg_struct_t* arg)
{
    const uint8_t data1[] = {0x0E, 0x04, 0x01, 0x03, 0x0c, 0x00};
    packet_handler(HCI_EVENT_PACKET, data1, sizeof(data1));
    const uint8_t data2[] = {0x0E, 12, 1, 0x01, 0x10, 0, 10, 0, 0, 0, 0, 0 ,0, 0};
    packet_handler(HCI_EVENT_PACKET, data2, sizeof(data2));
}

static const hci_transport_t hci_transport_fuzz = {
        /* const char * name; */                                        "FUZZ",
        /* void   (*init) (const void *transport_config); */            NULL,
        /* int    (*open)(void); */                                     &hci_transport_fuzz_open,
        /* int    (*close)(void); */                                    &hci_transport_fuzz_close,
        /* void   (*register_packet_handler)(void (*handler)(...); */   &hci_transport_fuzz_register_packet_handler,
        /* int    (*can_send_packet_now)(uint8_t packet_type); */       &hci_transport_fuzz_can_send_now,
        /* int    (*send_packet)(...); */                               &hci_transport_fuzz_send_packet,
        /* int    (*set_baudrate)(uint32_t baudrate); */                NULL,
        /* void   (*reset_link)(void); */                               NULL,
        /* void   (*set_sco_config)(uint16_t voice_setting, int num_connections); */ NULL,
};


const hci_transport_t* hci_transport_fuzz_instance(){
    return &hci_transport_fuzz;
}
