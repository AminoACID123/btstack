#include "hci.h"
#include "hci_transport.h"
#include "hci_transport_h4.h"

typedef struct arg_struct{
    uint8_t packet_type;
    uint8_t* packet;
    uint16_t size;
}arg_struct_t;

const hci_transport_t* hci_transport_fuzz_instance();

void recv_packet(arg_struct_t* arg);