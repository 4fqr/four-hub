

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define FH_SNAPLEN 65535


typedef struct {
    uint64_t ts_sec;      
    uint32_t ts_usec;     
    uint32_t caplen;      
    uint32_t origlen;     
    uint8_t  data[FH_SNAPLEN]; 
} fh_packet_t;


typedef struct fh_capture fh_capture_t;


fh_capture_t *fh_capture_open(const char *iface,
                               int         snaplen,
                               int         promisc,
                               char       *errbuf);


int fh_capture_next(fh_capture_t *cap, fh_packet_t *out);


int fh_capture_set_filter(fh_capture_t *cap, const char *filter_str);


void fh_capture_close(fh_capture_t *cap);


void fh_capture_stats(fh_capture_t *cap,
                      uint64_t *ps_recv,
                      uint64_t *ps_drop);

#ifdef __cplusplus
}
#endif

#endif 
