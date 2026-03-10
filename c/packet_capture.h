/*
 * four-hub · c/packet_capture.h
 * Public interface for the raw-packet capture C extension.
 */

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum captured bytes per packet. */
#define FH_SNAPLEN 65535

/* Packet metadata + raw bytes returned to Rust. */
typedef struct {
    uint64_t ts_sec;      /* Epoch seconds                */
    uint32_t ts_usec;     /* Microseconds part            */
    uint32_t caplen;      /* Bytes actually captured      */
    uint32_t origlen;     /* Original packet length       */
    uint8_t  data[FH_SNAPLEN]; /* Raw bytes              */
} fh_packet_t;

/* Opaque capture handle. */
typedef struct fh_capture fh_capture_t;

/*
 * fh_capture_open – open a live capture on `iface`.
 * Returns a heap-allocated handle or NULL on error (error in `errbuf`).
 * `errbuf` must be at least 256 bytes.
 */
fh_capture_t *fh_capture_open(const char *iface,
                               int         snaplen,
                               int         promisc,
                               char       *errbuf);

/*
 * fh_capture_next – capture one packet (blocking, with 1 s timeout).
 * Returns 1 on success, 0 on timeout, -1 on error.
 */
int fh_capture_next(fh_capture_t *cap, fh_packet_t *out);

/*
 * fh_capture_set_filter – apply a BPF filter string.
 * Returns 0 on success, -1 on error.
 */
int fh_capture_set_filter(fh_capture_t *cap, const char *filter_str);

/*
 * fh_capture_close – close and free the capture handle.
 */
void fh_capture_close(fh_capture_t *cap);

/*
 * fh_capture_stats – fill in received / dropped packet counts.
 */
void fh_capture_stats(fh_capture_t *cap,
                      uint64_t *ps_recv,
                      uint64_t *ps_drop);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_CAPTURE_H */
