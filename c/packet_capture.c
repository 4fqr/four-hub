


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <pcap/pcap.h>
#include "packet_capture.h"



struct fh_capture {
    pcap_t  *handle;
    char     errbuf[PCAP_ERRBUF_SIZE];
};



fh_capture_t *
fh_capture_open(const char *iface, int snaplen, int promisc, char *errbuf)
{
    if (!iface || !errbuf) {
        if (errbuf) strncpy(errbuf, "invalid arguments", 255);
        return NULL;
    }

    fh_capture_t *ctx = (fh_capture_t *)calloc(1, sizeof(fh_capture_t));
    if (!ctx) {
        snprintf(errbuf, 256, "%s", "out of memory");
        return NULL;
    }

    
    mlock(ctx, sizeof(fh_capture_t));

    ctx->handle = pcap_open_live(
        iface,
        snaplen > 0 ? snaplen : FH_SNAPLEN,
        promisc,
        1000,          
        ctx->errbuf
    );

    if (!ctx->handle) {
        snprintf(errbuf, 256, "%s", ctx->errbuf);
        munlock(ctx, sizeof(fh_capture_t));
        free(ctx);
        return NULL;
    }

    return ctx;
}



int
fh_capture_set_filter(fh_capture_t *cap, const char *filter_str)
{
    if (!cap || !filter_str) return -1;

    struct bpf_program fp;
    bpf_u_int32 net  = 0;
    bpf_u_int32 mask = 0;

    
    char tmp_err[PCAP_ERRBUF_SIZE];
    pcap_lookupnet(pcap_datalink_val_to_name(pcap_datalink(cap->handle)),
                   &net, &mask, tmp_err);

    if (pcap_compile(cap->handle, &fp, filter_str, 1, net) != 0) {
        return -1;
    }
    int rc = pcap_setfilter(cap->handle, &fp);
    pcap_freecode(&fp);
    return rc;
}



int
fh_capture_next(fh_capture_t *cap, fh_packet_t *out)
{
    if (!cap || !out) return -1;

    struct pcap_pkthdr *hdr  = NULL;
    const u_char       *data = NULL;

    int rc = pcap_next_ex(cap->handle, &hdr, &data);
    

    if (rc == 1 && hdr && data) {
        out->ts_sec  = (uint64_t)hdr->ts.tv_sec;
        out->ts_usec = (uint32_t)hdr->ts.tv_usec;
        out->origlen = hdr->len;
        out->caplen  = hdr->caplen < FH_SNAPLEN ? hdr->caplen : FH_SNAPLEN;
        memcpy(out->data, data, out->caplen);
        return 1;
    }

    return rc == 0 ? 0 : -1;
}



void
fh_capture_stats(fh_capture_t *cap, uint64_t *ps_recv, uint64_t *ps_drop)
{
    if (!cap || !ps_recv || !ps_drop) return;

    struct pcap_stat st;
    if (pcap_stats(cap->handle, &st) == 0) {
        *ps_recv = (uint64_t)st.ps_recv;
        *ps_drop = (uint64_t)st.ps_drop;
    } else {
        *ps_recv = 0;
        *ps_drop = 0;
    }
}



void
fh_capture_close(fh_capture_t *cap)
{
    if (!cap) return;
    if (cap->handle) {
        pcap_close(cap->handle);
        cap->handle = NULL;
    }
    
    memset(cap->errbuf, 0, sizeof(cap->errbuf));
    munlock(cap, sizeof(fh_capture_t));
    free(cap);
}
