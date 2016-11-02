/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2006 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */

/* prototypes */
void pcap_fifo_plugin(int, struct configuration *, void *);
int init_pcap_fifo(char *, int *);
void writePcapHeader(int *, char *);
void writePcapPacket(struct pkt_data *, int *, char *);
int write_to_pcap_fifo(char *, int *, int *);
void close_pcap_fifo(int *);
void unlink_pcap_fifo(char *);
void pcap_fifo_init_pipe(struct pollfd *, int);
void pcap_fifo_exit_now(int);
/* variables */
static char pcap_fifo_default_path[] = "/tmp/pcap_fifo";
/*JK*/
char fifo_name[256];
int *fifo_socket;
FILE *fifo_stream;
int fifo_header;
/*end JK*/




/* tcpdump file format */

struct pcap_my_file_header {
  u_int32_t magic;
  u_int16_t version_major;
  u_int16_t version_minor;
  u_int32_t thiszone;	/* gmt to local correction */
  u_int32_t sigfigs;	/* accuracy of timestamps */
  u_int32_t snaplen;	/* max length saved portion of each pkt */
  u_int32_t linktype;	/* data link type (DLT_*) */
  };

struct pcap_my_pkthdr {
  struct timeval ts;	/* time stamp */
  u_int32_t caplen;	/* length of portion present */
  u_int32_t len;	/* length this packet (off wire) */
  /* some systems expect to see more information here. For example,
   * on some versions of RedHat Linux, there are three extra fields:
   *   int index;
   *   unsigned short protocol;
   *   unsigned char pkt_type;
   * To pad the header with zeros, use the tcpdumpHdrPad option.
   */
};
