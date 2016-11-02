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
/* Portions Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#define __PCAP_FIFO_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "net_aggr.h"
#include "ports_aggr.h"
#include "pcap_fifo_plugin.h"


/* just do it in a portable way... */
static u_int32_t MyByteSwap32(u_int32_t n) {
  return (((n & 0x000000FF)<<24) +
	  ((n & 0x0000FF00)<<8) +
	  ((n & 0x00FF0000)>>8) +
	  ((n & 0xFF000000)>>24));
}
static u_int16_t MyByteSwap16(u_int16_t n) {
  return ((n >> 8) | (n << 8));
}

#define YES 1
#define NO 0

/* Functions */
void pcap_fifo_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data dummy;
  struct pkt_data *data;
  //struct ports_table pt;
  struct pollfd pfd, fifopfd;
  //struct insert_data idata;
  unsigned char *pipebuf;
  struct timezone tz;
  time_t now;
  int timeout, timeout_fifo;
  int ret, stt;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  char *pipebuf_ptr;
  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;
  int chrs;

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "PCAP FIFO Plugin", config.name);
  //memset(&idata, 0, sizeof(idata));
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
 
  reload_map = FALSE;
  //status->wakeup = TRUE;

  /* a bunch of default definitions and post-checks */
 // pipebuf = (unsigned char *) malloc(config.buffer_size);

  //setnonblocking(pipe_fd);
 // memset(pipebuf, 0, config.buffer_size);
  //no_more_space = FALSE;
  
  //signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGINT, pcap_fifo_exit_now); /* exit lane */
  signal(SIGUSR1, SIG_IGN);
  //signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4 
  signal(SIGCHLD, SIG_IGN); 
#else
  signal(SIGCHLD, ignore_falling_child); 
#endif
  /* some LOCAL initialization AFTER setting some default values */
  //reload_map = FALSE;
  //timeout = 60000; /* dirty */
  //now = time(NULL);
  //refresh_deadline = now;
  //memset(&nt, 0, sizeof(nt));
  //memset(&nc, 0, sizeof(nc));
  ///memset(&dummy, 0, sizeof(dummy));
  //memset(data, 0, sizeof(*data));
  
  pipebuf = (unsigned char *) malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);
 
  timeout = 60 * 1000; /* 1 min */
  timeout_fifo = 2000; /* 2 seconds */
  fifo_socket = (int *) malloc(sizeof(int));
  *fifo_socket = -1;
  
  strlcpy(fifo_name, config.pcap_fifo_path, strlen(config.pcap_fifo_path)+1);
  //DEFAULT: if no fifo name gets to us set the default
  if(strlen(fifo_name) < 1) {
    chrs = strlcpy(fifo_name, pcap_fifo_default_path, 15);
    strlcpy(fifo_name + chrs, config.name, 15);
  }

  pcap_fifo_init_pipe(&pfd, pipe_fd);
  
  //fifopfd.fd = *fifo_socket;
  //fifopfd.events = POLLOUT;
  //setnonblocking(*fifo_socket);
  
    
  /* plugin main loop */
  /*PCAP FIFO ALPHA*/
  for(;;) {
	poll_again:
	
	//Don't want to wait for data from the plugin pipe before creating the fifo
	//stt = poll(&fifopfd, 1, timeout_fifo);
	//if (stt < 0) goto poll_again;
    if (*fifo_socket < 0) init_pcap_fifo(fifo_name,fifo_socket);
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
	
    if (ret < 0) goto poll_again;
	
	if (ret > 0) {
		read_data:
		
		  if (!pollagain) {
			seq++;
			seq %= MAX_SEQNUM;
			if (seq == 0) rg_err_count = FALSE;
		  }
		  else {
			if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
			  exit_plugin(1); /* we exit silently; something happened at the write end */
			  
		  }
		   if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
			if (!pollagain) {
			  pollagain = TRUE;
			  goto poll_again;
			}
			else {
		  rg_err_count++;
		  if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
			Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
			Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
			Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
			Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
			Log(LOG_ERR, "- increase system maximum socket size.\n\n");
		  }
		  seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
		}
		  }
		  
		  pollagain = FALSE;
		  memcpy(pipebuf, rg->ptr, bufsz);
		  if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
		  else rg->ptr += bufsz;
		
		  pipebuf_ptr = pipebuf+ChBufHdrSz;
		  data = (struct pkt_data *) pipebuf_ptr;
		  //print_payload(data->primitives.packet_header, sizeof(data->primitives.packet_header));
		  //print_payload(data->primitives.packet_payload, sizeof(data->primitives.packet_payload));
			if (*fifo_socket > 0) {
				char fifo_output[2048];
				int fifo_bytes;
				
				memset(fifo_output,0,sizeof(fifo_output));
				memset(&fifo_bytes,0,sizeof(fifo_bytes));
				
				writePcapPacket(data, &fifo_bytes, fifo_output);
				if (write_to_pcap_fifo(fifo_output, fifo_socket, &fifo_bytes) == -1) {
					unlink_pcap_fifo(fifo_name);
					goto poll_again;
				}
			}
			((struct ch_buf_hdr *)pipebuf)->num--;
			if (((struct ch_buf_hdr *)pipebuf)->num) data++;
		 goto read_data;
	  }
    }close_pcap_fifo(*fifo_socket);
	 unlink_pcap_fifo(&fifo_name);
  } 
//

/*_________________---------------------------__________________
  _________________   writePcapHeader         __________________
  -----------------___________________________------------------
*/
#define TCPDUMP_MAGIC 0xa1b2c3d4  /* from libpcap-0.5: savefile.c */
#define DLT_EN10MB	1	  /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

void writePcapHeader(int *bytes, char *output) {
  struct pcap_my_file_header hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TCPDUMP_MAGIC;
  hdr.version_major = PCAP_VERSION_MAJOR;
  hdr.version_minor = PCAP_VERSION_MINOR;
  hdr.thiszone = 0;
  hdr.snaplen = (config.snaplen ? config.snaplen : DEFAULT_SNAPLEN);
  hdr.sigfigs = 0;
  hdr.linktype = DLT_EN10MB;
  /*if (fwrite((char *)&hdr, sizeof(hdr), 1, stdout) != 1) {
    fprintf(stderr, "failed to write tcpdump header: %s\n", strerror(errno));
    exit(-1);
  }
  */
  
  memcpy(output, (char *)&hdr, sizeof(hdr)); //Blech this is ugly
  *bytes = sizeof(hdr);
  //fflush(stdout);
}

/*_________________---------------------------__________________
  _________________   writePcapPacket         __________________
  -----------------___________________________------------------
*/

void writePcapPacket(struct pkt_data *pdata, int *bytes, char *output) {
  u_char buf[2048], extract_length[7],extract_true_length[7], *caplen_ptr, *truelen_ptr;
  int byteme = 0;
  int header_length, payload_length, cap_length, header_primitive_length, payload_primitive_length, true_packet_length;
  struct pcap_my_pkthdr hdr;
  
  payload_primitive_length = sizeof(pdata->primitives.packet_payload) - 8;
  header_primitive_length = sizeof(pdata->primitives.packet_header) - 9;
  /*XXX dirty*/
  header_length = (int)pdata->primitives.packet_header[sizeof(pdata->primitives.packet_header) - 2];
  
  
  caplen_ptr = &pdata->primitives.packet_payload[payload_primitive_length];
  memset(extract_length, 0, sizeof(extract_length) -1);
  memcpy(extract_length, caplen_ptr, sizeof(extract_length) - 1);
  //extract_length[sizeof(extract_length) - 1] = '\0';
  sscanf(extract_length, "%i", &payload_length);
  
  
  truelen_ptr = &pdata->primitives.packet_header[header_primitive_length];
  memset(extract_true_length, 0, sizeof(extract_true_length) - 1);
  memcpy(extract_true_length, truelen_ptr, sizeof(extract_true_length)- 1);
  //extract_true_length[sizeof(extract_true_length) - 1] = '\0';
  sscanf(extract_true_length, "%i", &true_packet_length);
  
  
  if (payload_length > payload_primitive_length) payload_length = payload_primitive_length;
  else if (payload_length < 0) payload_length = 0;
  if (header_length > header_primitive_length) header_length = header_primitive_length;
  else if (header_length < 0) header_length = 0;
  
  
  cap_length = header_length + payload_length;
  //printf("Captured Length:%d\n", cap_length);
  //printf("True Length:%d\n", true_packet_length);
  if (true_packet_length < 0 || true_packet_length > 1518) true_packet_length = cap_length;
  
  hdr.ts.tv_sec = time(NULL);
  hdr.ts.tv_usec = 0;
  hdr.len = true_packet_length;
  hdr.caplen = cap_length;
  /*if(config.removeContent && sample->offsetToPayload) {
    // shorten the captured header to ensure no payload bytes are included
    hdr.caplen = sample->offsetToPayload;
  }
  */
  // prepare the whole thing in a buffer first, in case we are piping the output
  // to another process and the reader expects it all to appear at once...
  memcpy(buf, &hdr, sizeof(hdr));
  byteme = sizeof(hdr);

  memcpy(buf+byteme, pdata->primitives.packet_header, header_length);
  byteme += header_length;
  memcpy(buf+byteme, pdata->primitives.packet_payload, payload_length);
  byteme += payload_length;
  
  memcpy(output, &buf, byteme); //Blech this is ugly
  *bytes = byteme;
}
/*_________________---------------------------__________________
  _________________   write_to_pcap_fifo         __________________
  -----------------___________________________------------------
*/
int write_to_pcap_fifo(char *input, int *fifo_socket, int *bytes) {
	//FILE *fifo_so;
	//fifo_so = (FILE *) malloc(sizeof(FILE));
	
	//DEFAULT: if no fifo name gets to us set the default
	//if(strlen(fifo_name) < 1) strlcpy(fifo_name, "/tmp/pcap_fifo", 15);
	
	//fifo_so = fdopen(*fifo_socket, "w");
	//results=write(fd,"testies", 7);
	
	//if(fifo_so == NULL) {
	//	Log(LOG_WARNING, "WARN ( default/core ): Initializing PCAP packet FIFO stream FAILED! ...\n");
	//	return -1;
	//} 
	//else {
		//Log(LOG_INFO, "INFO ( default/core ): Initializing PCAP packet FIFO ...\n");
		if(write(*fifo_socket, input, *bytes) == -1) {
			Log(LOG_ERR, "ERROR ( %s/%s ): Writing to PCAP packet FIFO FAILED! ...\n", config.name, config.type);
			*fifo_socket = -1;
			return ERR;
		}
	//}
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): Copy to PCAP packet FIFO stream ...\n", config.name, config.type);
	//free(fifo_so);
	return SUCCESS;
}
/*_________________---------------------------__________________
  _________________   Init_pcap_fifo        __________________
  -----------------___________________________------------------
*/
int init_pcap_fifo(char *fifo_name, int *fifo_socket) {
	int sstatus, bytes;
	u_char output[128];
		
	if (mknod(fifo_name, S_IFIFO | 0777, 0) < 0) {
		unlink(fifo_name);
		if (mknod(fifo_name, S_IFIFO | 0777, 0) < 0) {
			Log(LOG_ERR, "ERROR ( %s/%s ): Creating PCAP packet FIFO FAILED! ...\n", config.name, config.type);
		}
	}
	//sstatus = mkfifo(fifo_name, 0777);
	*fifo_socket = open(fifo_name, O_WRONLY);
	
	if(*fifo_socket == -1) {
		Log(LOG_WARNING, "WARN ( %s/%s ): Initializing PCAP packet FIFO FAILED! ...\n", config.name, config.type);
		return ERR;
	} 
	else {
		Log(LOG_INFO, "INFO ( %s/%s ): Initializing PCAP packet FIFO ...\n", config.name, config.type);
		writePcapHeader(&bytes, output);
		sstatus = write_to_pcap_fifo(output, fifo_socket, &bytes);
		if (sstatus == ERR) {
			return ERR;
		}
		return SUCCESS;
	}
}
/*_________________---------------------------__________________
  _________________   close_pcap_fifo         __________________
  -----------------___________________________------------------
*/
void close_pcap_fifo(int *fifo_socket) {
	close(*fifo_socket);
	Log(LOG_INFO, "INFO ( %s/%s ): Closed PCAP packet FIFO ...\n", config.name, config.type);
}

void unlink_pcap_fifo(char *fifo_name) {
	unlink(*fifo_name);
	Log(LOG_INFO, "INFO ( %s/%s ): Deleting PCAP packet FIFO ...\n", config.name, config.type);
}

void pcap_fifo_init_pipe(struct pollfd *pollfd, int fd)
{
  pollfd->fd = fd;
  pollfd->events = POLLIN;
  setnonblocking(fd);
}

void pcap_fifo_exit_now(int signum)
{   
   close_pcap_fifo(fifo_socket);
   unlink_pcap_fifo(&fifo_name);
   exit_plugin(0);
}
