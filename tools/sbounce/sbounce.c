/* sbounce: splidge's zBounce alike.
 *
 * Version 1.2
 *
 * Copyright (C) 2003 David Mansell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistributions of source code
 * retain the above copyright notice, this condition and the following
 * disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <zlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>

/*
 * Various settings and constants that CAN be tweaked if you so desire..
 */

/* Buffer / network settings */
#define BUFSIZE 65536
#define MAXFDS  100
#define LISTEN_RECVBUF    61440
#define RECVBUF           61440
#define SENDBUF           61440

/* File settings */
#ifndef SETTINGSFILE
#define SETTINGSFILE      "/opt/ircd/lib/bounce.conf"
#endif
#ifndef LOGFILE
#define LOGFILE           "/opt/ircd/lib/sbounce.log"
#endif
#ifndef PIDFILE
#define PIDFILE           "/opt/ircd/lib/sbounce.pid"
#endif

#define STATSINTERVAL     300         /* How frequently to write compression stats to a file */

/* These two directly affect the lag induced by the bouncer.. */
#define POLLTIMEOUT       100         /* The main poll timeout */
#define FLUSHTIMEOUT      80000       /* How long (in uSec) between last output and forcing a flush */

#undef  DONTDETACH                    /* Define this to make it not detach */

/* Magic constants and macros etc. - these should NOT be tweaked :) */
#define SST_IDLE           0x00000
#define SST_LISTEN_COMP    0x10001
#define SST_LISTEN_DECOMP  0x10002
#define SST_COMP           0x20001
#define SST_DECOMP         0x20002

#define IsListenSocket(x)     (ssa[(x)].type & 0x10000)
#define IsActiveSocket(x)     (ssa[(x)].type & 0x20000)

#define IsCompressSocket(x)   (ssa[(x)].type & 0x1)
#define IsDecompressSocket(x) (ssa[(x)].type & 0x2)

/* Function prototypes */
void handlefd(int fd, short events);
void handlelistenfd(int fd, short events);

int logfd;

typedef struct ssock {
  int              type;

  /* poll() stuff - valid for all types */
  int              pollfdpos;
  short            events;

  /* Address stuff - valid for listen types only */
  unsigned int     listenaddr;
  unsigned short   listenport;
  unsigned int     remoteaddr;
  unsigned short   remoteport;
  int              marker;

  /* Things valid for connected sockets only */
  z_stream         zs;
  int              companion;
  unsigned char   *inbuf;
  unsigned char   *outbuf;
  unsigned char   *overflow;
  int              overflowsize;
  struct timeval   lastoutput;
  int              dirty;
  time_t           lastdump;
} ssock;

typedef struct validip {
  unsigned int     IPaddress;
  struct validip  *next;
} validip;

ssock          ssa[MAXFDS];
struct pollfd  pfd[MAXFDS];
int            cur_pfds;
validip       *okhosts;
int            needrehash;
char           configfile[512];

void init() {
  int i;
  FILE *f;

  memset(ssa, 0, MAXFDS * sizeof(ssock));
  memset(pfd, 0, MAXFDS * sizeof(struct pollfd));

  /* Non-zero init here */
  for(i=0;i<MAXFDS;i++) {
    ssa[i].pollfdpos = -1;
    ssa[i].companion = -1;
  }

  cur_pfds=0;
  okhosts=NULL;
  needrehash=0;

#ifndef DONTDETACH
  if ((logfd=open(LOGFILE, O_CREAT | O_WRONLY | O_APPEND,00660)) < 0) {
    printf("ERROR: can't open logfile.\n");
    exit(1);
  }

  if (fork())
    exit(0);

  if (fork())
    exit(0);
#endif

  f = fopen(PIDFILE, "w");
  if (f == NULL) {
    fprintf(stderr, "Couldn't create pid file \"%s\": %s",
    PIDFILE, strerror(errno));   
  } else {
    fprintf(f, "%ld\n", (long) getpid());
    fclose(f);
  }
}

long usecdiff(struct timeval *tv1, struct timeval *tv2) {
  long secdiff  = tv2->tv_sec - tv1->tv_sec;
  long usecdiff = tv2->tv_usec - tv1->tv_usec;
  
  return (secdiff * 1000000) + usecdiff;
}

void logwrite(char *message, ...) {
  char buf[512];
  char buf2[512];
  char buf3[512];
  struct tm *tmp;
  time_t now;
  int len;

  va_list va;

  va_start(va,message);
  vsnprintf(buf,512,message,va);
  va_end(va);

  now=time(NULL);
  tmp=localtime(&now);
  strftime(buf2, 512, "%Y-%m-%d %H:%M",tmp);
#ifdef DONTDETACH
  printf("[%s] %s",buf2,buf);
#else
  len=snprintf(buf3,512,"[%s] %s",buf2,buf);

  write(logfd, buf3, len);
#endif
}

char *IPtostr(unsigned int ip) {
  static char buf1[15];
  static char buf2[15];
  char *buf;
  static int count=0;

  if ((count++)%2)
    buf=buf1;
  else
    buf=buf2;
  
  sprintf(buf,"%d.%d.%d.%d",ip&255,(ip>>8)&255,(ip>>16)&255,(ip>>24)&255);
  
  return buf;
}

/* setpoll(): Set the specified fd to be checked for the specified events.
 * If events==0, remove the fd from the array. 
 */

void setpoll(int fd, short events) {  
  if (events) {
    if (ssa[fd].pollfdpos > -1) {
      /* Already in the array.. */
      assert(pfd[ssa[fd].pollfdpos].fd == fd);
      pfd[ssa[fd].pollfdpos].events=events;
      ssa[fd].events=events;
      return;
    } else {
      /* Not in the array, add to the end */
      ssa[fd].pollfdpos=cur_pfds;
      pfd[cur_pfds].fd=fd;
      pfd[cur_pfds].events=events;
      pfd[cur_pfds].revents=0;
      ssa[fd].events=events;
      cur_pfds++;

      return;
    }
  } else {
    if (ssa[fd].pollfdpos==-1) {
      /* This FD wasn't in the array */
      return;
    } else {
      cur_pfds--;
      if (ssa[fd].pollfdpos!=cur_pfds) {
	/* We need to swap the entry from the end in here */
	pfd[ssa[fd].pollfdpos].fd     = pfd[cur_pfds].fd;
	pfd[ssa[fd].pollfdpos].events = pfd[cur_pfds].events;
	pfd[ssa[fd].pollfdpos].revents = pfd[cur_pfds].revents;
	
	ssa[pfd[cur_pfds].fd].pollfdpos = ssa[fd].pollfdpos;
      }

      ssa[fd].pollfdpos=-1;
      ssa[fd].events=0;
      return;
    }
  }
}

/*
 * dopoll(): Calls poll(), and then calls handlefd() for each fd that had
 * events.
 */

int dopoll(int timeout) {
  int i,ret;

  if ((ret=poll(pfd, cur_pfds, timeout))) {
    if (ret<0 && errno!=EINTR) {
      logwrite("poll() error: %d\n",errno);
      return 0;
    }
    for(i=0;i<cur_pfds;i++) {
      if (pfd[i].revents) {
	handlefd(pfd[i].fd, pfd[i].revents);
      }
    }
    return 1;
  } else {
    return 0;
  }
}

/* 
 * initconnection(): Set up to compressor/decompressor for the specified socket.
 * Allocate buffers and set socket options.
 */

void initconnection(int fd) {
  unsigned int rbuf=RECVBUF, sbuf=SENDBUF, opt=1;

  ssa[fd].inbuf =(unsigned char *)malloc(BUFSIZE);
  ssa[fd].outbuf=(unsigned char *)malloc(BUFSIZE);
  memset(&(ssa[fd].zs), 0, sizeof(z_stream));

  if (IsCompressSocket(fd)) {
    if (deflateInit(&(ssa[fd].zs), 6) != Z_OK) {
      logwrite("Error initialising deflate!\n");
    }
  } else {
    if (inflateInit(&(ssa[fd].zs)) != Z_OK) {
      logwrite("Error initialising inflate!\n");
    }
  }

  ssa[fd].zs.next_in=ssa[fd].inbuf;
  ssa[fd].zs.avail_in=0;
  ssa[fd].zs.next_out=ssa[fd].outbuf;
  ssa[fd].zs.avail_out=0;

  ssa[fd].dirty=0;
  ssa[fd].lastdump=time(NULL);

  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*) &rbuf, sizeof(rbuf)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*) &sbuf, sizeof(sbuf))) {
    logwrite("Error setting socket buffers on fd %d\n",fd);
  }

  if (ioctl(fd, FIONBIO, &opt) == -1) {
    logwrite("Error setting socket non-blocking on fd %d\n",fd);
  }
  
  ssa[fd].overflowsize=0;
}

/*
 * killconnection(): Kills off the compressor/decompressor and frees all buffers
 */

void killconnection(int fd) {
  close(fd);
  setpoll(fd,0);
  free(ssa[fd].inbuf);
  free(ssa[fd].outbuf);
  if (IsCompressSocket(fd)) {
    deflateEnd(&(ssa[fd].zs));
  } else {
    inflateEnd(&(ssa[fd].zs));
  }
  ssa[fd].type=SST_IDLE;
}
  
/*
 * flushdata(): Flushes all data from the specified fd.
 *  Returns 0  if all data was written.
 *  Returns 1  if there is some data left.
 *  Returns -1 if there was a socket error.
 */

int flushdata(int fd) {
  int genbytes,bytesout;
  int companionfd=ssa[fd].companion;

  if ((genbytes=ssa[fd].overflowsize)==0)
    return 0; /* nothing there */
  
  bytesout=write(companionfd, ssa[fd].overflow, genbytes);
  
  if (bytesout!=genbytes) {
    /* It didn't all get written */
    if (bytesout==-1) {
      if (errno==EAGAIN) {
	return 1;
      } else {
	logwrite("Error writing to fd %d: %d\n",companionfd,errno);
	return -1;
      }
    }

    /* Short write - I'm ASSUMING this is cos the socket buffer filled up */
    ssa[fd].overflowsize-=bytesout;
    ssa[fd].overflow+=bytesout;
    return 1;
  }

  /* Clear the overflow and return */
  ssa[fd].overflowsize=0;

  return 0;
} 
  
/*
 * handledata(): Handles data outstanding on the specified fd.
 *   Returns 0 if everything went OK
 *   Returns 1 if there was an error
 * 
 * This function will manipulate the poll() array as necessary if sockets become blocked.
 */

int handledata(int fd, int forceflush) {
  int ret;
  int companionfd = ssa[fd].companion;
  struct timezone tz;

  /* Check we don't have outstanding data to write.. */
  if ((ret=flushdata(fd))) {
    if (ret==1) {
      return 0;
    } else {
      return 1;
    }
  }

  if (ssa[fd].dirty == 0) {
    gettimeofday(&(ssa[fd].lastoutput), &tz);
  }
  
  if (ssa[fd].zs.avail_in || forceflush) {
    for(;;) {
      ssa[fd].zs.next_out=ssa[fd].outbuf;
      ssa[fd].zs.avail_out=BUFSIZE;
      
      if (IsCompressSocket(fd)) {
	ret=deflate(&(ssa[fd].zs), forceflush ? Z_SYNC_FLUSH : 0);
      } else { 
	ret=inflate(&(ssa[fd].zs), Z_SYNC_FLUSH);
      }
      
      if (ret != Z_OK && ret != Z_BUF_ERROR) {
	logwrite("Compression error %d on fd %d.\n",ret,fd);
	return 1;
      }
      
      /* Mark all generated data as overflow */
      ssa[fd].overflowsize = (BUFSIZE - ssa[fd].zs.avail_out);
      ssa[fd].overflow     = ssa[fd].outbuf;

      /* If it actually produced anything, make a note.. */
      if (ssa[fd].overflowsize) {
	gettimeofday(&(ssa[fd].lastoutput), &tz);
      
	/* And flush */
	if ((ret=flushdata(fd))) {
	  if (ret==1) {
	    /* It's full - swap the poll() stuff around */
	    setpoll(fd, ssa[fd].events & ~POLLIN);
	    setpoll(companionfd, ssa[companionfd].events | POLLOUT);
	    ssa[fd].dirty=0;
	    return 0;
	  } else {
	    /* It broke, return error */
	    return 1;
	  }
	}
      }

      if (ssa[fd].zs.avail_in == 0)
	break;
    }
  }

  /* OK, we dealt with everything */
  if (!(ssa[fd].events & POLLIN)) {
    /* We need to swap poll() things back */
    setpoll(fd, ssa[fd].events | POLLIN);
    setpoll(companionfd, ssa[companionfd].events & ~POLLOUT);
    ssa[fd].dirty=1;
  }

  return 0;
}

/*
 * handlefd(): Deals with events occuring on the specified fd.
 */

void handlefd(int fd, short events) {
  /* Palm off listen sockets elsewhere */
  int bytes;
  int companionfd;

  companionfd=ssa[fd].companion;

  if (IsListenSocket(fd)) {
    handlelistenfd(fd, events); 
    return;
  }

  if (events & POLLIN) {
    /* Input data to be handled by the [de]compressor - read all data, compress
       and send to companion socket.  If the companion blocks, we make the companion
       poll for POLLOUT and stop this socket polling for POLLIN. */

    /* It's an INVARIANT that if we were polling for POLLIN there is nothing in the input OR output buffers
     * from this socket. */
     
    if (ssa[fd].overflowsize || ssa[fd].zs.avail_in || !(ssa[fd].events & POLLIN)) {
      logwrite("Unexpected input data on fd %d. - overflowsize=%d avail_in=%d ev=%d pfdev=%d rev=%d\n",fd,ssa[fd].overflowsize,
               ssa[fd].zs.avail_in, pfd[ssa[fd].pollfdpos].events, ssa[fd].events, events);
    } else {
      if ((bytes=read(fd, ssa[fd].inbuf, BUFSIZE))<=0) {
        if (bytes==0) {
          /* EOF */
          logwrite("Connection closed (EOF) - closing fds %d and %d.\n",fd,companionfd);
          killconnection(companionfd);
          killconnection(fd);
          return;
        } else if (errno==EAGAIN) {
          /* Just EAGAIN.. return and come back later */
          return;
        } else {
          logwrite("Connection close (Read error - %s) - closing fds %d and %d.\n",strerror(errno),fd,companionfd);
          killconnection(companionfd);
          killconnection(fd);
          return;
        }
      }
	
      ssa[fd].zs.next_in=ssa[fd].inbuf;
      ssa[fd].zs.avail_in=bytes;
    
      if (handledata(fd, 0)) {
        /* Error return - close connection */
        logwrite("Connection closed (ERROR) - closing fds %d and %d.\n",fd,companionfd);
        killconnection(companionfd);
        killconnection(fd);
        return;
      }
      ssa[fd].dirty=1;
      if (time(NULL) - ssa[fd].lastdump > STATSINTERVAL) {
        ssa[fd].lastdump=time(NULL);
        logwrite("fd %d Stats: %d bytes in, %d bytes out.\n",fd,ssa[fd].zs.total_in,ssa[fd].zs.total_out);
      }
    }
  }

  if (events & POLLOUT) {
    /* We can write - need to grab output data from companion socket and write it out.
       If we manage to empty the buffer, we should set the companion socket to wait 
       for POLLIN again -- handledata() does ALL this for us */

    if (handledata(companionfd, 0)) {
      /* Error return - close connection */
      logwrite("Connection closed (ERROR) - closing fds %d and %d.\n",fd,companionfd);
      killconnection(companionfd);
      killconnection(fd);
      return;
    }
  }

  if (events & (POLLERR|POLLHUP|POLLNVAL)) {
    /* Something has broken - close this socket and companion and clean everything up */
    logwrite("Connection error - closing fds %d and %d.\n",fd,ssa[fd].companion);
    killconnection(ssa[fd].companion);
    killconnection(fd);
  }
}

/*
 * handlelistenfd(): Deals with activity on a listening FD (i.e. incoming connection)
 */

void handlelistenfd(int fd, short events) {
  int newfd, companionfd;
  struct sockaddr_in sin;
  unsigned int len=sizeof(struct sockaddr_in);
  validip *vip;
  int res;

  if (events & POLLIN) {
    /* We have a connection - need to accept(), initialise the [de]compressor and set up
     * a companion socket, initiating a non-blocking connect() to the remote address. */
    
    newfd=accept(fd, (struct sockaddr *) &sin, &len);
    
    if (newfd >= MAXFDS) {
      logwrite("FD %d out of range - closing connection.  Recompile with larger MAXFDS\n",newfd);
      close(newfd);
      return;
    }

    /* Check that this host is authorised to connect */
    for (vip=okhosts;vip;vip=vip->next) {
      if (vip->IPaddress == sin.sin_addr.s_addr)
	break;
    }

    if (!vip) {
      logwrite("Rejecting unauthorised connection from %d.%d.%d.%d\n",sin.sin_addr.s_addr & 255,
	     (sin.sin_addr.s_addr >> 8) & 255, (sin.sin_addr.s_addr >> 16) & 255, 
	     (sin.sin_addr.s_addr >> 24) & 255);
      close(newfd);
      return;
    }

    /* Set the type */
    ssa[newfd].type = ssa[fd].type+0x10000;
    initconnection(newfd);

    /* By default we listen on the NEW socket we open only.. */
    setpoll(newfd,0);

    /* Now set up the companion socket */
    if ((companionfd=socket(AF_INET,SOCK_STREAM,0))==-1) {
      logwrite("Error creating companion socket!\n");
      killconnection(newfd);
      return;
    }

    if (companionfd >= MAXFDS) {
      logwrite("FD %d out of range - closing connection.  Recompile with larger MAXFDS.\n",companionfd);
      close(companionfd);
      killconnection(newfd);
      return;
    }

    logwrite("Accepted connection from %d.%d.%d.%d.  fd=%d, companion=%d\n",sin.sin_addr.s_addr & 255,
	   (sin.sin_addr.s_addr >> 8) & 255, (sin.sin_addr.s_addr >> 16) & 255, 
	   (sin.sin_addr.s_addr >> 24) & 255, newfd, companionfd);

    if (ssa[newfd].type == SST_COMP)
      ssa[companionfd].type = SST_DECOMP;
    else
      ssa[companionfd].type = SST_COMP;

    initconnection(companionfd);

    sin.sin_addr.s_addr=ssa[fd].remoteaddr;
    sin.sin_port = htons(ssa[fd].remoteport);
    if ((res=connect(companionfd, (struct sockaddr *) &sin, sizeof(struct sockaddr)))) {
      if (errno != EINPROGRESS) {
	logwrite("Error connecting companion socket: %d\n",errno);
	killconnection(newfd);
	killconnection(companionfd);
	return;
      }
    }

    setpoll(companionfd, POLLIN|POLLOUT);

    /* Set the companion fields up */
    ssa[companionfd].companion = newfd;
    ssa[newfd].companion = companionfd;
  }

  if (events & (POLLERR|POLLHUP|POLLNVAL)) {
    /* Something has broken - this shouldn't happen (famous last words) 
     * but clean up the listen socket */
    ssa[fd].type = SST_IDLE;
    close(fd);
    setpoll(fd, 0);
  }
}

/*
 * openlistenfd(): Creates a listening socket
 */

int openlistenfd(int type, unsigned int listenip, unsigned short listenport,
		 unsigned int remoteip, unsigned short remoteport) {
  struct sockaddr_in sin;
  int                fd;
  unsigned int       opt=1;

  if ((fd=socket(AF_INET,SOCK_STREAM,0))==-1) {
    logwrite("openlistenfd(): Error creating socket\n");
    return 1;
  }
  
  logwrite("Creating %s listener on %s:%d forwarding to %s:%d\n",
	 type==SST_LISTEN_COMP ? "compressing" : "decompressing", IPtostr(listenip),listenport,IPtostr(remoteip),remoteport);

  if (fd>=MAXFDS) {
    logwrite("openlistenfd(): fd out of range - recompile with larger MAXFDS\n");
    close(fd);
    return 1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &opt, sizeof(opt))!=0) {
    logwrite("openlistenfd(): Error setting SO_REUSEADDR\n");
    close(fd);
    return 1;
  }
  
  /* Initialiase the addresses */
  memset(&sin,0,sizeof(sin));
  sin.sin_family=AF_INET;
  sin.sin_port=htons(listenport);
  sin.sin_addr.s_addr=listenip;
  
  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin))) {
    logwrite("openlistenfd(): Unable to bind socket.\n");
    close(fd);
    return 1;
  }

  opt = LISTEN_RECVBUF;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*) &opt, sizeof(opt))) {
    logwrite("openlistenfd(): Error setting socket buffer size.\n");
  }

  if (listen(fd,5)) {
    logwrite("openlistenfd(): Unable to listen.\n");
    close(fd);
    return 1;
  }
  
  /* Now do the specific setup - only the following fields are relevant for listeners */
  ssa[fd].type = type;
  ssa[fd].listenaddr = listenip;
  ssa[fd].listenport = listenport;
  ssa[fd].remoteaddr = remoteip;
  ssa[fd].remoteport = remoteport;
  ssa[fd].marker = 1;

  setpoll(fd, POLLIN);
  
  return 0;
}

/*
 * parseconfig(): Reads the config file, setting up and destroying listeners as necessary
 */

int parseconfig(const char *filename) {
  validip *vip, *nvip;
  FILE *fp;
  char buf[512];
  int i;
  unsigned int ip1,ip2;
  unsigned short port1, port2;
  unsigned int type;
  struct hostent *hep;
  char *cp,*cp2;
  int found;

  /* Check that we can open the file before we blow away the old state.. */
  if (!(fp=fopen(filename,"r"))) {
    logwrite("parseconfig(): Can't open config file!\n");
    return 1;
  }

  /* Clear out the list of trusted IPs */
  for (vip=okhosts;vip;vip=nvip) {
    nvip=vip->next;
    free(vip);
  }
  okhosts=NULL;

  /* Clear all markers */
  for (i=0;i<MAXFDS;i++) {
    ssa[i].marker=0;
  }

  while(!feof(fp)) {
    fgets(buf, 512, fp);

    if (feof(fp))
      break;

    /* Check for valid config types.. */
    if (*buf=='A') {
      if (buf[1]!=':') {
	logwrite("parseconfig(): malformed config line %s\n",buf);
	continue;
      }
      
      for (cp=buf+2;*cp;cp++) {
	if (*cp=='\n') {
	  *cp='\0';
	  break;
	}
      }

      hep=gethostbyname(buf+2);
      if (hep && hep->h_addr) {
	vip=malloc(sizeof(struct validip));
	vip->IPaddress=*(unsigned int *)hep->h_addr;
	vip->next=okhosts;
	okhosts=vip;
      } else {
	logwrite("parseconfig(): unable to parse: %s\n",buf+2);
      }
    }

    if (*buf=='p' || *buf=='P') {
      type=(*buf=='p'?SST_LISTEN_DECOMP:SST_LISTEN_COMP);
      
      if (buf[1]!=':') {
	logwrite("parseconfig(): malformed config line %s\n",buf);
	continue;
      }
      
      /* P:212.115.48.227:4480:212.115.48.164:4410 */
      cp2=buf+2;
      for (cp=buf+2;*cp && *cp!=':';cp++);
      if (!*cp) {
	logwrite("parseconfig(): malformed config line %s\n",buf);
	continue;
      }

      *cp++='\0';
      hep=gethostbyname(cp2);
      if (!hep || !(ip1=*(unsigned int *)hep->h_addr)) {
	logwrite("parseconfig(): Invalid host %s\n",cp2);
	continue;
      }

      if (!(port1=strtol(cp, &cp, 10))) {
	logwrite("parseconfig(): Invalid config line\n");
	continue;
      }
      
      if (*cp++!=':') {
	logwrite("parseconfig(): Malformed config line\n");
	continue;
      }

      cp2=cp;
      for (;*cp && *cp!=':';cp++); 
      if (!cp) { 
        logwrite("parseconfig(): malformed config line.\n"); 
        continue; 
      }    
           
      *cp++='\0'; 
      hep=gethostbyname(cp2); 
      if (!hep || !(ip2=*((unsigned int *)hep->h_addr))) { 
        logwrite("parseconfig(): Invalid host %s\n",cp2); 
        continue; 
      } 

      if (!(port2=strtol(cp, &cp, 10))) {
	logwrite("parseconfig(): Invalid config line\n");
	continue;
      }

      /* Check for matching listeners.. */
      found=0;
      for (i=0;i<MAXFDS;i++) {
	if (IsListenSocket(i) && ssa[i].listenaddr==ip1 && ssa[i].listenport==port1 &&
	    ssa[i].remoteaddr==ip2 && ssa[i].remoteport==port2) {
	  /* Found one, just set the type (allows p: <-> P: rehashes) */
	  ssa[i].type=type;
	  ssa[i].marker=1;
	  found=1;
	  break;
	}
      }
      if (!found)
	openlistenfd(type, ip1, port1, ip2, port2);
    }
  }

  fclose(fp);

  /* Kill off dead listeners */
  for (i=0;i<MAXFDS;i++) {
    if (IsListenSocket(i) && ssa[i].marker==0) {
      logwrite("Closing extinct listen socket %d\n",i);
      setpoll(i,0);
      ssa[i].type=SST_IDLE;
      close(i);
    }
  }

  return 0;
}

void handlehup(int x) {
  needrehash=1;
}

void dorehash() {
  close(logfd);
  if ((logfd=open(LOGFILE, O_CREAT | O_WRONLY | O_APPEND,00660)) < 0) {
    printf("ERROR: can't reopen logfile.\n");                            
    exit(1); 
  }
  logwrite("Received SIGHUP - reloading config file.\n");
  parseconfig(configfile);
  needrehash=0;
}

int main(int argc, char **argv) {
  struct sigaction sa;
  int i;
  struct timezone tz;
  struct timeval tv;

  sa.sa_handler=handlehup;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags=0;

  strncpy(configfile, (argc > 1 ? argv[1] : SETTINGSFILE), 511);

  init();
  sigaction(SIGHUP, &sa, NULL);
  sa.sa_handler=SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);

  if (parseconfig(configfile)) {
    return 1;
  }

  for(;;) {
    if (!dopoll(POLLTIMEOUT)) {
      for (i=0;i<MAXFDS;i++) {
	if (ssa[i].dirty==1 && IsActiveSocket(i)) {
	  /* Flush everything */
	  handledata(i,1);
	  ssa[i].dirty=0;
	}
      }
      while (!dopoll(1000)) {
	if (needrehash)
	  dorehash();
      }
    } else {
      /* something happened - do a more detailed dirty check */
      gettimeofday(&tv, &tz);
      for (i=0;i<MAXFDS;i++) {
	if (ssa[i].dirty==1 && IsActiveSocket(i)) {
	  if (usecdiff(&(ssa[i].lastoutput), &tv) > FLUSHTIMEOUT) {
	    handledata(i,1);
	    ssa[i].dirty=0;
	  }
	}
      }
    }	
    if (needrehash)
	dorehash();
  }
  
  return 0;
}
