/*
 * IRC - Internet Relay Chat, ircd/m_check.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 * University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "channel.h"
#include "check.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "IPcheck.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_osdep.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_user.h"
#include "s_debug.h"
#include "s_misc.h"

#include <string.h>

#define CHECK_CHECKCHAN  0x01 /* -c */
#define CHECK_SHOWUSERS  0x02 /* ! -u */
#define CHECK_OPSONLY    0x04 /* -o */
#define CHECK_SHOWIPS    0x08 /* -i */
#define CHECK_CIDRMASK   0x10 /* automatically detected when performing a hostmask /CHECK */
#define CHECK_OPLEVELS   0x20 /* -l */
#define CHECK_CLONES     0x40 /* -C */
#define CHECK_SHOWSERVER 0x80 /* -s */
#define CHECK_SHOWHOSTIP 0x100 /* -I */
#define CHECK_SHOWMORE   0x200 /* -e */

/*
 * - ASUKA ---------------------------------------------------------------------
 * This is the implimentation of the CHECK function for Asuka.
 * Some of this code is from previous QuakeNet ircds, but most of it is mine..
 * The old code was written by Durzel (durzel@quakenet.org).
 * 
 * qoreQ (qoreQ@quakenet.org) - 08/14/2002
 * -----------------------------------------------------------------------------
 */

/*
 * Syntax: CHECK <channel|nick|server|hostmask> [-flags]
 * 
 * Where valid flags are:
 * -c: Show channels when checking a hostmask.
 * -e: show more inform when checking a mask.
 * -i: Show IPs instead of hostnames when displaying results.
 * -l: Show oplevels when checking a channel.
 * -o: Only show channel operators when checking a channel.
 * -s: show server user is on when checking a channel (or on a mask when combined with -e).
 * -u: Hide users when checking a channel.
 * -C: Perform clone count when checking a channel.
 * -I: show hostnames and IPs when checking a channel.
 *
 * <hostmask> can be of the form host, user@host, nick!user@host, 
 * with host being host.domain.cc, 127.0.0.1 or 127.0.0.0/24.
 * Wildcards are supported.
 */

int m_check(struct Client *cptr, struct Client *sptr, int parc, char *parv[]) {
  struct Channel *chptr;
  struct Client *acptr;
  int flags = CHECK_SHOWUSERS, i;

  if (!HasPriv(sptr, PRIV_CHECK))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2) {
    send_reply(sptr, ERR_NEEDMOREPARAMS, "CHECK");
    return 0;
  }

  if ( parc>=4 ||
      (parc==3 && parv[2][0] != '-')) {
    /* remote query */
    if (hunt_server_cmd(sptr, CMD_CHECK, cptr,  0, parc==4 ? "%C %s %s" : "%C %s", 1, parc, parv) != HUNTED_ISME)
      return 0;
    parv++; parc--;
  }

  /* This checks to see if any flags have been supplied */
  if ((parc >= 3) && (parv[2][0] == '-')) {
    for (i = 0; parv[2][i]; i++) {
      switch (parv[2][i]) {
      case 'c':
        flags |= CHECK_CHECKCHAN;
        break;
        
      case 'o':
        flags |= CHECK_OPSONLY; /* fall through */
      case 'u':
        flags &= ~(CHECK_SHOWUSERS);
        break;
        
      case 'i':
        flags |= CHECK_SHOWIPS;
        break;
      case 'l':
        flags |= CHECK_OPLEVELS;
        break;
      case 'C':
        flags |= CHECK_CLONES;
        break;
      case 's':
        flags |= CHECK_SHOWSERVER;
        break;
      case 'I':
        flags |= CHECK_SHOWHOSTIP;
        break;
      case 'e':
        flags |= CHECK_SHOWMORE;
        break; 
     default:
        /* might want to raise some sort of error here? */
        break;
      }
    }
  }

  if (IsChannelName(parv[1])) { /* channel */
    if ((chptr = FindChannel(parv[1]))) {
      checkChannel(sptr, chptr);
      checkUsers(sptr, chptr, flags);
    }
    else
      send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
  }
  else if ((acptr = FindClient(parv[1])) && !(FindServer(parv[1]))) { /* client and not a server */
    if (!IsRegistered(acptr)) {
      send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
      return 0;
    }

    checkClient(sptr, acptr);
  }
  else if ((acptr = FindServer(parv[1]))) { /* server */
    checkServer(sptr, acptr);
  }
  else if (checkHostmask(sptr, parv[1], flags) > 0) /* hostmask */
    return 1;
  else /* no match */
    send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
 
  return 1;
}



/* return number of clients from same IP on the channel */
static int checkClones(struct Channel *chptr, struct Client *cptr) {
  int clones = 0, count = 0;
  struct Membership *lp;
  struct Client *acptr;

  for (lp = chptr->members; lp; lp = lp->next_member) {
    acptr = lp->user;
    if (are_ips_clones(&cli_ip(cptr),&cli_ip(acptr))) { 
      clones++;
    }
  }

  /* Optimise only if we will actually save CPU time */
  if (clones >= 2) {
    for (lp = chptr->members; lp; lp = lp->next_member) {
      acptr = lp->user;
      if (are_ips_clones(&cli_ip(cptr),&cli_ip(acptr))) {
        cli_marker(acptr) = clones;
        count++;
        if (clones == count) {
          break;
        }
      }
    }
  }

  return clones;
}


/* compare IPs from clients and return 1 when they are clones
 *  same IPv4 IP
 *  IPv4 and IPv6 IPs, but IPv4 over IPv6 etc cases
 *  IPv6 IPs from the same /64 block 
 */
int are_ips_clones(const struct irc_in_addr *ip1, const struct irc_in_addr *ip2) {
  int ipv4ip1 = has_ipv4_addr(ip1);

  /* are both ip addresses ipv4 or ipv6? if not, no clones */
  if (ipv4ip1 != has_ipv4_addr(ip2)) return 0;

  if (ipv4ip1) /* check ipv4 */
    return (get_ipv4_addr(ip1) == get_ipv4_addr(ip2)) ? 1 : 0;

  /* check ipv6 */
  return ipmask_check(ip1, ip2, IPV6USERBITS) ? 1 : 0;
}


void checkUsers(struct Client *sptr, struct Channel *chptr, int flags) {
  struct Membership *lp;
  struct Ban *ban;
  struct Client *acptr;

  char outbuf[BUFSIZE], outbuf2[BUFSIZE], ustat[64];
  int cntr = 0, opcntr = 0, vcntr = 0, clones = 0, bans = 0, authed = 0, delayedjoin = 0;

  if (flags & CHECK_SHOWUSERS) { 
    send_reply(sptr, RPL_DATASTR, "Users (@ = op, + = voice)");
  }

  if (flags & CHECK_CLONES) {
    for (lp = chptr->members; lp; lp = lp->next_member) {
      cli_marker(lp->user) = 0;
    }
  }

  for (lp = chptr->members; lp; lp = lp->next_member) {
    int opped = 0, c = 0;

    acptr = lp->user;

    if (flags & CHECK_CLONES) {
      if (!cli_marker(acptr)) {
        c = checkClones(chptr, acptr);
      } else {
        c = cli_marker(acptr);
      }

      if (c != 1) {
        clones++;
      }
    }

    if (IsChanOp(lp)) {
      if (flags & CHECK_OPLEVELS) {
        if (c) {
          ircd_snprintf(0, ustat, sizeof(ustat), "%2d %3hu@", c, OpLevel(lp));
        } else {
          ircd_snprintf(0, ustat, sizeof(ustat), "%3hu@", OpLevel(lp));
        }
      } else {
        if (c) {
          ircd_snprintf(0, ustat, sizeof(ustat), "%2d @", c);
        } else {
          ircd_snprintf(0, ustat, sizeof(ustat), "@");
        }
      }
      opcntr++;
      opped = 1;
    }
    else if (HasVoice(lp)) {
      if (c) {
        ircd_snprintf(0, ustat, sizeof(ustat), "%2d %s+", c, (flags & CHECK_OPLEVELS) ? "   " : "");
      } else {
        ircd_snprintf(0, ustat, sizeof(ustat), "%s", (flags & CHECK_OPLEVELS) ? "   +" : "+");
      }
      vcntr++;
    }
    else if (IsDelayedJoin(lp)) {
      if (c) {
        ircd_snprintf(0, ustat, sizeof(ustat), "%2d %s<", c, (flags & CHECK_OPLEVELS) ? "   " : "");
      } else {
        ircd_snprintf(0, ustat, sizeof(ustat), "%s", (flags & CHECK_OPLEVELS) ? "   <" : "<");
      }
      delayedjoin++;
    }
    else {
      if (c) {
        ircd_snprintf(0, ustat, sizeof(ustat), "%2d  %s", c, (flags & CHECK_OPLEVELS) ? "   " : "");
      } else {
        ircd_snprintf(0, ustat, sizeof(ustat), " %s", (flags & CHECK_OPLEVELS) ? "   " : "");
      }
    }

    if ((c = IsAccount(acptr))) {
      authed++;
    }

    if ((flags & CHECK_SHOWUSERS) || ((flags & CHECK_OPSONLY) && opped)) {
      ircd_snprintf(0, outbuf, sizeof(outbuf), "%s%c", acptr->cli_info, COLOR_OFF);
      if (flags & CHECK_SHOWHOSTIP) {
        ircd_snprintf(0, outbuf2, sizeof(outbuf2), " [%s]", ircd_ntoa(&(cli_ip(acptr))));
      }
      send_reply(sptr, RPL_CHANUSER, ustat, acptr->cli_name, cli_user(acptr)->realusername,
            ((flags & CHECK_SHOWIPS) ? ircd_ntoa(&(cli_ip(acptr))) : cli_user(acptr)->realhost), (flags & CHECK_SHOWHOSTIP) ? outbuf2 : "", (flags & CHECK_SHOWSERVER) ? cli_name(cli_user(acptr)->server) : outbuf,
            (c ? cli_user(acptr)->account : ""));
    }

    cntr++;
  }

  send_reply(sptr, RPL_DATASTR, " ");

  if (flags & CHECK_CLONES) {
    ircd_snprintf(0, outbuf, sizeof(outbuf),
        "Total users:: %d (%d ops, %d voiced, %d clones, %d authed, %d hidden)",
        cntr, opcntr, vcntr, clones, authed, delayedjoin);

    for (lp = chptr->members; lp; lp = lp->next_member) {
      cli_marker(lp->user) = 0;
    }
  } else {
    ircd_snprintf(0, outbuf, sizeof(outbuf),
        "Total users:: %d (%d ops, %d voiced, %d authed, %d hidden)",
        cntr, opcntr, vcntr, authed, delayedjoin);
  }

  send_reply(sptr, RPL_DATASTR, outbuf);
  send_reply(sptr, RPL_DATASTR, " ");

  /* Do not display bans if ! flags & CHECK_SHOWUSERS */
  if (flags & CHECK_SHOWUSERS) {
    send_reply(sptr, RPL_DATASTR, "Bans on channel::");

    for (ban = chptr->banlist; ban; ban = ban->next) {
      ircd_snprintf(0, outbuf, sizeof(outbuf),  "[%d] - %s - Set by %s, on %s (%Tu)",
        ++bans, ban->banstr, ban->who, myctime(ban->when), ban->when);
      send_reply(sptr, RPL_DATASTR, outbuf);
    }

    if (bans == 0)
      send_reply(sptr, RPL_DATASTR, "<none>");
  }

  send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkChannel(struct Client *sptr, struct Channel *chptr) {
  char outbuf[TOPICLEN + MODEBUFLEN + 64], modebuf[MODEBUFLEN], parabuf[MODEBUFLEN];

  /* Header */
  send_reply(sptr, RPL_DATASTR, " ");
  send_reply(sptr, RPL_CHKHEAD, "channel", chptr->chname);
  send_reply(sptr, RPL_DATASTR, " ");

  /* Creation Time */
  ircd_snprintf(sptr, outbuf, sizeof(outbuf), "  Creation time:: %s (%Tu)", myctime(chptr->creationtime), chptr->creationtime);
  send_reply(sptr, RPL_DATASTR, outbuf);

  /* Topic */
  if (strlen(chptr->topic) <= 0)
    send_reply(sptr, RPL_DATASTR, "          Topic:: <none>");
  else {
    ircd_snprintf(sptr, outbuf, sizeof(outbuf), "          Topic:: %s", chptr->topic);
    send_reply(sptr, RPL_DATASTR, outbuf);

    /* ..set by */
    ircd_snprintf(sptr, outbuf, sizeof(outbuf), "         Set by:: %s", chptr->topic_nick);
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(sptr, outbuf, sizeof(outbuf), "         Set at:: %s (%Tu)", myctime(chptr->topic_time), chptr->topic_time);
    send_reply(sptr, RPL_DATASTR, outbuf); 
  }

  /* Channel Modes */

  strcpy(outbuf, "Channel mode(s):: ");

  modebuf[0] = '\0';
  parabuf[0] = '\0';

  channel_modes(sptr, modebuf, parabuf, sizeof(modebuf), chptr, NULL);

  if(modebuf[1] == '\0')
      strcat(outbuf, "<none>");
  else if(*parabuf) {
    strcat(outbuf, modebuf);
    strcat(outbuf, " ");
    strcat(outbuf, parabuf);
  }
  else
    strcat(outbuf, modebuf);

  send_reply(sptr, RPL_DATASTR, outbuf);

  /* Don't send 'END OF CHECK' message, it's sent in checkUsers, which is called after this. */
}

void checkClient(struct Client *sptr, struct Client *acptr) {
  struct Channel *chptr;
  struct Membership *lp;
  struct irc_sockaddr sin;
  char outbuf[BUFSIZE];
  char *umodes;
  time_t nowr;

  /* Header */
  send_reply(sptr, RPL_DATASTR, " ");
  send_reply(sptr, RPL_CHKHEAD, "user", cli_name(acptr));
  send_reply(sptr, RPL_DATASTR, " ");

  ircd_snprintf(0, outbuf, sizeof(outbuf), "           Nick:: %s (%s%s)", cli_name(acptr), NumNick(acptr));
  send_reply(sptr, RPL_DATASTR, outbuf);

  if (MyUser(acptr)) {  
    ircd_snprintf(0, outbuf, sizeof(outbuf),  "      Signed on:: %s (%Tu)", myctime(acptr->cli_firsttime), acptr->cli_firsttime);
    send_reply(sptr, RPL_DATASTR, outbuf);
  }

  ircd_snprintf(0, outbuf, sizeof(outbuf), "      Timestamp:: %s (%d)", myctime(acptr->cli_lastnick), acptr->cli_lastnick);
  send_reply(sptr, RPL_DATASTR, outbuf);

  ircd_snprintf(0, outbuf, sizeof(outbuf), "  User/Hostmask:: %s@%s (%s)", cli_user(acptr)->username, cli_user(acptr)->host,
  ircd_ntoa(&(cli_ip(acptr))));
  send_reply(sptr, RPL_DATASTR, outbuf);

  if (IsSetHost(acptr) || HasHiddenHost(acptr)) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), " Real User/Host:: %s@%s", cli_user(acptr)->realusername, cli_user(acptr)->realhost);
    send_reply(sptr, RPL_DATASTR, outbuf);
  }

  ircd_snprintf(0, outbuf, sizeof(outbuf), "      Real Name:: %s%c", cli_info(acptr), COLOR_OFF);
  send_reply(sptr, RPL_DATASTR, outbuf);

  if( IsService(cli_user(acptr)->server)) {
    if (IsChannelService(acptr))
      send_reply(sptr, RPL_DATASTR, "         Status:: Network Service");
    else if (IsAnOper(acptr))
      send_reply(sptr, RPL_DATASTR, "         Status:: IRC Operator (service) (ID: %s)", cli_user(acptr)->opername ? cli_user(acptr)->opername : "<unknown>");
    else 
      send_reply(sptr, RPL_DATASTR, "         Status:: Client (service)");
  } else if (IsAnOper(acptr)) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "         Status:: IRC Operator (ID: %s)", cli_user(acptr)->opername ? cli_user(acptr)->opername : "<unknown>");
    send_reply(sptr, RPL_DATASTR, outbuf);
  } else
    send_reply(sptr, RPL_DATASTR, "         Status:: Client");

  ircd_snprintf(0, outbuf, sizeof(outbuf), "   Connected to:: %s (Hops: %d)", cli_name(cli_user(acptr)->server), cli_hopcount(acptr));
  send_reply(sptr, RPL_DATASTR, outbuf);

  /* +s (SERV_NOTICE) is not relayed to us from remote servers,
   * so we cannot tell if a remote client has that mode set.
   * And hacking it onto the end of the output of umode_str is EVIL BAD AND WRONG
   * (and breaks if the user is +r) so we won't do that either.
   */

  /* show the usermodes and account info (but not OperID and sethost)  */
  umodes = umode_str(acptr, UMODE_AND_ACCOUNT);
  ircd_snprintf(0, outbuf, sizeof(outbuf), "    Usermode(s):: %s%s", *umodes ? "+" : "<none>", umodes);
  send_reply(sptr, RPL_DATASTR, outbuf);

  if (cli_user(acptr)->joined == 0)
    send_reply(sptr, RPL_DATASTR, "     Channel(s):: <none>");
  else if (cli_user(acptr)->joined > 50) {

    /* NB. As a sanity check, we DO NOT show the individual channels the
     *     client is on if it is on > 50 channels.  This is to prevent the ircd
     *     barfing ala Uworld when someone does /quote check Q :).. (I shouldn't imagine
     *     an Oper would want to see every single channel 'x' client is on anyway if
     *     they are on *that* many).
     */

    ircd_snprintf(0, outbuf, sizeof(outbuf), "     Channel(s):: - (total: %u)", cli_user(acptr)->joined);
    send_reply(sptr, RPL_DATASTR, outbuf);
  }
  else {
    char chntext[BUFSIZE];
    int len = strlen("     Channel(s):: ");
    int mlen = strlen(me.cli_name) + len + strlen(cli_name(sptr));
    *chntext = '\0';

    strcpy(chntext, "     Channel(s):: ");
    for (lp = cli_user(acptr)->channel; lp; lp = lp->next_channel) {
      chptr = lp->channel;
      if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5) {
        send_reply(sptr, RPL_DATASTR, chntext);
        *chntext = '\0';
        strcpy(chntext, "     Channel(s):: ");
        len = strlen(chntext);
      }
      if (IsDeaf(acptr))
        *(chntext + len++) = '-';
      if (!PubChannel(chptr))
        *(chntext + len++) = '*';
      if (IsZombie(lp))
        *(chntext + len++) = '!';
      if (IsChanOp(lp))
        *(chntext + len++) = '@';
      else if (HasVoice(lp))
        *(chntext + len++) = '+';
      else if (IsDelayedJoin(lp))
        *(chntext + len++) = '<';
      if (len)
        *(chntext + len) = '\0';

      strcpy(chntext + len, chptr->chname);
      len += strlen(chptr->chname);
      strcat(chntext + len, " ");
      len++;
    }

    if (chntext[0] != '\0')
      send_reply(sptr, RPL_DATASTR, chntext);
  }

  if (MyUser(acptr)) {
    nowr = CurrentTime - cli_user(acptr)->last;
    ircd_snprintf(0, outbuf, sizeof(outbuf), "       Idle for:: %d days, %02ld:%02ld:%02ld",
        nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
    send_reply(sptr, RPL_DATASTR, outbuf);
  }

  /* Away message (if applicable) */
  if (cli_user(acptr)->away) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "   Away message:: %s", cli_user(acptr)->away);
    send_reply(sptr, RPL_DATASTR, outbuf);
  }

  /* If local user.. */
  if (MyUser(acptr)) {
    os_get_peername(con_fd(cli_connect(sptr)), &sin);

    send_reply(sptr, RPL_DATASTR, " ");
    ircd_snprintf(0, outbuf, sizeof(outbuf), "          Ports:: %d -> %d (client -> server)",
        sin.port, cli_listener(acptr)->addr.port);
    send_reply(sptr, RPL_DATASTR, outbuf);
    if (feature_bool(FEAT_EXTENDED_CHECKCMD)) {
      /* Note: sendq = receiveq for a client (it makes sense really) */
      ircd_snprintf(0, outbuf, sizeof(outbuf), "      Data sent:: %lu.%0.3u Kb (%u protocol messages)",
            (unsigned long)cli_receiveB(acptr) / 1024, (unsigned long)cli_receiveB(acptr) % 1024, cli_receiveM(acptr));
      send_reply(sptr, RPL_DATASTR, outbuf);                          
      ircd_snprintf(0, outbuf, sizeof(outbuf), "  Data received:: %lu.%0.3lu Kb (%u protocol messages)",
            (unsigned long)cli_sendB(acptr) / 1024, (unsigned long)cli_sendB(acptr) % 1024, cli_sendM(acptr));
      send_reply(sptr, RPL_DATASTR, outbuf);
      ircd_snprintf(0, outbuf, sizeof(outbuf), "  receiveQ size:: %d bytes (max. %d bytes)",
            DBufLength(&(cli_recvQ(acptr))), feature_int(FEAT_CLIENT_FLOOD));
      send_reply(sptr, RPL_DATASTR, outbuf);
            ircd_snprintf(0, outbuf, sizeof(outbuf), "     sendQ size:: %d bytes (max. %d bytes)",
            DBufLength(&(cli_sendQ(acptr))), get_sendq(acptr));                                
      send_reply(sptr, RPL_DATASTR, outbuf);                
    }
  }

  /* Send 'END OF CHECK' message */
  send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkServer(struct Client *sptr, struct Client *acptr) {
  char outbuf[BUFSIZE];

  /* Header */
  send_reply(sptr, RPL_DATASTR, " ");
  send_reply(sptr, RPL_CHKHEAD, "server", acptr->cli_name);
  send_reply(sptr, RPL_DATASTR, " ");

  ircd_snprintf(0, outbuf, sizeof(outbuf), "   Connected at:: %s (%Tu)", myctime(acptr->cli_serv->timestamp), acptr->cli_serv->timestamp);
  send_reply(sptr, RPL_DATASTR, outbuf);

  ircd_snprintf(0, outbuf, sizeof(outbuf), "    Server name:: %s", acptr->cli_name);
  send_reply(sptr, RPL_DATASTR,  outbuf);

  ircd_snprintf(0, outbuf, sizeof(outbuf), "        Numeric:: %s --> %d", NumServ(acptr), base64toint(acptr->cli_yxx));
  send_reply(sptr, RPL_DATASTR, outbuf);
  
  ircd_snprintf(0, outbuf, sizeof(outbuf), "          Users:: %d / %d", (acptr == &me) ? UserStats.local_clients : cli_serv(acptr)->clients, 
    base64toint(cli_serv(acptr)->nn_capacity));
  send_reply(sptr, RPL_DATASTR, outbuf);
  
  if (IsBurst(acptr))
    send_reply(sptr, RPL_DATASTR, "         Status:: Bursting");
  else if (IsBurstAck(acptr))
    send_reply(sptr, RPL_DATASTR, "         Status:: Awaiting EOB Ack");
  else if (IsService(acptr))
    send_reply(sptr, RPL_DATASTR, "         Status:: Network Service");
  else if (IsHub(acptr))
    send_reply(sptr, RPL_DATASTR, "         Status:: Network Hub");
  
  if (feature_bool(FEAT_EXTENDED_CHECKCMD)) {
    int dlinkc = 0;
    struct DLink* slink = NULL;
    
    send_reply(sptr, RPL_DATASTR, " ");
    send_reply(sptr, RPL_DATASTR, "Downlinks::");
    for (slink = cli_serv(acptr)->down; slink; slink = slink->next) {
      ircd_snprintf(0, outbuf, sizeof(outbuf), "[%d] - %s%s", ++dlinkc, 
            IsBurst(slink->value.cptr) ? "*" : IsBurstAck(slink->value.cptr) ? "!" : IsService(slink->value.cptr) ? "=" : IsHub(slink->value.cptr) ? "+" : " ", 
            cli_name(slink->value.cptr));
      send_reply(sptr, RPL_DATASTR, outbuf);
    }
    
    if (!dlinkc)
      send_reply(sptr, RPL_DATASTR, "<none>");
  }

  /* Send 'END OF CHECK' message */
  send_reply(sptr, RPL_ENDOFCHECK, " ");
}

signed int checkHostmask(struct Client *sptr, char *orighoststr, int flags) {
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *lp;
  int count = 0, found = 0;
  char outbuf[BUFSIZE];
  char targhost[NICKLEN + USERLEN + HOSTLEN + 3], curhost[NICKLEN + USERLEN + HOSTLEN + 3];
  char hoststr[NICKLEN + USERLEN + HOSTLEN + 3];
  char nickm[NICKLEN + 1], userm[USERLEN + 1], hostm[HOSTLEN + 1];
  char *p = NULL;
  char *umodes;
  struct irc_in_addr cidr_check;
  unsigned char cidr_check_bits;

  ircd_strncpy(hoststr, orighoststr, NICKLEN + USERLEN + HOSTLEN + 3);
  strcpy(nickm,"*");
  strcpy(userm,"*");
  strcpy(hostm,"*");

  if (!strchr(hoststr, '!') && !strchr(hoststr, '@'))
    ircd_strncpy(hostm,hoststr,HOSTLEN);
  else {
    if ((p = strchr(hoststr, '@'))) {
      *p++ = '\0';
      if (*p) ircd_strncpy(hostm,p, HOSTLEN);
    }

    /* Get the nick!user mask */
    if ((p = strchr(hoststr, '!'))) {
      *p++ = '\0';
      if (*p) ircd_strncpy(userm,p,USERLEN);
      if (*hoststr) ircd_strncpy(nickm,hoststr,NICKLEN);
    }
    else if (*hoststr) {
      /* Durz: We should only do the following *IF* the hoststr has not already been
       * copied into hostm (ie. neither ! or @ specified).. otherwise, when we do
       * /quote check *.barrysworld.com - we end up with targhost as: *!*.barryswo@*.barrysworld.com
       */
      ircd_strncpy(userm,hoststr,USERLEN);
    }
  }
 
  if (ipmask_parse(hostm, &cidr_check, &cidr_check_bits) != 0) {
    flags |= CHECK_CIDRMASK;
  }

  /* Copy formatted string into "targhost" buffer */
  ircd_snprintf(0, targhost, sizeof(targhost),  "%s!%s@%s", nickm, userm, hostm);

  targhost[sizeof(targhost) - 1] = '\0';

  /* Note: we have to exclude the last client struct as it is not a real client
   * structure, and therefore any attempt to access elements in it would cause
   * a segfault.
   */

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    /* Dont process if acptr is a unregistered client, a server or a ping */
    if (!IsRegistered(acptr) || IsServer(acptr))
      continue;

    if (IsMe(acptr))   /* Always the last acptr record */
      break;

    if(count >= 500) { /* sanity stuff */
      ircd_snprintf(0, outbuf, sizeof(outbuf), "More than %d results, truncating...", count);
      send_reply(sptr, RPL_DATASTR, outbuf);
      break;
    }

    /* Copy host info into buffer */
    curhost[0] = '\0';
    ircd_snprintf(0, curhost, sizeof(curhost), "%s!%s@%s", cli_name(acptr), cli_user(acptr)->realusername, cli_user(acptr)->realhost);

    if (flags & CHECK_CIDRMASK) {
      if (ipmask_check(&cli_ip(acptr), &cidr_check, cidr_check_bits) && !match(nickm, acptr->cli_name) 
            && (!match(userm, cli_user(acptr)->realusername) || !match(userm, cli_user(acptr)->username)))
        found = 1;
    }
    else {
      if(match((const char*)targhost,(const char*)curhost) == 0)
        found = 1;
      else {
        curhost[0] = '\0';
        ircd_snprintf(0, curhost, sizeof(curhost), "%s!%s@%s", acptr->cli_name, cli_user(acptr)->username, cli_user(acptr)->host);

        if(match((const char*)targhost,(const char*)curhost) == 0)
          found = 1;
      }
    }

    if (found == 1) {
      found = 0;  /* reset that so it doesn't get crazy go nuts */

      /* Show header if we've found at least 1 record */
      if (count == 0) {
        /* Output header */ 
        send_reply(sptr, RPL_DATASTR, " ");
        send_reply(sptr, RPL_CHKHEAD, "host", targhost);

        send_reply(sptr, RPL_DATASTR, " ");
        if (flags & CHECK_SHOWMORE)
          ircd_snprintf(0, outbuf, sizeof(outbuf), "No. %s  nick  user@host  [IP]  (usermodes)  :realname", (flags & CHECK_CLONES) ? "[clients]" : ""); 
        else 
          ircd_snprintf(0, outbuf, sizeof(outbuf),  "%s   %-*s%-*s%s", "No.", (NICKLEN + 2), "Nick",
                (USERLEN + 2), "User", "Host");
        send_reply(sptr, RPL_DATASTR, outbuf);
      }

      if (flags & CHECK_SHOWMORE) {
        /* show more information */
        umodes = umode_str(acptr, UMODE_AND_ACCOUNT_SHORT);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "%-4d  ", (count+1));
        if (flags & CHECK_CLONES)
          ircd_snprintf(0, outbuf, sizeof(outbuf), "%s[%+3u]    ", outbuf, IPcheck_nr(acptr));
        ircd_snprintf(0, outbuf, sizeof(outbuf), "%s%s  %s@%s  [%s]  (%s%s)  :%s", outbuf,
              acptr->cli_name,
              cli_user(acptr)->realusername, cli_user(acptr)->realhost,
              ircd_ntoa(&(cli_ip(acptr))),
              *umodes ? "+" : "<none>", umodes,
              (flags & CHECK_SHOWSERVER) ? cli_name(cli_user(acptr)->server) : cli_info(acptr));
      } else {
        /* default output */
        ircd_snprintf(0, outbuf, sizeof(outbuf), "%-4d  %-*s%-*s%s", (count+1), (NICKLEN + 2),
              acptr->cli_name, (USERLEN + 2), cli_user(acptr)->realusername, 
              (flags & CHECK_SHOWIPS) ? ircd_ntoa(&(cli_ip(acptr))) : cli_user(acptr)->realhost);
      }
      send_reply(sptr, RPL_DATASTR, outbuf);

      /* Show channel output (if applicable) - the 50 channel limit sanity check
       * is specifically to prevent coredumping when someone lamely tries to /check
       * Q or some other channel service...
       */
      if (flags & CHECK_CHECKCHAN) {
        if (cli_user(acptr)->joined > 0 && cli_user(acptr)->joined <= 50) {
          char chntext[BUFSIZE];
          int len = strlen("      on channels: ");
          int mlen = strlen(me.cli_name) + len + strlen(sptr->cli_name);
          *chntext = '\0';

          strcpy(chntext, "      on channels: ");
          for (lp = cli_user(acptr)->channel; lp; lp = lp->next_channel) {
            chptr = lp->channel;
            if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5) {
              send_reply(sptr, RPL_DATASTR, chntext);
              *chntext = '\0';
              strcpy(chntext, "      on channels: ");
              len = strlen(chntext);
            }
            if (IsDeaf(acptr))
              *(chntext + len++) = '-';
            if (!PubChannel(chptr))
              *(chntext + len++) = '*';
            if (IsZombie(lp))
              *(chntext + len++) = '!';
            if (IsChanOp(lp))
              *(chntext + len++) = '@';
            else if (HasVoice(lp))
              *(chntext + len++) = '+';
            else if (IsDelayedJoin(lp))
              *(chntext + len++) = '<';
            if (len)
              *(chntext + len) = '\0';

            strcpy(chntext + len, chptr->chname);
            len += strlen(chptr->chname);
            strcat(chntext + len, " ");
            len++;
          }
          if (chntext[0] != '\0')
            send_reply(sptr, RPL_DATASTR, chntext);

          send_reply(sptr, RPL_DATASTR, " ");
        }
      }
      count++;
    }
  }

  if (count > 0) {
    send_reply(sptr, RPL_DATASTR, " ");

    ircd_snprintf(0, outbuf, sizeof(outbuf), "Matching records found:: %d", count);
    send_reply(sptr, RPL_DATASTR, outbuf);

    send_reply(sptr, RPL_ENDOFCHECK, " ");
  }

  return count;
}
