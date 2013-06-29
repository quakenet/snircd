/*
 * IRC - Internet Relay Chat, ircd/m_mode.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 *
 * $Id: m_mode.c 1818 2007-07-14 02:40:01Z isomer $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "numnicks.h"

#include <stdlib.h>

/**
 * ms_remotemode - remotemode server message handler
 *
 * parv[0]  = sender prefix
 * parv[1]  = target user numeric
 * parv[2+] = mode and arguments
 *
 */
int ms_remotemode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *target;
  struct Client *acptr;
  struct Flags setflags;
  struct Membership *chan;

  char** p;
  char*  m;
  char *hostmask;
  char *user = NULL;
  char *host = NULL;
  char hiddenhost[USERLEN + HOSTLEN + 2];
  int what = MODE_ADD;
  int do_host_hiding = 0;
  int do_set_host = 0;

  /* not from a server */
  if (!IsServer(sptr))
    return protocol_violation(cptr, "Received REMOTEMODE from user %C", sptr);

  /* check paramaters */
  if (parc < 3)
    return protocol_violation(cptr, "Received too few parameters for REMOTEMODE from %C (got %d - need at least 3)", parc, sptr);

  target = parv[1];

  /* find user */
  if(!(acptr = findNUser(target)))
    return 0;

  /* TODO: how to pass along all params in an easy way? */
  /* not for my user, pass it along */
  if (!MyConnect(acptr)) {
    sendcmdto_one(sptr, CMD_REMOTEMODE, acptr, "%C %s %s %s %s %s %s %s %s %s %s %s %s %s", acptr,
      parv[2],
      parc >  3 ?  parv[3] : "",
      parc >  4 ?  parv[4] : "", 
      parc >  5 ?  parv[5] : "",
      parc >  6 ?  parv[6] : "",
      parc >  7 ?  parv[7] : "",
      parc >  8 ?  parv[8] : "",
      parc >  9 ?  parv[9] : "",
      parc > 10 ? parv[10] : "",
      parc > 11 ? parv[11] : "",
      parc > 12 ? parv[12] : "",
      parc > 13 ? parv[13] : "",
      parc > 14 ? parv[14] : "");
    return 0;
  }

  /* backup flags */
  setflags = cli_flags(acptr);

  /* parse mode change string(s) */
  for (p = &parv[2]; *p && p<&parv[parc]; p++) {  /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
        case '+':
          what = MODE_ADD;
          break;
        case '-':
          what = MODE_DEL;
          break;
        case 'w':
          if (what == MODE_ADD)
            SetWallops(acptr);
          else
            ClearWallops(acptr);
          break;
        case 'i':
          if (what == MODE_ADD)
            SetInvisible(acptr);
          else
            ClearInvisible(acptr);
          break;
        case 'd':
          if (what == MODE_ADD)
            SetDeaf(acptr);
          else
            ClearDeaf(acptr);
          break;
        case 'n':
          if (what == MODE_ADD)
            SetNoChan(acptr);
          else
            ClearNoChan(acptr);
          break;
        case 'I':
          if (what == MODE_ADD)
            SetNoIdle(acptr);
          else
            ClearNoIdle(acptr);
          break;
        case 'R':
          if (what == MODE_ADD)
            SetAccountOnly(acptr);
          else
            ClearAccountOnly(acptr);
          break;
        case 'x':
          if (what == MODE_ADD)
            do_host_hiding = 1;
          break;
        case 'h':
          if (what == MODE_ADD) {
            if (*(p + 1) && is_hostmask(*(p + 1))) {
              do_set_host = 1;
              hostmask = *++p;
            } else {
              if (!*(p+1))
                protocol_violation(sptr, "Received REMOTEMODE +h without host parameter for user %C", acptr);
              else {
                protocol_violation(sptr, "Received REMOTEMODE +h with invalid host parameter %s for user %C", *(p+1), acptr);
                p++; /* Swallow the arg anyway */
              }
            }
          } else { /* MODE_DEL */
            do_set_host = 1;
            hostmask = NULL;
          }
          break;

        default:
          protocol_violation(sptr, "Received REMOTEMODE %c%c unknown user mode flag or disallowed to set remotely for user %C",
            what == MODE_ADD ? '+' : '-', *m, acptr);
          break;
      }
    }
  }

  /* do host hiding for +x */
  if (!FlagHas(&setflags, FLAG_HIDDENHOST) && do_host_hiding)
    hide_hostmask(acptr, FLAG_HIDDENHOST);

  /* sanity checks for -h */
  if (do_set_host && !hostmask) {
    /* user has no sethost or has no account
     *
     * user has +h - their host is hidden, do not remove it
     *   unless the user has an account set
     *     we should not out of the blue expose the real host
     */
    if (!IsSetHost(acptr) || !IsAccount(acptr))
      do_set_host = 0;

    /* user not +x and not allowed to set it */
    else if (!IsHiddenHost(acptr) && !feature_bool(FEAT_HOST_HIDING))
      do_set_host = 0;

    /* set +x */
    else 
      SetHiddenHost(acptr);
  }

  /* sanity checks for +h */
  if (do_set_host && hostmask) {
    if ((host = strrchr(hostmask, '@'))) {
      *host++ = '\0';
      user = hostmask;
    }
    else
      host = hostmask;

    /* check if new sethost is different from before */
    if (IsSetHost(acptr) && 
       (!user || strcmp(cli_user(acptr)->username, user) == 0) &&
        strcmp(cli_user(acptr)->host, host) == 0)
      do_set_host = 0;
  }

  /* do host hiding for +h/-h */
  if (do_set_host) {

    /* quit user from channel */
    sendcmdto_common_channels_butone(acptr, CMD_QUIT, acptr, ":Host change");

    /* set +h */
    if (host) {
      SetSetHost(acptr);
      /* clear +h in old flags so +h is sent out again with new sethost param */
      FlagClr(&setflags, FLAG_SETHOST);
      if (user)
        ircd_strncpy(cli_user(acptr)->username, user, USERLEN);
      ircd_strncpy(cli_user(acptr)->host, host, HOSTLEN);

    /* set -h */
    } else {
      ClearSetHost(acptr);
      ircd_strncpy(cli_user(acptr)->username, cli_user(acptr)->realusername, USERLEN);
      /* user is +rx - need to restore +x host */
      if (HasHiddenHost(acptr)) 
        ircd_snprintf(0, cli_user(acptr)->host, HOSTLEN, "%s.%s",
          cli_user(acptr)->account, feature_str(FEAT_HIDDEN_HOST));
      else
        ircd_strncpy(cli_user(acptr)->host, cli_user(acptr)->realhost, HOSTLEN);
    }

    /* inform user of hidden host */
    ircd_snprintf(0, hiddenhost, HOSTLEN + USERLEN + 2, "%s@%s",
      cli_user(acptr)->username, cli_user(acptr)->host);
    send_reply(acptr, RPL_HOSTHIDDEN, hiddenhost);

    /*
     * Go through all channels the client was on, rejoin him
     * and set the modes, if any
     */
    for (chan = cli_user(acptr)->channel; chan; chan = chan->next_channel) {
      /* Invalidate bans against the user so we check them again */
      ClearBanValid(chan);
      if (IsZombie(chan))
        continue;
      /* If this channel has delayed joins and the user has no modes, just set
       * the delayed join flag rather than showing the join, even if the user
       * was visible before */
      if (!IsChanOp(chan) && !HasVoice(chan)
          && (chan->channel->mode.mode & MODE_DELJOINS)) {
        SetDelayedJoin(chan);
      } else {
        sendcmdto_channel_butserv_butone(acptr, CMD_JOIN, chan->channel, acptr, 0,
          "%H", chan->channel);
      }
      if (IsChanOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, acptr, 0,
          "%H +ov %C %C", chan->channel, acptr, acptr);
      } else if (IsChanOp(chan) || HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, acptr, 0,
          "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : 'v', acptr);
      }
    }
  }

  /* adjust count for invisible/visible users */
  if (FlagHas(&setflags, FLAG_INVISIBLE) && !IsInvisible(acptr)) {
    assert(UserStats.inv_clients > 0);
    --UserStats.inv_clients;
  }
  if (!FlagHas(&setflags, FLAG_INVISIBLE) && IsInvisible(acptr)) {
    ++UserStats.inv_clients;
  }
  assert(UserStats.inv_clients <= UserStats.clients + UserStats.unknowns);

  /* send out the mode */
  send_umode_out(acptr, acptr, &setflags, 0);

  return 0;
}
