/*
 * IRC - Internet Relay Chat, ircd/m_sethost.c
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
 * $Id: asuka-sethost.patch,v 1.27 2005/02/13 17:28:11 froo Exp $
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

#include "client.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_features.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"
#include "numnicks.h"

#include "channel.h"
#include "msg.h"

#include <assert.h>
#include <stdlib.h>

/*
 * m_sethost - generic message handler
 *
 * mimic old lain syntax:
 *
 * (Oper) /SETHOST ident host.cc [quit-message]
 * (User) /SETHOST host.cc password
 * (Both) /SETHOST undo
 *
 * check for undo, prepend parv w. <nick> -h or +h
 */
int m_sethost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char hostmask[USERLEN + HOSTLEN + 2];
  char curhostmask[USERLEN + HOSTLEN + 2];

  struct Flags setflags;

  /* Back up the flags first */
  setflags = cli_flags(sptr);

  if (parc < 2)
    return need_more_params(sptr, "SETHOST");

  if (0 == ircd_strcmp("undo", parv[1])) {
    set_hostmask(sptr, NULL, NULL);
  } else {
    if (parc<3)
      return need_more_params(sptr, "SETHOST");
    if (IsAnOper(sptr)) {
      ircd_snprintf(0, hostmask, USERLEN + HOSTLEN + 2, "%s@%s", parv[1], parv[2]);
      if (!is_hostmask(hostmask)) {
	send_reply(sptr, ERR_BADHOSTMASK, hostmask);
	return 0;
      }
      if (IsSetHost(sptr) || IsAccount(sptr)) {
        ircd_snprintf(0, curhostmask, USERLEN + HOSTLEN + 2, "%s@%s", sptr->cli_user->username, sptr->cli_user->host);
        if (0 == strcmp(hostmask, curhostmask)) {
          send_reply(cptr, RPL_HOSTHIDDEN, curhostmask);
          return 0; 
        }
      }
      if (set_hostmask(sptr, hostmask, NULL))
      	FlagClr(&setflags, FLAG_SETHOST);
    } else {
      if (!is_hostmask(parv[1])) {
	send_reply(sptr, ERR_BADHOSTMASK, parv[1]);
	return 0;
      }
      if (IsSetHost(sptr) || IsAccount(sptr)) {
        if (0 == strcmp(parv[1], sptr->cli_user->host)) {
          send_reply(cptr, RPL_HOSTHIDDEN, parv[1]);
          return 0;
        }
      }
      if (set_hostmask(sptr, parv[1], parv[2]))
        FlagClr(&setflags, FLAG_SETHOST);
    }
  }  

  send_umode_out(cptr, sptr, &setflags, 0);
  return 0;
}


/*
 * ms_sethost - sethost server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target user numeric
 * parv[2] = target user's new ident
 * parv[3] = target user's new host 
 */
int ms_sethost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *target;
  char hostmask[USERLEN + HOSTLEN + 2];
  struct Membership *chan;

  if (parc < 4)
    return need_more_params(sptr, "SETHOST");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "SETHOST from non-server %s",
                              cli_name(sptr));

  /* Locate our target user; ignore the message if we can't */
  if(!(target = findNUser(parv[1])))
    return 0;

  /* Fake host assignments must be from services */
  if (!find_conf_byhost(cli_confs(sptr), cli_name(sptr), CONF_UWORLD))
    return protocol_violation(cptr, "Non-U:lined server %s set fake host on user %s", cli_name(sptr), cli_name(target));

  if (IsSetHost(target) || IsAccount(target)) { 
    if ((0 == strcmp(parv[2], target->cli_user->username)) && (0 == strcmp(parv[3], target->cli_user->host))) 
      return 0;
  }

  ircd_snprintf(0, hostmask, USERLEN + HOSTLEN + 2, "%s@%s", parv[2], parv[3]);
  if (!is_hostmask(hostmask))
    return protocol_violation(cptr, "Bad Host mask %s for user %s", hostmask, cli_name(target));

  sendcmdto_common_channels_butone(target, CMD_QUIT, target, ":Host change");

  /* Assign and propagate the fakehost */
  SetSetHost(target);
  ircd_strncpy(cli_user(target)->username, parv[2], USERLEN);
  ircd_strncpy(cli_user(target)->host, parv[3], HOSTLEN);
  
  if (MyConnect(target)) {
    send_reply(target, RPL_HOSTHIDDEN, hostmask);
  }

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(target)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan))
      continue;
    /* If this channel has delayed joins and the user has no modes, just set
     * the delayed join flag rather than showing the join, even if the user
     * was visible before */
    if (!IsChanOp(chan) && !HasVoice(chan)
        && (chan->channel->mode.mode & MODE_DELJOINS)) {
      SetDelayedJoin(chan);
    } else {
      sendcmdto_channel_butserv_butone(target, CMD_JOIN, chan->channel, target, 0,
        "%H", chan->channel);
    }
    if (IsChanOp(chan) && HasVoice(chan)) {
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, target, 0,
        "%H +ov %C %C", chan->channel, target, target);
    } else if (IsChanOp(chan) || HasVoice(chan)) {
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, target, 0,
        "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : 'v', target);
    }
  }


  sendcmdto_serv_butone(sptr, CMD_SETHOST, cptr, "%C %s %s", target,
                        target->cli_user->username, target->cli_user->host);
 return 0;
}

