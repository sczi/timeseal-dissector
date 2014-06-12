/*
   ettercap -- dissector fics -- TCP 23, 5000

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

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>


/* protos */

FUNC_DECODER(dissector_fics);
void fics_init(void);

static char *key="Timestamp (FICS) v1.0 - programmed by Henrik Gram.";

/* decodes messages mangled with timeseal */

static void decode_timeseal(char *s) {
    int n, l, offset;
    char *t;
    /* there might be multiple separate messages, but only need first */
    t = strchr(s, 0x0a) - 1;
    offset = (unsigned char)*t - 0x80;
    l = t - s;
    s[l] = 0;

    for (n = 0; n < l; n++)
        s[n] = ((s[n] + 32) ^ key[(n + offset) % 50]) & ~0x80;

#define SC(A,B) s[B]^=s[A]^=s[B],s[A]^=s[B]
    for (n = 0; n < l; n += 12)
		SC(n,n+11), SC(n+2,n+9), SC(n+4,n+7);

    /* cut off the timestamp */
    t = strchr(s, 0x18);
    if (t)
        *t = 0;
}

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init fics_init(void)
{
   dissect_add("fics", APP_LAYER_TCP, 23, dissector_fics);
   dissect_add("fics5000", APP_LAYER_TCP, 5000, dissector_fics);
}

FUNC_DECODER(dissector_fics)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct ec_session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;

   /* create an ident to retrieve the session */
   dissect_create_ident(&ident, PACKET, DISSECT_CODE(dissector_fics));

   /* is the message from the server or the client ? */
   if (FROM_SERVER("fics", PACKET) || FROM_SERVER("fics5000", PACKET)) {
      /* start the collecting process when "login:" is seen */
      if (session_get(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) {
         if (strstr(ptr, "login:")) {
            /* create the session to begin the collection */
            dissect_create_session(&s, PACKET, DISSECT_CODE(dissector_fics));
            session_put(s);
         }
      }
   } else {
      /* decode if using timeseal */
      if (*(end-1) == 0xa && *(end-2) >= 0x80)
         decode_timeseal(ptr);

      /* also print timeseal connection string to be
       * able to impersonate them */
      if (strstr(ptr, "TIMESTAMP"))
          DISSECT_MSG("%s\n", ptr);

      /* retrieve the session */
      if (session_get(&s, ident, DISSECT_IDENT_LEN) == ESUCCESS) {

         /* ignore telnet commands */
         if (ptr[0] == 0xff)
            return NULL;

         if (s->data == NULL) {
            /* the client is sending the username */
            s->data = strdup(ptr);
         } else {
            /* the client is sending the password */
            /* fill the structure */
            PACKET->DISSECTOR.user = strdup(s->data);
            PACKET->DISSECTOR.pass = strdup(ptr);

            /* delete carriage returns or newlines if present */
            if ( (ptr = strchr(PACKET->DISSECTOR.user, '\r')) != NULL )
               *ptr = '\0';
            if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
               *ptr = '\0';
            if ( (ptr = strchr(PACKET->DISSECTOR.user, '\n')) != NULL )
               *ptr = '\0';
            if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\n')) != NULL )
               *ptr = '\0';

            /* display the message */
            DISSECT_MSG("FICS : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                  ntohs(PACKET->L4.dst), 
                  PACKET->DISSECTOR.user,
                  PACKET->DISSECTOR.pass);

            /* delete the session to stop the collection */
            dissect_wipe_session(PACKET, DISSECT_CODE(dissector_fics));
            SAFE_FREE(ident);
         }
      }
   }

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab
