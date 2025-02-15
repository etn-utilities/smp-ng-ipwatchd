/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2018 Jaroslav Imrich <jariq(at)jariq(dot)sk>
 *  
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

/** \file message.c
 * \brief Contains logic used for manipulating program messages
 */


#include "ipwatchd.h"


extern int debug_flag;
extern int syslog_flag;
extern int daemon_flag;


//! Handles output of messages generated by IPwatchD
/*!
 * \param type Type of message.
 * \param format Message to output in format similar to printf.
 */
void ipwd_message (IPWD_MSG_TYPE type, const char *format, ...)
{

	/* Handle debug mode first for efficiency */
	if ((type == IPWD_MSG_TYPE_DEBUG) && (!debug_flag))
	{
		return;
	}

	va_list arguments;
	char msg[IPWD_MSG_BUFSIZ];

	/* Put formatted message to msg buffer */
	va_start(arguments, format);
	vsnprintf(msg, IPWD_MSG_BUFSIZ, format, arguments);
	va_end(arguments);

	/* Every message is recorded by syslog no matter if process is daemonized or not */
	switch (type)
	{

		case IPWD_MSG_TYPE_INFO:
			syslog (LOG_INFO, "%s", msg);
			break;

		case IPWD_MSG_TYPE_ERROR:
			syslog (LOG_ERR, "%s", msg);
			break;

		case IPWD_MSG_TYPE_ALERT:
			syslog (LOG_ALERT, "%s", msg);
			break;

		case IPWD_MSG_TYPE_DEBUG:
			syslog (LOG_DEBUG, "%s", msg);
			break;

		default:
			syslog (LOG_ERR, "%s", msg);
			break;

	}

	/* Output message also to terminal if process is not daemonized */
	if (!daemon_flag)
	{
		switch (type)
		{

			case IPWD_MSG_TYPE_INFO:
				fprintf (stdout, "%s\n", msg);
				break;

			case IPWD_MSG_TYPE_ERROR:
				fprintf (stderr, "%s\n", msg);
				break;

			case IPWD_MSG_TYPE_ALERT:
				fprintf (stderr, "%s\n", msg);
				break;

			case IPWD_MSG_TYPE_DEBUG:
				fprintf (stdout, "%s\n", msg);
				break;

			default:
				fprintf (stderr, "%s\n", msg);
				break;

		}
	}

}
