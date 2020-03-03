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

/** \file devinfo.c
 * \brief Contains logic used for acquiring information about network devices
 */

#include "ipwatchd.h"

extern IPWD_S_CONFIG config;
extern IPWD_S_DEVS devices;


const IPWD_S_DEV* ipwd_fill_device(const pcap_if_t *pDev, IPWD_PROTECTION_MODE mode)
{
	const IPWD_S_DEV *pResult = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	int sock = -1;
	pcap_t *h_pcap = NULL;
	struct ifreq ifr;

	if (pDev->addresses == NULL)
	{
		ipwd_message(IPWD_MSG_TYPE_DEBUG, "Device \"%s\" has no address", pDev->name);
		goto clean_up;
	}

	/* Check if device is valid ethernet device */
	h_pcap = pcap_open_live(pDev->name, BUFSIZ, 0, 0, errbuf);
	if (h_pcap == NULL)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "IPwatchD is unable to work with device \"%s\"", pDev->name);
		goto clean_up;
	}

	if (pcap_datalink(h_pcap) != DLT_EN10MB)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "Device \"%s\" is not valid ethernet device", pDev->name);
		goto clean_up;
	}
	pcap_close(h_pcap);
	h_pcap = NULL;

	

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "Could not open socket");
		goto clean_up;
	}

	strncpy(ifr.ifr_name, pDev->name, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = 0;
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "ioctl");
		goto clean_up;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "not ethernet interface");
		goto clean_up;
	}

	const char *p_dev_mac = NULL;
	if ((p_dev_mac = ether_ntoa((const struct ether_addr *)&ifr.ifr_hwaddr.sa_data[0])) == NULL)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "Could not convert IP address of the device \"%s\"", pDev->name);
		goto clean_up;
	}

	/* Put read values into devices structure */
	if ((devices.dev = (IPWD_S_DEV *)realloc(devices.dev, (devices.devnum + 1) * sizeof(IPWD_S_DEV))) == NULL)
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to resize devices structure");
		goto clean_up;
	}
	
	strncpy(devices.dev[devices.devnum].mac, p_dev_mac, sizeof(devices.dev[devices.devnum].mac));
	ifr.ifr_name[sizeof(devices.dev[devices.devnum].mac) - 1] = 0;

	memset(devices.dev[devices.devnum].device, '\0', IPWD_MAX_DEVICE_NAME_LEN);
	strncpy(devices.dev[devices.devnum].device, pDev->name, IPWD_MAX_DEVICE_NAME_LEN - 1);
	devices.dev[devices.devnum].mode = mode;

	/* Set time of last conflict */
	devices.dev[devices.devnum].time.tv_sec = 0;
	devices.dev[devices.devnum].time.tv_usec = 0;
	devices.dev[devices.devnum].addresses = NULL;
	for (const pcap_addr_t *pAddr = pDev->addresses; pAddr != NULL; pAddr = pAddr->next)
	{
		if (pAddr->addr->sa_family != AF_INET)
			continue;

		IPWD_S_ADDR *address = malloc(sizeof(IPWD_S_ADDR));
		memset(address, 0, sizeof(IPWD_S_ADDR));

		const char *strIP;
		struct in_addr sin_addr = ((struct sockaddr_in *)pAddr->addr)->sin_addr;
		if ((strIP = inet_ntoa(sin_addr)) == NULL)
		{
			ipwd_message(IPWD_MSG_TYPE_ERROR, "Could not convert IP address of the device \"%s\"", pDev->name);
			continue;
		}

		address->ip = strdup(strIP);
		address->next = devices.dev[devices.devnum].addresses;
		devices.dev[devices.devnum].addresses = address;

		ipwd_message(IPWD_MSG_TYPE_DEBUG, "Found device %s - %s", devices.dev[devices.devnum].device, strIP);
	}
	pResult = &devices.dev[devices.devnum];
	devices.devnum = devices.devnum + 1;

clean_up:
	if (sock != -1)
		close(sock);

	if (h_pcap != NULL)
	{
		pcap_close(h_pcap);
		h_pcap = NULL;
	}

	return pResult;
}


//! Gets list of available network interfaces and fills devices structure with acquired information
/*!
 * Based on example from: http://www.doctort.org/adam/nerd-notes/enumerating-network-interfaces-on-linux.html
 * See netdevice(7) manual page for more information.
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_fill_devices()
{
	int res = IPWD_RV_ERROR;	
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_if_t *pAllDevs = NULL;

	/* Verify that devices structure is empty and configuration mode is automatic */
	if ((devices.dev != NULL) || (devices.devnum != 0))
	{
		ipwd_message(IPWD_MSG_TYPE_ERROR, "Cannot proceed with automatic configuration. Please check that configuration file does not contain iface variables");
		return IPWD_RV_ERROR;
	}

	if (pcap_findalldevs(&pAllDevs, errbuf))
		goto clean_up;

	for (const pcap_if_t *pDev = pAllDevs; pDev != NULL; pDev = pDev->next)
	{
		if (pDev->flags & PCAP_IF_LOOPBACK)
		{
			ipwd_message(IPWD_MSG_TYPE_DEBUG, "Skipping loopback device \"%s\"", pDev->name);
			continue;
		}

		ipwd_fill_device(pDev, IPWD_PROTECTION_MODE_PASSIVE);
	}
	res = IPWD_RV_SUCCESS;

clean_up:
	if (pAllDevs != NULL)
		pcap_freealldevs(pAllDevs);

	return res;
}
