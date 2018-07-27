#!/usr/bin/python3
# -*- coding: utf-8 tab-width: 4 indent-tabs-mode: t -*-

import sys
from gi.repository import GLib
from gi.repository import gdhcp


def sig_term(signum):
    global main_loop
    main_loop.quit()
    return True
   

def handle_error(error):
    if error == gdhcp.CLIENT_ERROR_NONE:
        print("dhcp client ok")
    elif error == gdhcp.CLIENT_ERROR_INTERFACE_UNAVAILABLE:
        print("Interface unavailable")
    elif error == gdhcp.CLIENT_ERROR_INTERFACE_IN_USE:
        print("Interface in use")
    elif error == gdhcp.CLIENT_ERROR_INTERFACE_DOWN:
        print("Interface down")
    elif error == gdhcp.CLIENT_ERROR_NOMEM:
        print("No memory")
    elif error == gdhcp.CLIENT_ERROR_INVALID_INDEX:
        print("Invalid index")
    elif error == gdhcp.CLIENT_ERROR_INVALID_OPTION:
        print("Invalid option")


def no_lease_cb(dhcp_client):
    global main_loop
    print("No lease available")
    main_loop.quit()


def lease_available_cb(dhcp_client):
    print("Lease available")

    address = gdhcp.client_get_address(dhcp_client)
    print("address %s" % (address))
    if address is None:
        return

	option_value = gdhcp.client_get_option(dhcp_client, gdhcp.SUBNET);
	for (list = option_value; list; list = list->next)
		print("sub-mask %s", (char *) list->data);

	option_value = gdhcp.client_get_option(dhcp_client, gdhcp.DNS_SERVER);
	for (list = option_value; list; list = list->next)
		print("domain-name-servers %s", (char *) list->data);

	option_value = gdhcp.client_get_option(dhcp_client, gdhcp.DOMAIN_NAME);
	for (list = option_value; list; list = list->next)
		print("domain-name %s", (char *) list->data);

	option_value = gdhcp.client_get_option(dhcp_client, gdhcp.ROUTER);
	for (list = option_value; list; list = list->next)
		print("routers %s", (char *) list->data);

	option_value = gdhcp.client_get_option(dhcp_client, gdhcp.HOST_NAME);
	for (list = option_value; list; list = list->next)
		print("hostname %s", (char *) list->data);



if __name__ == "__main__":
    if len(sys.args) < 2:
        print("Usage: dhcp-test <interface index>")
        sys.exit(0)

    index = int(sys.args[1])

    print("Create DHCP client for interface %d" % (index))

    dhcp_client = gdhcp.client_new(gdhcp.IPV4, index, &error)
    if dhcp_client is None:
        handle_error(error)
        sys.exit(0)

    gdhcp.client_set_send(dhcp_client, gdhcp.HOST_NAME, "<hostname>")
    gdhcp.client_set_request(dhcp_client, gdhcp.HOST_NAME)
    gdhcp.client_set_request(dhcp_client, gdhcp.SUBNET)
    gdhcp.client_set_request(dhcp_client, gdhcp.DNS_SERVER)
    gdhcp.client_set_request(dhcp_client, gdhcp.DOMAIN_NAME)
    gdhcp.client_set_request(dhcp_client, gdhcp.NTP_SERVER)
    gdhcp.client_set_request(dhcp_client, gdhcp.ROUTER)

    gdhcp.client_register_event(dhcp_client, gdhcp.CLIENT_EVENT_LEASE_AVAILABLE, lease_available_cb, None)
    gdhcp.client_register_event(dhcp_client, gdhcp.CLIENT_EVENT_NO_LEASE, no_lease_cb, CLIENT_EVENT_NO_LEASE)

    main_loop = GLib.MainLoop()

    print("Start DHCP operation")

    timer = GLib.Timer()

    gdhcp.client_start(dhcp_client, None)

    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, sig_term, None)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, sig_term, None)

    main_loop.run()

    del timer
    gdhcp.client_unref(dhcp_client)

    sys.exit(0)
