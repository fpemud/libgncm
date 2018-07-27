/* build with:
 *   gcc `pkg-config --cflags --libs gdhcp-1.0 gobject-2.0` dhcp-test.c -o dhcp-test
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <linux/if_arp.h>

#include <gdhcp.h>

static GTimer *timer;

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void print_elapsed(void)
{
	gdouble elapsed;

	elapsed = g_timer_elapsed(timer, NULL);

	printf("elapsed: %f seconds\n", elapsed);
}

static void handle_error(GError *error)
{
	printf("%s\n", error->message);
}

static void no_lease_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	print_elapsed();

	printf("No lease available\n");

	g_main_loop_quit(main_loop);
}

static void lease_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	GList *list, *option_value = NULL;
	char *address;

	print_elapsed();

	printf("Lease available\n");

	address = gdhcp_client_get_address(dhcp_client);
	printf("address %s\n", address);
	if (!address)
		return;

	option_value = gdhcp_client_get_option(dhcp_client, GDHCP_SUBNET);
	for (list = option_value; list; list = list->next)
		printf("sub-mask %s\n", (char *) list->data);

	option_value = gdhcp_client_get_option(dhcp_client, GDHCP_DNS_SERVER);
	for (list = option_value; list; list = list->next)
		printf("domain-name-servers %s\n", (char *) list->data);

	option_value = gdhcp_client_get_option(dhcp_client, GDHCP_DOMAIN_NAME);
	for (list = option_value; list; list = list->next)
		printf("domain-name %s\n", (char *) list->data);

	option_value = gdhcp_client_get_option(dhcp_client, GDHCP_ROUTER);
	for (list = option_value; list; list = list->next)
		printf("routers %s\n", (char *) list->data);

	option_value = gdhcp_client_get_option(dhcp_client, GDHCP_HOST_NAME);
	for (list = option_value; list; list = list->next)
		printf("hostname %s\n", (char *) list->data);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	GError *error = NULL;
	GDHCPClient *dhcp_client;
	int index;

	if (argc < 2) {
		printf("Usage: dhcp-test <interface index>\n");
		exit(0);
	}

	index = atoi(argv[1]);

	printf("Create DHCP client for interface %d\n", index);

	dhcp_client = gdhcp_client_new(G_DHCP_IPV4, index, &error);
	if (!dhcp_client) {
		handle_error(error);
		exit(0);
	}

	gdhcp_client_set_send(dhcp_client, GDHCP_HOST_NAME, "<hostname>", NULL);

	gdhcp_client_set_request(dhcp_client, GDHCP_HOST_NAME);
	gdhcp_client_set_request(dhcp_client, GDHCP_SUBNET);
	gdhcp_client_set_request(dhcp_client, GDHCP_DNS_SERVER);
	gdhcp_client_set_request(dhcp_client, GDHCP_DOMAIN_NAME);
	gdhcp_client_set_request(dhcp_client, GDHCP_NTP_SERVER);
	gdhcp_client_set_request(dhcp_client, GDHCP_ROUTER);

	g_signal_connect(dhcp_client,
					 "lease-available",
					 G_CALLBACK (lease_available_cb),
					 NULL);

	g_signal_connect(dhcp_client,
					 "no-lease",
					 G_CALLBACK (no_lease_cb),
					 NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	printf("Start DHCP operation\n");

	timer = g_timer_new();

	gdhcp_client_start(dhcp_client, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	g_timer_destroy(timer);

	g_object_unref(dhcp_client);

	g_main_loop_unref(main_loop);

	return 0;
}
