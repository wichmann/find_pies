#! /usr/bin/env python
#
# find_pies
#
# find_pies searches for all devices inside a connected network filtered by a
# given MAC address.
#
# This tool is based on the Layer 2 network neighbourhood discovery tool by
# Benedikt Waldvogel. (https://github.com/bwaldvogel/neighbourhood)
#

from __future__ import absolute_import, division, print_function

import math
import errno
import socket
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
from operator import attrgetter
from collections import namedtuple
from collections import defaultdict

import urwid


logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.ERROR)
logger = logging.getLogger(__name__)


Host = namedtuple('Host', 'hostname ip_address mac_address')

TIMEOUT = 1
RENEW_RATE = 5
SCAN_TIMER = 2.0
FILTER_BY_MAC = True
MAC_ADDRESS = ('b8:27:eb', )  # OUI for Raspberry Pi Foundation

current_interface = 'enp0s31f6'
current_network = '192.168.10.0/24'
list_of_already_show_hosts = []
times_host_has_been_found = defaultdict(int)

palette = [
    ('banner', 'black', 'light gray'),
    ('streak', 'black', 'dark red'),
    ('bg', 'black', 'dark blue'),
    ('highlight', 'black', 'yellow'),]


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError('illegal netmask value', hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = '{}/{}'.format(network, netmask)
    if netmask < 16:
        logger.warn('{} is too big. Skipping.'.format(net))
        return None
    return net


def scan_neighbors(net, interface):
    logger.info('Arping {} on {}.'.format(net, interface))
    list_of_hosts = list()
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=TIMEOUT, verbose=False)
        for s, r in ans.res:
            hostname= ''
            mac_address = r.src
            ip_address= r.psrc
            try:
                hostname = socket.gethostbyaddr(r.psrc)
            except socket.herror:
                # failed to resolve
                pass
            #logger.info(str(r))
            list_of_hosts.append(Host(hostname, ip_address, mac_address))
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error('{}. Did you run as root?'.format(e.strerror))
        elif e.errno == 19:
            logger.error('{}. No such device found.'.format(e.strerror))
        else:
            raise
    # define parts of ip address as integer in a tuple to let Python sort them correctly
    list_of_hosts.sort(key=lambda x: tuple(int(part) for part in x.ip_address.split('.')))
    return list_of_hosts


def scan_all_interfaces():
    for network, netmask, _, interface, address in scapy.config.conf.route.routes:
        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue
        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue
        net = to_CIDR_notation(network, netmask)
        if interface != scapy.config.conf.iface:
            # see http://trac.secdev.org/scapy/ticket/537
            logger.warn('Skipping {} because scapy currently doesn\'t support arping on non-primary network interfaces'.format(net))
            continue
        if net:
            scan_neighbors(net, interface)


def find_all_pies():
    list_of_hosts = scan_neighbors(current_network, current_interface)
    for host in list_of_hosts:
        logger.debug('Found host: {}'.format(host))
    if FILTER_BY_MAC:
        result = [h for h in list_of_hosts if any([h.mac_address.startswith(m) for m in MAC_ADDRESS])]
    else:
        result = list_of_hosts
    return result


def on_unhandled_input(key):
    if key in ('q', 'Q'):
        raise urwid.ExitMainLoop()


def on_network_address_change(edit, new_edit_text):
    logger.debug('Setting new network address: ' + new_edit_text)
    current_network = new_edit_text


def on_interface_change(edit, new_edit_text):
    logger.debug('Setting new interface name: ' + new_edit_text)
    current_interface = new_edit_text


def on_exit_clicked(button):
    raise urwid.ExitMainLoop()


def on_timer(widget, user_data):
    infos = ['']
    list_of_hosts = find_all_pies()
    for h in list_of_hosts:
        if isinstance(h, list):
            logger.warn('Found list were a Host instance should be: ' + str(h))
            continue
        # host has been found at last search
        times_host_has_been_found[h] += 1
        if h not in list_of_already_show_hosts:
            # found new host at last search
            list_of_already_show_hosts.append(h)
    for h in list_of_already_show_hosts:
        if h in list_of_hosts:
            if isinstance(h, list):
                logger.warn('Found list were a Host instance should be: ' + str(h))
                continue
            # host has been found at last search
            attr = 'highlight' if times_host_has_been_found[h] < RENEW_RATE else ''
            infos.append((attr, h.ip_address + ' '*(18-len(h.ip_address)) + h.mac_address + '    ' + h.hostname + '\n'))
        else:
            # host has been found before but is no longer available
            times_host_has_been_found[h] = 0
            infos.append(('', '    \n'))
    result_text.set_text(infos)
    loop.set_alarm_in(SCAN_TIMER, on_timer)


def main_gui():
    global loop
    global result_text
    div = urwid.Divider()
    banner_text = urwid.Text(('banner', u'Find Pies'), align='center')
    banner_text_map = urwid.AttrMap(banner_text, 'streak')
    result_text = urwid.Text('', align='left')
    #result_text.set_text(u'\n' * 100)
    results = urwid.LineBox(result_text, title='Found devices')
    # setting widgets
    network_address_edit = urwid.Edit(u"Network address: ")
    network_address_edit.set_edit_text(current_network)
    interface_edit = urwid.Edit(u"Interface name: ")
    interface_edit.set_edit_text(current_interface)
    settings_pile = urwid.Pile([network_address_edit, div, interface_edit])
    settings = urwid.LineBox(settings_pile, title='Settings')
    # other widgets
    button = urwid.Button(u'Exit')
    pile = urwid.Pile([banner_text_map, div, settings, div, results, div, button])
    top = urwid.Filler(pile, valign='top')
    # connect events to funtions
    urwid.connect_signal(network_address_edit, 'change', on_network_address_change)
    urwid.connect_signal(interface_edit, 'change', on_interface_change)
    urwid.connect_signal(button, 'click', on_exit_clicked)
    # start main loop
    loop = urwid.MainLoop(top, palette, unhandled_input=on_unhandled_input)
    loop.set_alarm_in(SCAN_TIMER, on_timer)
    loop.run()


if __name__ == '__main__':
    main_gui()
