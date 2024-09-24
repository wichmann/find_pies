#! /usr/bin/env python3
#
# find_pies
#
# find_pies searches for all devices inside a connected network filtered by a
# given MAC address.
#
# This tool was based on the Layer 2 network neighbourhood discovery tool by
# Benedikt Waldvogel. (https://github.com/bwaldvogel/neighbourhood)
#

import socket
import logging
from ipaddress import IPv4Network
from collections import namedtuple
from collections import defaultdict

import urwid
from getmac import get_mac_address
from multiping import multi_ping


# initialize logging only to log file
FORMAT = '%(asctime)s %(levelname)-5s %(message)s'
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('find_pies.log')
formatter = logging.Formatter(FORMAT)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler) 
logger.setLevel(logging.DEBUG)

# create class to handle Hosts found on the local network
Host = namedtuple('Host', 'hostname ip_address mac_address')

# set constants for scanning
TIMEOUT = 1
RENEW_RATE = 5
SCAN_TIMER = 4.0
FILTER_BY_MAC = True
MAC_ADDRESS = ('b8:27:eb', 'dc:a6:32') # OUIs for Raspberry Pi Foundation

# initialize global variables (sic!)
current_network = '192.168.1.0/24'
list_of_already_show_hosts = []
times_host_has_been_found = defaultdict(int)

# set color palette for different parts of the GUI
palette = [
    ('banner', 'black', 'light gray'),
    ('streak', 'black', 'dark red'),
    ('bg', 'black', 'dark blue'),
    ('highlight', 'black', 'yellow'),]


def scan_neighbors(net):
    logger.info('Pinging {}.'.format(net))
    list_of_hosts = list()
    addrs = [str(h) for h in IPv4Network(net).hosts()]
    responses, no_responses = multi_ping(addrs, timeout=TIMEOUT)
    for ip_address, r_time in responses.items():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except socket.herror:
            # failed to resolve
            pass
        # find MAC address for given IP
        mac_address = get_mac_address(ip=ip_address)
        if not mac_address:
            mac_address = '00:00:00:00:00:00'
        # append host to list
        list_of_hosts.append(Host(hostname, ip_address, mac_address))    
    # define parts of ip address as integer in a tuple to let Python sort them correctly
    list_of_hosts.sort(key=lambda x: tuple(int(part) for part in x.ip_address.split('.')))
    return list_of_hosts


def find_all_pies():
    list_of_hosts = scan_neighbors(current_network)
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
    network_address_edit = urwid.Edit('Network address: ')
    network_address_edit.set_edit_text(current_network)
    settings_pile = urwid.Pile([network_address_edit, ])
    settings = urwid.LineBox(settings_pile, title='Settings')
    # other widgets
    button = urwid.Button('Exit')
    pile = urwid.Pile([banner_text_map, div, settings, div, results, div, button])
    top = urwid.Filler(pile, valign='top')
    # connect events to funtions
    urwid.connect_signal(network_address_edit, 'change', on_network_address_change)
    urwid.connect_signal(button, 'click', on_exit_clicked)
    # start main loop
    loop = urwid.MainLoop(top, palette, unhandled_input=on_unhandled_input)
    loop.set_alarm_in(SCAN_TIMER, on_timer)
    loop.run()


if __name__ == '__main__':
    main_gui()
