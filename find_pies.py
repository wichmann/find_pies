#! /usr/bin/env python3

"""
find_pies

find_pies searches for all devices inside a connected network filtered by a given MAC address.

This tool was based on the Layer 2 network neighbourhood discovery tool by Benedikt Waldvogel.
(https://github.com/bwaldvogel/neighbourhood)
"""

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
# OUIs for Raspberry Pi Foundation
MAC_ADDRESS = ('d8:3a:dd', 'b8:27:eb', 'dc:a6:32', 'e4:5f:01', '2c:cf:67')

# initialize global variables (sic!)
CURRENT_NETWORK = '192.168.10.0/24'
list_of_already_show_hosts = []
times_host_has_been_found = defaultdict(int)

# set color palette for different parts of the GUI
palette = [
    ('banner', 'black', 'light gray'),
    ('streak', 'black', 'dark red'),
    ('bg', 'black', 'dark blue'),
    ('highlight', 'black', 'yellow'),]


def scan_neighbors(net):
    """Scans given network and returns a list of found hosts."""
    logger.info(f'Pinging {net}.')
    list_of_hosts = []
    addrs = [str(h) for h in IPv4Network(net).hosts()]
    responses, _ = multi_ping(addrs, timeout=TIMEOUT)
    for ip_address, _ in responses.items():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except socket.herror:
            # failed to resolve
            hostname = ''
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
    """Filters a list of hosts by MAC address."""
    list_of_hosts = scan_neighbors(CURRENT_NETWORK)
    for host in list_of_hosts:
        logger.debug(f'Found host: {host}')
    if FILTER_BY_MAC:
        result = [h for h in list_of_hosts if any(h.mac_address.startswith(m) for m in MAC_ADDRESS)]
    else:
        result = list_of_hosts
    return result


def on_unhandled_input(key):
    """Handles key inputs in the TUI."""
    if key in ('q', 'Q'):
        raise urwid.ExitMainLoop()


def on_network_address_change(edit, new_edit_text):
    """Handles a change of the network address in the TUI and updates global variable."""
    logger.debug(f'Setting new network address: {new_edit_text}')
    global CURRENT_NETWORK
    CURRENT_NETWORK = new_edit_text


def on_exit_clicked(button):
    """Handles a click on the exit button."""
    raise urwid.ExitMainLoop()


def on_timer(loop, result_text):
    """Updates list in TUI by searching for all Raspberry Pi."""
    infos = ['']
    list_of_hosts = find_all_pies()
    for h in list_of_hosts:
        if isinstance(h, list):
            logger.warning(f'Found list were a Host instance should be: {h}')
            continue
        # host has been found at last search
        times_host_has_been_found[h] += 1
        if h not in list_of_already_show_hosts:
            # found new host at last search
            list_of_already_show_hosts.append(h)
    for h in list_of_already_show_hosts:
        if h in list_of_hosts:
            if isinstance(h, list):
                logger.warning(f'Found list were a Host instance should be: {h}')
                continue
            # host has been found at last search
            attr = 'highlight' if times_host_has_been_found[h] < RENEW_RATE else ''
            host_string = h.ip_address + ' '*(18-len(h.ip_address)) + h.mac_address + '    ' + h.hostname + '\n'
            infos.append((attr, host_string))
        else:
            # host has been found before but is no longer available
            times_host_has_been_found[h] = 0
            infos.append(('', '    \n'))
    result_text.set_text(infos)
    loop.set_alarm_in(SCAN_TIMER, lambda widget, user_data: on_timer(loop, result_text))


def main_gui():
    """Builds main dialog for TUI."""
    div = urwid.Divider()
    banner_text = urwid.Text(('banner', 'Find Pies'), align='center')
    banner_text_map = urwid.AttrMap(banner_text, 'streak')
    result_text = urwid.Text('', align='left')
    # result_text.set_text(u'\n' * 100)
    results = urwid.LineBox(result_text, title='Found devices')
    # setting widgets
    network_address_edit = urwid.Edit('Network address: ')
    network_address_edit.set_edit_text(CURRENT_NETWORK)
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
    loop.set_alarm_in(SCAN_TIMER, lambda widget, user_data: on_timer(loop, result_text))
    loop.run()


if __name__ == '__main__':
    main_gui()
