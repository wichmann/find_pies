# find_pies

find_pies searches for all devices inside a connected network filtered by a
given MAC address.

This tool was originally based on the Layer 2 network neighbourhood discovery
tool by Benedikt Waldvogel. [1]


## Usage

find_pies has to be executed with root privileges:

    sudo ./find_pies.py


## Dependencies

find_pies runs only under Python 3 and uses the following libraries:

* [multiping][2] for networking functions like ICMP ping requests
* [urwid][3] for console widgets


## Sources

[1]: https://github.com/bwaldvogel/neighbourhood
[2]: https://github.com/romana/multi-ping
[3]: http://urwid.org/
