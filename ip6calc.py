#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
    apt install python3-ipaddr
    or
    pip3 install ipaddr

	Given an IPv6 address or IPv6 network prefix, it shows all information
        about assignable addresses and address formats.
"""

import ipaddr #require external library
import argparse
import re
import sys
import os
import struct
import termios
import fcntl

WIDE_TERMINAL_SIZE = 154

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_terminal_width():
    try:
        fd = os.open(os.ctermid(), os.O_RDONLY)
    except:
        return None
    try:
        cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))
        os.close(fd)
        return cr[1]
    except:
        os.close(fd)
        return None
    

def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.RawDescriptionHelpFormatter,
        description = __doc__+("""
        Examples:\n
           Provide all informations about a single IPv6 address.
             # ip6calc.py 2001:41d0:8:17d8::1


           Provide all informations about an IPv6 network prefix and all
           contained addresses:
             # ip6calc.py 2001:41d0:8:17d8::1/64

           Addresses can be provided in binary form too:
             # ip6calc.py 0010000000000001:0100000111010000:"""
"""0000000000001000:0001011111011000:0000000000000000:0000000000000000:"""
"""0000000000000000:0000000000000001

             # ip6calc.py 0010000000000001:0100000111010000:"""
"""0000000000001000:0001011111011000:0000000000000000:0000000000000000:"""
"""0000000000000000:0000000000000001/64

           Note: Some output details may be missing if terminal width is
                 shorter than {termsize} characters.

    """.format(termsize = WIDE_TERMINAL_SIZE)))

    parser.add_argument("ip6addr", 
        help = ("IPv6 address or network prefix (compressed, exploded IPv6"
                " format or full binary format)"))

    parser.add_argument("--print-all-subnets-counts",
        help = ("When given a network prefix, it forces to compute the "
                "number of subnets available for each subnet size"),
        action="store_true")

    parser.add_argument("--count-deaggregation-into",
        help = ("When given a network prefix, it shows the number of IPv6 "
               "sub-prefixes of length N contained in the prefix provided"),
               type = int)

    parser.add_argument("--show-deaggregated-into",
        help = ("When given a network prefix, it shows all the IPv6 "
               "sub-prefixes of length N contained in the prefix provided"),
               type = int)

    parser.add_argument("--use-colors",
        help = ("Specify if force using or not using colors in the terminal "
                "output. By default colors are used, except when running "
                "a the program in a pipe"), default = sys.stdout.isatty(),
               type = bool)

    return parser.parse_args()

def get_binary_address(addr, is_network = False, use_colors = False):
    bin_str = bin(int(addr)).replace("0b","").zfill(128)
    out_str = ""
    if is_network and use_colors: out_str += bcolors.OKBLUE
    for i in ipaddr.xrange(128):
        if is_network and i == addr.prefixlen and use_colors:
            out_str += bcolors.ENDC
        if (i % 16 == 0) and i != 0:
            out_str += ":"
        out_str += bin_str[i]

    return out_str

def address_reprs(addr_obj, use_colors = False, wide_output = False):
    prefixlen_str = ""
    is_network = False
    if (type(addr_obj) == ipaddr.IPv6Network) and (addr_obj.prefixlen < 128):
        prefixlen_str = "/{0}".format(addr_obj.prefixlen)
        is_network = True
    out_str = (u"  (Compressed)  {compr}\n"
               u"    (Exploded)  {extend}\n"
               u"      (Binary)  {binary}{prefix}".format(
                compr = str(addr_obj),
                extend = (bcolors.OKGREEN + addr_obj.exploded + bcolors.ENDC),
                binary = get_binary_address(addr_obj, is_network, use_colors),
                prefix = prefixlen_str))
    if is_network and wide_output:
        if use_colors: out_str += bcolors.FAIL
        out_str += (u"\n                ↑          ↑                 ↑ "
                    u" ↑                ↑        ↑       ↑             "
                    u"                                     ↑           "
                    u"     ↑\n                /1         /12           "
                    u"   /29 /32              /48      /56     /64     "
                    u"                                           /112  "
                    u"           /128")
        if use_colors: out_str += bcolors.ENDC
    return out_str

def address_type_str(addr):
    if addr.is_link_local:
        return "link local"
    elif addr.is_loopback:
        return "loopback"
    elif addr.is_multicast:
        return "multicast"
    elif addr.is_private:
        return "private"
    elif addr.is_reserved:
        return "reserved"
    elif addr.is_site_local:
        return "site local"
    elif addr.is_unspecified:
        return "unspecified"
    else:
        return "global unicast"

def convert_from_binary(addr):
    # Note that the binary address my contain or not contain any separator
    # between groups.
    token = addr.split("/")
    bin_match = re.match("([01]{16})[^01]*([01]{16})[^01]*([01]{16})[^01]*"
                         "([01]{16})[^01]*([01]{16})[^01]*([01]{16})[^01]*"
                         "([01]{16})[^01]*([01]{16})", token[0])
    output_addr = ""
    for group in bin_match.groups():
        output_addr += hex(int(group, 2))[2:].zfill(4) + ":"
    # Remove final column
    return (output_addr[:-1] + "/" + token[1])

def print_available_subnets_of_prefix(addr_obj, n):
    print("   * {num} (2^{exp} or {num:.2g}) subnets /{length}".format(       
          num = 2**(n-addr_obj.prefixlen),                            
          exp = (n-addr_obj.prefixlen),
          length = n))

def get_mac_addr(addr):
    """ Take out MAC address bytes for the IPv6, and return the MAC
        address in a string format.
    """
    mac_bytes = []
    mac_bytes.append(int(((int(addr) >> 56) & 0xff) ^ 0x02))
    mac_bytes.append(int((int(addr) >> 48) & 0xff))
    mac_bytes.append(int((int(addr) >> 40) & 0xff))
    mac_bytes.append(int((int(addr) >> 16) & 0xff))
    mac_bytes.append(int((int(addr) >> 8) & 0xff))
    mac_bytes.append(int(int(addr) & 0xff))
    return ":".join([hex(x)[2:].zfill(2) for x in mac_bytes])


def print_addr_info(addr, show_all_subnet_sizes, deaggregate_to = False,
                    use_colors = False, wide_output = False,
                    count_deaggregation_into = False):
    """ Show all available information about an IPv6 prefix or address """
    is_network = False

    # Convert the address if provided in binary string form
    if len(addr) >= 128 and \
       re.match("([01]{16}[^01]*){7}[01]{16}(/[0-9]+)?", addr):
        addr = convert_from_binary(addr)

    # Check if the address is a network prefix or a single address
    if ("/" in addr) and (int(addr.split("/")[-1]) != 128):
        is_network = True
        addr_obj = ipaddr.IPNetwork(addr)
        # We immediately mask the address using the specified prefix length
        # in order to avoid showing non-existing bits
        addr_obj = addr_obj.masked()
    else:
        addr_obj = ipaddr.IPAddress(addr.split("/")[0])

    # This tool works only for IPv6 at the moment
    if addr_obj.version != 6: return

    print("Address:")
    print(address_reprs(addr_obj, use_colors, wide_output))

    print("Address type is: {color1}{addrtype}{color2}\n".format(
        addrtype = address_type_str(addr_obj),
        color1 = bcolors.WARNING if use_colors else "",
        color2 = bcolors.ENDC if use_colors else ""))

    # If this is not an IPv6 prefix and there is 0xfffe in a specific
    # position, then this is likely a SLAAC address autogenerated
    # from the host's MAC address.
    if not is_network and (((int(addr_obj) >> 24) & 0xffff) == 0xfffe):
        print("This address might have been autogenerated by an "
              "host with MAC address: {color1}{mac}{color2}".format(
              mac = get_mac_addr(addr_obj),
              color1 = bcolors.FAIL if use_colors else "",
              color2 = bcolors.ENDC if use_colors else ""))

    if is_network:
        reserved_addresses = 0
        print("Netmask:")
        print(address_reprs(addr_obj.netmask))

        print("First address assignable: ")
        print(address_reprs(addr_obj[0]))

        print("Last address assignable: ")
        print(address_reprs(addr_obj[-1]))       

        print("\nTotal number of addresses: "
              "{color1}{num} (2^{exp} or {num:.2g})"
              "{color2}\n".format(num = addr_obj.numhosts,
                  exp = 128-addr_obj.prefixlen,
                  color1 = bcolors.WARNING if use_colors else "",
                  color2 = bcolors.ENDC if use_colors else ""))
        print("\n")

        if (addr_obj.prefixlen <= 126):
            reserved_addresses += 1
            print("First address assignable (excluding "
                  "\"subnet-router anycast\" of RFC 2526):")
            print(address_reprs(addr_obj[0] + 1))

        if (addr_obj.prefixlen >= 64) and (addr_obj.prefixlen <= 128-8):
            reserved_addresses += 128
            print("Last address assignable (Excluding \"reserved\" addresses "
                  "of RFC 2526): ")
            print(address_reprs(addr_obj[-129]))

        if reserved_addresses > 0:
            print("Total number of addresses (Excluding \"reserved\" "
                  "addresses): {num} ({num:.2g})\n".format(
                  num = addr_obj.numhosts-reserved_addresses))

        if show_all_subnet_sizes:
            print("\nThis prefix can contain one of the following:")
            for n in range(addr_obj.prefixlen + 1, 128)[::-1]:
                print_available_subnets_of_prefix(addr_obj, n)
        elif count_deaggregation_into and \
             count_deaggregation_into > addr_obj.prefixlen:
            print("\nThis prefix can contain:")
            print_available_subnets_of_prefix(addr_obj,
                count_deaggregation_into)
        else:
            if addr_obj.prefixlen < 64:
                print("\nThis prefix can contain one of the following:")
                print_available_subnets_of_prefix(addr_obj, 64)
            if addr_obj.prefixlen < 56:
                print_available_subnets_of_prefix(addr_obj, 56)
            if addr_obj.prefixlen < 48:
                print_available_subnets_of_prefix(addr_obj, 48)
            if addr_obj.prefixlen < 32:
                print_available_subnets_of_prefix(addr_obj, 32)

        if deaggregate_to and deaggregate_to > addr_obj.prefixlen:
            print("\nList of /{deag_len} prefixes deaggregated from the "
                  "{orig_len} provided:".format(deag_len = deaggregate_to,
                  orig_len = addr_obj.prefixlen))
            for p in addr_obj.Subnet(deaggregate_to - addr_obj.prefixlen):
                print(p.exploded)
            

if __name__ == "__main__":
    args = parse_args()
    wide_terminal = (get_terminal_width() >= WIDE_TERMINAL_SIZE)
    if args.show_deaggregated_into:
        print_addr_info(args.ip6addr, args.print_all_subnets_counts,
                        args.show_deaggregated_into,
                        use_colors = args.use_colors,
                        wide_output = wide_terminal,
                        count_deaggregation_into =
                            args.count_deaggregation_into)
    else:
        print_addr_info(args.ip6addr, args.print_all_subnets_counts,
                        use_colors = args.use_colors,
                        wide_output = wide_terminal,
                        count_deaggregation_into =
                            args.count_deaggregation_into)

