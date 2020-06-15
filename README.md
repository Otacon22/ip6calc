# (Otacon22/ip6calc) Python3 Bugfix by Gabriel Padilha
IPv6 version of "ipcalc" program.
It is useful for doing countings of IPv6 addresses, subnets, available addresses, subnets slices, etc..

# Dependencies

* Python ipaddr module

# Examples

Information about a single IPv6 address

	# ./ip6calc.py 2001:0000:0000:0000:0202:c2ff:fe1e:1918
	Address:
	  (Compressed)  2001::202:c2ff:fe1e:1918
	    (Exploded)  2001:0000:0000:0000:0202:c2ff:fe1e:1918
	      (Binary)  0010000000000001:0000000000000000:0000000000000000:0000000000000000:0000001000000010:1100001011111111:1111111000011110:0001100100011000

	Address type is: global unicast

	This address might have been autogenerated by an host with MAC address: 00:02:c2:1e:19:18


Example information about an IPv6 /50 prefix:

	# ./ip6calc.py 2001:0000:fedc:8000::/50
	Address:
	  (Compressed)  2001:0:fedc:8000::/50
	    (Exploded)  2001:0000:fedc:8000:0000:0000:0000:0000/50
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1000000000000000:0000000000000000:0000000000000000:0000000000000000:0000000000000000/50

	Address type is: global unicast

	Netmask:
	  (Compressed)  ffff:ffff:ffff:c000::
	    (Exploded)  ffff:ffff:ffff:c000:0000:0000:0000:0000
	      (Binary)  1111111111111111:1111111111111111:1111111111111111:1100000000000000:0000000000000000:0000000000000000:0000000000000000:0000000000000000

	First address assignable: 
	  (Compressed)  2001:0:fedc:8000::
	    (Exploded)  2001:0000:fedc:8000:0000:0000:0000:0000
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1000000000000000:0000000000000000:0000000000000000:0000000000000000:0000000000000000

	Last address assignable: 
	  (Compressed)  2001:0:fedc:bfff:ffff:ffff:ffff:ffff
	    (Exploded)  2001:0000:fedc:bfff:ffff:ffff:ffff:ffff
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1011111111111111:1111111111111111:1111111111111111:1111111111111111:1111111111111111

	Total number of addresses: 302231454903657293676544 (2^78 or 3e+23)



	First address assignable (excluding "subnet-router anycast" of RFC 2526):
	  (Compressed)  2001:0:fedc:8000::1
	    (Exploded)  2001:0000:fedc:8000:0000:0000:0000:0001
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1000000000000000:0000000000000000:0000000000000000:0000000000000000:0000000000000001

	Total number of addresses (Excluding "reserved" addresses): 302231454903657293676543 (3e+23)


	This prefix can contain one of the following:
	   * 16384 (2^14 or 1.6e+04) subnets /64
	   * 64 (2^6 or 64) subnets /56


Another example with a /64

	# ./ip6calc.py 2001:0000:fedc:abcd::/64
	Address:
	  (Compressed)  2001:0:fedc:abcd::/64
	    (Exploded)  2001:0000:fedc:abcd:0000:0000:0000:0000/64
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1010101111001101:0000000000000000:0000000000000000:0000000000000000:0000000000000000/64

	Address type is: global unicast

	Netmask:
	  (Compressed)  ffff:ffff:ffff:ffff::
	    (Exploded)  ffff:ffff:ffff:ffff:0000:0000:0000:0000
	      (Binary)  1111111111111111:1111111111111111:1111111111111111:1111111111111111:0000000000000000:0000000000000000:0000000000000000:0000000000000000

	First address assignable: 
	  (Compressed)  2001:0:fedc:abcd::
	    (Exploded)  2001:0000:fedc:abcd:0000:0000:0000:0000
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1010101111001101:0000000000000000:0000000000000000:0000000000000000:0000000000000000

	Last address assignable: 
	  (Compressed)  2001:0:fedc:abcd:ffff:ffff:ffff:ffff
	    (Exploded)  2001:0000:fedc:abcd:ffff:ffff:ffff:ffff
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1010101111001101:1111111111111111:1111111111111111:1111111111111111:1111111111111111

	Total number of addresses: 18446744073709551616 (2^64 or 1.8e+19)



	First address assignable (excluding "subnet-router anycast" of RFC 2526):
	  (Compressed)  2001:0:fedc:abcd::1
	    (Exploded)  2001:0000:fedc:abcd:0000:0000:0000:0001
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1010101111001101:0000000000000000:0000000000000000:0000000000000000:0000000000000001

	Last address assignable (Excluding "reserved" addresses of RFC 2526): 
	  (Compressed)  2001:0:fedc:abcd:ffff:ffff:ffff:ff7f
	    (Exploded)  2001:0000:fedc:abcd:ffff:ffff:ffff:ff7f
	      (Binary)  0010000000000001:0000000000000000:1111111011011100:1010101111001101:1111111111111111:1111111111111111:1111111111111111:1111111101111111

	Total number of addresses (Excluding "reserved" addresses): 18446744073709551487 (1.8e+19)


