![](https://img.shields.io/badge/Language-C-orange.svg)
![](https://img.shields.io/badge/version-3.0.0-green.svg)
![](https://travis-ci.org/jacopodl/Spark.svg?branch=master)
![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)
![](https://img.shields.io/badge/Supported%20Os-Linux%2FMac%20Os-red.svg)

# Spark #
Small and easy to use network library that support raw socket, pcap file and contains API to easily manipulate the main Internet protocols.  

# How to use #

## Building library ##
Check out the latest version with:

    $ git clone https://github.com/jacopodl/spark

or download .zip from [release](<https://github.com/jacopodl/Spark/releases/>) page.

Now you can build library in this way:  \
(Spark required cmake to automate build process, please install cmake first!)

    $ cd spark
    $ cmake .
    $ make

If the build finishes without errors, the compiled library will be located in the bin directory and related headers file will be located in include directory.

## Quick tour ##

### Packet sniffer ###

```C
unsigned char buf[4096];
struct SpkSock *rsock;
struct SpkPcap *mypcap;
struct SpkTimeStamp ts;

int err;
int len;
int max_packet = 1000;

if((err = spark_opensock("my-interface", sizeof(buf), &rsock)) < 0)
{
    fprintf(stderr, "%s\n", spark_strerror(err));
    return -1;
}

if((err = spark_pnew("my-pcap", SPKPCAP_SNAPLEN_DEFAULT, spark_getltype(rsock), &mypcap)) < 0)
{
    fprintf(stderr, "%s\n", spark_strerror(err));
    return -1;
}

while(max_packet-- > 0)
{
    len = spark_read(rsock, buf, &ts);
    spark_pwrite(mypcap, buf, len, &ts);
}

spark_close(rsock);
spark_pclose(mypcap);

```

### Polymorphic type ###

```C
void addr_printer(struct netaddr *addr)
{
    if(NETADDR_CMP_TYPE((*addr), NA_TYPE_MAC))
        printf("This is MAC address!\n");
    else if(NETADDR_CMP_TYPE((*addr), NA_TYPE_IP))
        printf("This is IPv4 address!\n");
    else if (NETADDR_CMP_TYPE((*addr), NA_TYPE_IP6))
        printf("This is IPv6 address!\n");
    else
        printf("Generic/unknown address!\n");
}

int main()
{
    netaddr_mac(macaddr);
    netaddr_ip(ipaddr);
    
    addr_printer(&macaddr);
    addr_printer(&ipaddr);
}

```

# License #
Made with :heartpulse: by <b>JDL</b> and released under <b>MIT license</b>.
