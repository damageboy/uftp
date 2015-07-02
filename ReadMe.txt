--== UFTP - Encrypted UDP based FTP with multicast ==--

UFTP is an encrypted multicast file transfer program, designed to securely,
reliably, and efficiently transfer files to multiple receivers simultaneously.
This is useful for distributing large files to a large number of receivers,
and is especially useful for data distribution over a satellite link (with two
way communication), where the inherent delay makes any TCP based communication
highly inefficient.  The multicast encryption scheme is based on TLS with
extensions to allow multiple receivers to share a common key.

UFTP also has the capability to communicate over disjoint networks separated
by one or more firewalls (NAT traversal) and without full end-to-end multicast
capability (multicast tunneling) through the use of a UFTP proxy server. 
These proxies also provide scalability by aggregating responses from a group
of receivers.

--== Building ==--

UNIX-like systems require GNU make and a C compiler such as GCC or
equivalent.  Windows systems require Visual Studio Express 2010 or later.

Non-Windows systems require OpenSSL to be installed if encryption support is
enabled.  On Linux, Solaris, and BSD systems (including MacOSX), this should
be included with the OS.


To compile for UNIX-like systems, including MacOSX:
make [ OPENSSL={install directory for OpenSSL} ] [ NO_ENCRYPTION=1 ] [ NO_EC=1 ]

To compile for Windows (from a Visual Studio command prompt):
nmake -f makefile.mak [ OPENSSL={install directory for OpenSSL} ] [ NO_ENCRYPTION=1 ] [ WINXP=1 ]

The OPENSSL parameter to make should only need to be specified if OpenSSL is
installed in a non-standard location, or on systems where it isn't
preinstalled.

The NO_ENCRYPTION flag compiles with no encryption support.  This can be
useful in embedded environments that don't need encryption and want to
keep the size of the executable down, and for use in a Windows service
that doesn't require encryption.

The NO_EC flag compiles without support for Elliptic Curve crypto.  This may
be required if either you have an older version of OpenSSL or the build of
OpenSSL installed wasn't configured with ECC support.

The WINXP flag is used on Windows systems to disable features requiring
Windows Vista or Windows 7.  This includes dual stack IPv4/IPv6 sockets as
well as the CNG API which supports Elliptic Curve crypto, larger hash sizes,
and authenticated mode ciphers.


To install for UNIX-like systems, including MacOSX:
make [ DESTDIR={install directory} ] install

The DESTDIR parameter allows installing into a fake root directory, which
can be useful for packaging utilities such as rpm.


--== Tuning ==--

If you find that clients can't receive data fast enough, or if servers
communicating with several hundred clients can't handle the flood of
STATUS messages that come in, you can increase the UDP send/receive buffer
size to help with this.  This is set using the -B option on server, 
client, or proxy.  However, many operating systems impose a maximum value
of 256K (262144).  This limit can be increased, although the method is OS
specific.  Here are a few common ones:

Solaris: ndd -set /dev/udp udp_max_buf {value}

Linux: sysctl -w net.core.rmem_max={value}
       sysctl -w net.core.wmem_max={value}

MacOSX / FreeBSD: sysctl -w kern.ipc.maxsockbuf={value}
(The actual maximum you can use is 8/9 of this value)

While Windows does not have this limitation, Windows XP Service Pack 3 and
later does throttle back UDP datagrams larger that 1024 bytes by default
(a UFTP packet is 1472 bytes by default).  This is most commonly seen when
attempting to move data at 100 Mbps or more.  You can change this by
adding/modifying the following registry value:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\FastSendDatagramThreshold

Set this DWORD value to 1500 and reboot, and it should take care of the issue.

If you're making use of the DSCP/TOS byte in the IP header, this can be
modified via the -Q option to the server, client, or proxy.  On Windows XP
systems, this can't be modified by default using portable libriaries.  This
can be overridden by adding/modifying the following registry value:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableUserTOSSetting

Set this DWORD value to 0 and reboot, and the -Q option should work.

Windows Vista and Windows 7 don't support this particular mechanism at all,
and each has it's own way of doing it.  For now, this option does not work on
these OSs.

The TOS byte also contains the ECN bits, which are used by the TFMCC 
congestion control scheme, so restrictions on the TOS byte also affect the
sender support for ECN.

--== Running under Windows ==--

UFTP was originally written to run in a UNIX/Linux environment, so it doesn't
natively do things that other Windows servers do such as run in the background
or run as a Windows service.  Included with UFTP are hidedos.exe, instsrv.exe,
and srvany.exe which allows these things to happen.  Hidedos is a utility
originally written by LANDesk to allow command line windows programs to run
in the background.  Instsrv and srvany are components of the Windows Resource
Kit which.  Instsrv is used to install and remove services, and srvany allows
programs not written as windows services to run as such.


To run the uftpd client or proxy without leaving a command prompt open
(the -d option tells uftpd to run in the foreground, so don't use this
option in this case):

hidedos uftpd [options]
-- or --
hidedos uftpproxyd [options]


To run the uftpd client as a Windows service:
(steps for the proxy are similar)

Copy instsrv.exe and srvany.exe to the system folder (usually
C:\Windows\system32)

Install the service:
instsrv UFTPD c:\windows\system32\srvany.exe

Configure the service:
Open regedit and go to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UFTPD
Right-click the UFTPD key and choose New > Key.
Name the key Parameters.
Right-click the new Parameters key under UFTP and choose New > String Value.
Name the string Application.  
Double-click the Application value and fill in the full command line to uftpd

Once configured, the service should start.  In the task list, you'll see
both srvany.exe and uftpd.exe running while the service is up.

If you need to remove the service:
instsrv UFTPD remove

