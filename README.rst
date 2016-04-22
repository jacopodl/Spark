.. image:: https://img.shields.io/badge/Language-C-orange.svg
   :alt: Language C

.. image:: https://img.shields.io/badge/license-GPL3-blue.svg
   :target: http://www.gnu.org/licenses/gpl-3.0.html
   :alt: GPLv3 License

.. image:: https://img.shields.io/badge/version-1.0-green.svg

=====
Spark
=====

A small raw socket library for Linux/BSD system to test and explore network technology.

Introduction
------------
This library provide a uniform interface for raw socket and implements various network protocols that are part of the TCP/IP stack.

+---------------------------------------------------------------------------+
|Implemented protocols                                                      |
+==============+==================+===================+=====================+
|**Link Layer**|**Internet layer**|**Transport layer**|**Application Layer**|
+--------------+------------------+-------------------+---------------------+
|Ethernet      |IPv4              |TCP                |DHCP(Partial)        |
+--------------+------------------+-------------------+---------------------+
|ARP           |ICMPv4            |UDP                |                     |
+--------------+------------------+-------------------+---------------------+

================
Getting the code
================
Check out the latest version with::

  $ git clone http://github.com/jacopodl/spark

or download .zip from `here <https://github.com/jacopodl/Spark/archive/spark.zip>`_.

Building library:
-----------------
Spark uses cmake for automate the build process, you can download it from `here <https://cmake.org/download>`_ or you can install from your package manager::

   Debian like:
      $ apt-get install cmake
   Arch like:
      $ pacman -S cmake

Now you can build library in this way::

   $ cd spark
   $ cmake CMakeLists.txt
   $ make

If the build finishes without errors, the compiled library will be located in the bin directory and related headers file will be located in include directory.

=======
License
=======
    Copyright (C) <2015-2016>  <Jacopo De Luca>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
