.. image:: https://img.shields.io/badge/Language-C-orange.svg
   :alt: Language C

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
   :alt: MIT License

.. image:: https://img.shields.io/badge/version-2.0.0-green.svg

.. image:: https://travis-ci.org/jacopodl/Spark.svg?branch=master

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

or download .zip from `here <https://github.com/jacopodl/Spark/archive/master.zip>`_.

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
    MIT License

    Copyright (c) 2016 Jacopo De Luca

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
