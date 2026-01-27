##! Network Security Monitoring - Attack Detection Rules
##! Detects: Port scans, DoS, SQL injection, XSS, brute force, and more

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssh
@load policy/tuning/json-logs.zeek

module SecurityMonitor;

export {
    redef enum Notice::Type += {
        ## Port scanning detection
        Port_Scan_Detected,
        
        ## HTTP-based attacks
        HTTP_Flood_Detected,
        SQL_Injection_Attempt,
        XSS_Attempt,
        Directory_Traversal_Attempt,
        Command_Injection_Attempt,
        
        ## SSH attacks
        SSH_Brute_Force,
        
        ## Network attacks
        ICMP_Flood_Detected,
        SYN_Flood_Detected,
        Malformed_Packet_Detected,
        
        ## Suspicious activity
        Suspicious_User_Agent,
        High_Request_Rate,
        
        ## System status
        Zeek_Started
    };
    
    ## Thresholds for detection
    const port_scan_threshold = 10 &redef;  # ports scanned
    const http_flood_threshold = 50 &redef;  # requests per interval
    const ssh_fail_threshold = 5 &redef;    # failed SSH attempts
    const icmp_flood_threshold = 100 &redef; # ICMP packets per interval
    
    ## Time windows for rate calculations
    const scan_interval = 60sec &redef;
    const http_flood_interval = 10sec &redef;
    const ssh_fail_interval = 60sec &redef;
}

## Global tracking tables
global port_scanners: table[addr] of set[port] &create_expire=scan_interval;
global http_requesters: table[addr] of count &create_expire=http_flood_interval;
global ssh_failures: table[addr] of count &create_expire=ssh_fail_interval;
global icmp_senders: table[addr] of count &create_expire=10sec;
global syn_flood_trackers: table[addr] of count &create_expire=5sec;

## Zeek initialization
event zeek_init()
{
    NOTICE([
        $note=Zeek_Started,
        $msg="Zeek Network Security Monitor initialized - All detection modules active"
    ]);
}

##############################################################################
## PORT SCAN DETECTION
##############################################################################
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    
    if ( orig !in port_scanners )
        port_scanners[orig] = set();
    
    add port_scanners[orig][c$id$resp_p];
    
    if ( |port_scanners[orig]| >= port_scan_threshold )
    {
        NOTICE([
            $note=Port_Scan_Detected,
            $conn=c,
            $src=orig,
            $msg=fmt("Port scan detected from %s - %d ports scanned", 
                     orig, |port_scanners[orig]|),
            $identifier=cat(orig)
        ]);
    }
}

##############################################################################
## HTTP ATTACK DETECTION
##############################################################################
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local src = c$id$orig_h;
    
    ## Track request rate for HTTP flood detection
    if ( src !in http_requesters )
        http_requesters[src] = 0;
    
    ++http_requesters[src];
    
    if ( http_requesters[src] >= http_flood_threshold )
    {
        NOTICE([
            $note=HTTP_Flood_Detected,
            $conn=c,
            $src=src,
            $msg=fmt("HTTP flood detected from %s - %d requests in %s", 
                     src, http_requesters[src], http_flood_interval)
        ]);
    }
    
    ## SQL Injection patterns
    if ( /(\%27)|(\')|(\-\-)|(\%23)|(#)/i in unescaped_URI ||
         /(union|select|insert|update|delete|drop|create|exec|script)/i in unescaped_URI &&
         /(\%20|&|;)/i in unescaped_URI )
    {
        NOTICE([
            $note=SQL_Injection_Attempt,
            $conn=c,
            $src=src,
            $msg=fmt("SQL injection attempt detected from %s: %s", src, unescaped_URI),
            $sub=original_URI
        ]);
    }
    
    ## XSS patterns
    if ( /<script|<img|onerror=|onload=|javascript:/i in unescaped_URI )
    {
        NOTICE([
            $note=XSS_Attempt,
            $conn=c,
            $src=src,
            $msg=fmt("XSS attempt detected from %s: %s", src, unescaped_URI),
            $sub=original_URI
        ]);
    }
    
    ## Directory traversal patterns
    if ( /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f/i in unescaped_URI )
    {
        NOTICE([
            $note=Directory_Traversal_Attempt,
            $conn=c,
            $src=src,
            $msg=fmt("Directory traversal attempt from %s: %s", src, unescaped_URI),
            $sub=original_URI
        ]);
    }
    
    ## Command injection patterns  
    if ( /;|\||&|`|\$\(|<\(|>\(/i in unescaped_URI &&
         /(cat|ls|whoami|id|passwd|shadow|wget|curl|nc|bash|sh)/i in unescaped_URI )
    {
        NOTICE([
            $note=Command_Injection_Attempt,
            $conn=c,
            $src=src,
            $msg=fmt("Command injection attempt from %s: %s", src, unescaped_URI),
            $sub=original_URI
        ]);
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && name == "USER-AGENT" )
    {
        ## Detect suspicious user agents (scanners, attack tools)
        if ( /sqlmap|nikto|nmap|masscan|zap|burp|metasploit|nessus/i in value )
        {
            NOTICE([
                $note=Suspicious_User_Agent,
                $conn=c,
                $src=c$id$orig_h,
                $msg=fmt("Suspicious user agent detected from %s: %s", c$id$orig_h, value),
                $sub=value
            ]);
        }
    }
}

##############################################################################
## SSH BRUTE FORCE DETECTION  
##############################################################################
event ssh_auth_failed(c: connection)
{
    local src = c$id$orig_h;
    
    if ( src !in ssh_failures )
        ssh_failures[src] = 0;
    
    ++ssh_failures[src];
    
    if ( ssh_failures[src] >= ssh_fail_threshold )
    {
        NOTICE([
            $note=SSH_Brute_Force,
            $conn=c,
            $src=src,
            $msg=fmt("SSH brute force detected from %s - %d failed attempts", 
                     src, ssh_failures[src])
        ]);
    }
}

##############################################################################
## ICMP FLOOD DETECTION
##############################################################################
event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
    local src = c$id$orig_h;
    
    if ( src !in icmp_senders )
        icmp_senders[src] = 0;
    
    ++icmp_senders[src];
    
    if ( icmp_senders[src] >= icmp_flood_threshold )
    {
        NOTICE([
            $note=ICMP_Flood_Detected,
            $conn=c,
            $src=src,
            $msg=fmt("ICMP flood detected from %s - %d packets", src, icmp_senders[src])
        ]);
    }
}

##############################################################################
## SYN FLOOD DETECTION
##############################################################################
event connection_attempt(c: connection)
{
    local src = c$id$orig_h;
    
    if ( src !in syn_flood_trackers )
        syn_flood_trackers[src] = 0;
    
    ++syn_flood_trackers[src];
    
    if ( syn_flood_trackers[src] >= 100 )
    {
        NOTICE([
            $note=SYN_Flood_Detected,
            $conn=c,
            $src=src,
            $msg=fmt("Possible SYN flood from %s - %d connection attempts", 
                     src, syn_flood_trackers[src])
        ]);
    }
}

##############################################################################
## MALFORMED PACKET DETECTION
##############################################################################
event conn_weird(name: string, c: connection, addl: string)
{
    if ( /bad_TCP|bad_ICMP|bad_UDP|truncated|corrupt/i in name )
    {
        NOTICE([
            $note=Malformed_Packet_Detected,
            $conn=c,
            $src=c$id$orig_h,
            $msg=fmt("Malformed packet detected from %s: %s - %s", 
                     c$id$orig_h, name, addl)
        ]);
    }
}
