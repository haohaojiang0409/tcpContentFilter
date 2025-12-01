//
//  tools.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/28.
//
#import "tools.h"

NSArray* resolveAddress(NSString* ipAddr)
{
    //hints
    struct addrinfo hints = {0};
    
    //result
    struct addrinfo *result = NULL;
    
    //address
    CFDataRef address = {0};
    
    //host
    CFHostRef host = NULL;
    
    //error
    CFStreamError streamError = {0};
    
    //(resolved) host names
    NSArray* hostNames = nil;
    
    //dbg msg
    NSLog(@"(attempting to) reverse resolve %@", ipAddr);
    
    //clear hints
    memset(&hints, 0x0, sizeof(hints));
    
    //init flags
    hints.ai_flags = AI_NUMERICHOST;
    
    //init family
    hints.ai_family = PF_UNSPEC;
    
    //init type
    hints.ai_socktype = SOCK_STREAM;
    
    //init proto
    hints.ai_protocol = 0;
    
    //get addr info
    if(0 != getaddrinfo(ipAddr.UTF8String, NULL, &hints, &result))
    {
        goto bail;
    }
    
    //convert to data
    address = CFDataCreate(NULL, (UInt8 *)result->ai_addr, result->ai_addrlen);
    if(NULL == address)
    {
        goto bail;
    }
    
    //create host
    host = CFHostCreateWithAddress(kCFAllocatorDefault, address);
    if(host == nil)
    {
        goto bail;
    }
    
    //resolve
    if(YES != CFHostStartInfoResolution(host, kCFHostNames, &streamError))
    {
        goto bail;
    }
    
    //capture
    hostNames = (__bridge NSArray *)(CFHostGetNames(host, NULL));
    
bail:
    
    //free address
    if(NULL != address)
    {
        //free
        CFRelease(address);
        address = NULL;
    }
    
    //free host
    if(NULL != host)
    {
        //free
        CFRelease(host);
        host = NULL;
    }
    
    //free result
    if(NULL != result)
    {
        //free
        freeaddrinfo(result);
        result = NULL;
    }
    
    return hostNames;
}

//将字符串转化为ipv4
uint32_t strToIpv4Uint16(NSString* strHostName){
    if(!strHostName){
        return 0;
    }
    struct in_addr addr;
    if (inet_aton([strHostName UTF8String], &addr)) {
        return ntohl(addr.s_addr);
    }
    return 0;
}
