//
//  tools.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/28.
//
#import "tools.h"

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

uint32_t ipv4StringToUInt32(NSString *ipStr) {
    if (!ipStr || ![ipStr isKindOfClass:[NSString class]]) return 0;
    
    struct in_addr addr;
    if (inet_aton([ipStr UTF8String], &addr) == 1) {
        // inet_aton 返回网络字节序，转为主机字节序便于比较和存储
        return ntohl(addr.s_addr);
    }
    return 0;
}
