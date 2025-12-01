//
//  tools.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/28.
//
#ifndef tools_h
#define tools_h

#import <Foundation/Foundation.h>
#import <netdb.h>
#import <arpa/inet.h>
//反向解析ip地址
NSArray* resolveAddress(NSString* ipAddr);

uint32_t strToIpv4Uint16(NSString* strHostName);
#endif
