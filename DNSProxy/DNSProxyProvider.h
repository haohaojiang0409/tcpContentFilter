//
//  DNSProxyProvider.h
//  DNSProxy
//
//  Created by haohaojiang0409 on 2025/12/1.
//

#import <NetworkExtension/NetworkExtension.h>
#import <nameser.h>
#import <dns_util.h>
#import <Network/Network.h>
#define DNS_FLAGS_QR_MASK  0x8000
#define DNS_FLAGS_QR_QUERY 0x0000

@interface DNSProxyProvider : NEDNSProxyProvider

@end
