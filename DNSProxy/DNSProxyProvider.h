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

-(NSArray<NSString*>*)lookupIPsForDomain:(NSString*)domain;

-(NSDictionary<NSString* , NSArray<NSString*>*>*)copyAllDomainIPsMapping;

-(void)cleanAllMapping;

-(void)recordDomain:(NSString*)domain ips:(NSArray<NSString *> *)ips;
//初始化方法·
-(instancetype)init;
@end
