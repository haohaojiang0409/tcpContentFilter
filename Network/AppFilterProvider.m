//
//  AppFilterProvider.m
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import "AppFilterProvider.h"

@implementation AppFilterProvider

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    // 出站规则
    NENetworkRule *outboundRule = [[NENetworkRule alloc]
        initWithRemoteNetwork:nil remotePrefix:0
        localNetwork:nil localPrefix:0
        protocol:NENetworkRuleProtocolAny
        direction:NETrafficDirectionOutbound];

    // 入站规则
    NENetworkRule *inboundRule = [[NENetworkRule alloc]
        initWithRemoteNetwork:nil remotePrefix:0
        localNetwork:nil localPrefix:0
        protocol:NENetworkRuleProtocolAny
        direction:NETrafficDirectionInbound];

    NEFilterRule *outboundFilterRule = [[NEFilterRule alloc]
        initWithNetworkRule:outboundRule action:NEFilterActionFilterData];
    NEFilterRule *inboundFilterRule = [[NEFilterRule alloc]
        initWithNetworkRule:inboundRule action:NEFilterActionFilterData];

    NEFilterSettings *filterSettings = [[NEFilterSettings alloc]
        initWithRules:@[outboundFilterRule, inboundFilterRule]
        defaultAction:NEFilterActionAllow];

    [self applySettings:filterSettings completionHandler:completionHandler];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler
{
  completionHandler();
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;

    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:64 filterOutbound:YES peekOutboundBytes:64];
}

- (NEFilterDataVerdict *)handleOutboundDataCompleteForFlow:(NEFilterFlow *)flow{
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;

    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
    return [NEFilterDataVerdict allowVerdict];
}

- (NEFilterDataVerdict *)handleInboundDataCompleteForFlow:(NEFilterFlow *)flow{
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;

    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
    return [NEFilterDataVerdict allowVerdict];
}
@end
