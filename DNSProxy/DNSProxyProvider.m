//
//  DNSProxyProvider.m
//  DNSProxy
//
//  Created by haohaojiang0409 on 2025/12/1.
//

#import "DNSProxyProvider.h"

@implementation DNSProxyProvider

- (void)startProxyWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
    // Add code here to start the DNS proxy.
    NSLog(@"DNS proxy start");
    completionHandler(nil);
}

- (void)stopProxyWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    // Add code here to stop the DNS proxy.
    NSLog(@"DNS proxy stop");
    completionHandler();
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    // Add code here to get ready to sleep.
    completionHandler();
}

- (void)wake {
    // Add code here to wake up.
}

- (BOOL)handleNewFlow:(NEAppProxyFlow *)flow {
    // Add code here to handle the incoming flow.
    NEFilterSocketFlow* socketFlow = NULL;
    if ([flow isKindOfClass:[NEAppProxyUDPFlow class]]) {
        [(NEAppProxyUDPFlow *)flow openWithLocalFlowEndpoint:((NEAppProxyUDPFlow *)flow).localFlowEndpoint completionHandler:^(NSError *error) {
            if (!error) {
               // [self flowOutUDP:(NEAppProxyUDPFlow *)flow];
                NSLog(@"UDP flow should be detected");
            }
        }];
        return YES;
    }else if ([flow isKindOfClass:[NEAppProxyTCPFlow class]]) {
        NEAppProxyTCPFlow *tcpFlow = (NEAppProxyTCPFlow *)flow;
        nw_endpoint_t remoteEndpoint = nw_endpoint_create_host(
            ((NWHostEndpoint *)tcpFlow.remoteFlowEndpoint).hostname.UTF8String,
            ((NWHostEndpoint *)tcpFlow.remoteFlowEndpoint).port.UTF8String
        );
        nw_connection_t remoteConnection = nw_connection_create(remoteEndpoint, nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
        
        nw_connection_set_queue(remoteConnection, dispatch_get_main_queue());
        nw_connection_set_state_changed_handler(remoteConnection, ^(nw_connection_state_t state, nw_error_t error) {
            if (error) {
                [flow closeWriteWithError:nil];
                return;
            }
            if (state == nw_connection_state_ready) {
                [flow openWithLocalFlowEndpoint:[NWHostEndpoint endpointWithHostname:@"localhost" port:@"0"] completionHandler:^(NSError *error) {
                    if (!error) {
                        [self flowOutTCP:tcpFlow connection:remoteConnection];
                        [self flowInTCP:tcpFlow connection:remoteConnection];
                    }
                }];
            }
        });
        nw_connection_start(remoteConnection);
        return YES;
    }
    return NO;
}

//处理出站UDP
-(void)flowOutUDP:(NEAppProxyUDPFlow*)flow{
    [flow readDatagramsWithCompletionHandler:^(NSArray *datagrams, NSArray *endpoints, NSError *error){
        if(error || datagrams.count == 0){
            return;
        }
        for(int i = 0;i < datagrams.count;i++){
            NSData* packet = datagrams[i];
            NWHostEndpoint *endpoint = endpoints[i];

            // 转发到远程 DNS 服务器
            nw_endpoint_t nwEndpoint = nw_endpoint_create_host(endpoint.hostname.UTF8String, endpoint.port.UTF8String);
            nw_connection_t connection = nw_connection_create(nwEndpoint, nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
            nw_connection_set_queue(connection, dispatch_get_main_queue());
            nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
                if (state == nw_connection_state_ready) {
                    dispatch_data_t data = dispatch_data_create(packet.bytes, packet.length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    nw_connection_send(connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, NULL);
                    [self flowInUDP:flow connection:connection endpoint:endpoint];
                }
            });
            nw_connection_start(connection);
        }
    }];
}
-(void)flowInUDP:(NEAppProxyUDPFlow*)flow connection:(nw_connection_t)connection endpoint:(NWHostEndpoint *)endpoint{
    nw_connection_receive(connection, 1, UINT32_MAX, ^(dispatch_data_t  _Nullable content, nw_content_context_t  _Nullable context, bool is_complete, nw_error_t  _Nullable error) {
        if(error || !content){
            NSData* response = (NSData*)content;
            [flow writeDatagrams:@[response] sentByFlowEndpoints:@[endpoint] completionHandler:nil];
        }
    });
}
// TCP 出站流量处理
- (void)flowOutTCP:(NEAppProxyTCPFlow *)flow connection:(nw_connection_t)remoteConnection {
    [flow readDataWithCompletionHandler:^(NSData *data, NSError *error) {
        if (error || data.length == 0) {
            [flow closeReadWithError:error];
            return;
        }
        
        // 解析 DNS 请求（跳过 TCP 长度前缀）
        uint16_t length = ntohs(*(uint16_t *)data.bytes);
        if (data.length >= sizeof(uint16_t) + length) {
            NSLog(@"DNS 数据包长度: %hu", length);
        }
        
        // 转发到远程 DNS 服务器
        dispatch_data_t dataToSend = dispatch_data_create(data.bytes, data.length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(remoteConnection, dataToSend, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
            if (!error) [self flowOutTCP:flow connection:remoteConnection];
        });
    }];
}

// TCP 入站流量处理
- (void)flowInTCP:(NEAppProxyTCPFlow *)flow connection:(nw_connection_t)connection {
    nw_connection_receive(connection, 1, UINT32_MAX, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        if (receive_error || !content) return;
        
        NSData *response = (NSData *)content;
        [flow writeData:response withCompletionHandler:^(NSError *error) {
            if (!error) [self flowInTCP:flow connection:connection];
        }];
        
        if (is_complete) nw_connection_cancel(connection);
    });
}

// 生成 NXDOMAIN 响应（简化版）
- (NSMutableData *)createNXResponse:(NSData *)request protocol:(NSUInteger)protocol {
    if (request.length < sizeof(dns_header_t)) return nil;
    
    NSMutableData *response = [request mutableCopy];
    dns_header_t *header = (dns_header_t *)response.bytes;
    if (protocol == SOCK_STREAM) header = (dns_header_t *)((char *)header + sizeof(uint16_t));
    
    header->flags |= htons(0x8000); // 设置为响应
    header->flags |= htons(0x0003); // 设置 RCODE 为 NXDOMAIN
    
    return response;
}
@end
