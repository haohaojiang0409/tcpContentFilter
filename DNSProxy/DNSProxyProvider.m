#import "DNSProxyProvider.h"
#import <arpa/inet.h>
#import <netinet/in.h>

@implementation DNSProxyProvider {
    //存储ip和域名的对应关系
    NSMutableDictionary<NSString *, NSArray<NSString *>* >*domainToIPs;
    dispatch_queue_t _dnsQueue; // 线程安全队列
}

- (instancetype)init {
    self = [super init];
    if (self) {
        domainToIPs = [NSMutableDictionary dictionary];
        _dnsQueue = dispatch_queue_create("com.eagleyun.dns.queue", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)startProxyWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
    NSLog(@"DNS proxy start");
    completionHandler(nil);
}

- (void)stopProxyWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"DNS proxy stop, reason: %ld", (long)reason);
    
    // 获取当前缓存的域名数量（线程安全）
    __block NSUInteger count = 0;
    dispatch_sync(_dnsQueue, ^{
        count = [domainToIPs count];
    });
    
    NSLog(@"Total number of DNS resolutions cached: %lu", (unsigned long)count);
    
    // 清理资源
    dispatch_barrier_sync(_dnsQueue, ^{
        [domainToIPs removeAllObjects];
    });
    
    completionHandler();
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    NSLog(@"DNS proxy sleep");
    completionHandler();
}

- (void)wake {
    NSLog(@"DNS proxy wake");
}

- (BOOL)handleNewFlow:(NEAppProxyFlow *)flow {
    // UDP流量处理
    if ([flow isKindOfClass:[NEAppProxyUDPFlow class]]) {
        NEAppProxyUDPFlow *udpFlow = (NEAppProxyUDPFlow *)flow;
        [udpFlow openWithLocalFlowEndpoint:udpFlow.localFlowEndpoint completionHandler:^(NSError *error) {
            if (error) {
                NSLog(@"UDP flow open failed: %@", error);
                [udpFlow closeReadWithError:error];
                return;
            }
            [self flowOutUDP:udpFlow];
        }];
        return YES;
    }
    // TCP流量处理
    else if ([flow isKindOfClass:[NEAppProxyTCPFlow class]]) {
        NEAppProxyTCPFlow *tcpFlow = (NEAppProxyTCPFlow *)flow;
        
        // 直接接受 flow，不创建任何新连接！
        [tcpFlow openWithLocalFlowEndpoint:[NWHostEndpoint endpointWithHostname:@"0.0.0.0" port:@"0"]
                        completionHandler:^(NSError *error) {
            if (error) {
                NSLog(@"Failed to open TCP flow: %@", error);
                return;
            }
            
            // 启动双向中转（直接读写 flow）
            [self flowOutTCP:tcpFlow]; // App → System (to remote DNS)
            [self flowInTCP:tcpFlow];  // System (from remote DNS) → App
        }];
        return YES;
    }
    
    NSLog(@"Unsupported flow type: %@", flow.class);
    return NO;
}

#pragma mark - UDP处理
- (void)flowOutUDP:(NEAppProxyUDPFlow *)flow {
    [flow readDatagramsAndFlowEndpointsWithCompletionHandler:^(NSArray<NSData *> *datagrams, NSArray<NWEndpoint *> *endpoints, NSError *error) {
        if (error || datagrams.count == 0) {
            [flow closeReadWithError:error];
            return;
        }

        // 解析域名（仅用于日志/缓存）
        for (NSUInteger i = 0; i < datagrams.count; i++) {
            NSString *domain = [self parseDNSQueryDomain:datagrams[i]];
            if (domain) {
                NSLog(@"DNS Query (UDP): %@", domain);
            }
        }

        // ✅ 关键：直接将原始数据写回 flow！
        // 系统会自动将其发送到 endpoints[i]（即 App 原本要发的 DNS 服务器）
        [flow writeDatagrams:datagrams sentByFlowEndpoints:endpoints completionHandler:^(NSError *writeError) {
            if (writeError) {
                NSLog(@"UDP write error: %@", writeError);
                [flow closeWriteWithError:writeError];
            }
        }];
    }];
}


#pragma mark - TCP处理
- (void)flowOutTCP:(NEAppProxyTCPFlow *)flow {
    [flow readDataWithCompletionHandler:^(NSData *data, NSError *error) {
        if (error || data.length == 0) {
            [flow closeReadWithError:error];
            return;
        }
        // 解析域名（日志用）
        if (data.length > 2) {
            uint16_t len = ntohs(*(uint16_t *)[data bytes]);
            if (len == data.length - 2) {
                NSData *dnsPacket = [data subdataWithRange:NSMakeRange(2, len)];
                NSString *domain = [self parseDNSQueryDomain:dnsPacket];
                if (domain) NSLog(@"TCP DNS Query: %@", domain);
            }
        }
        // 直接写回 flow → 系统自动转发
        [flow writeData:data withCompletionHandler:^(NSError *writeError) {
            if (!writeError) {
                [self flowOutTCP:flow]; // 继续读
            }
        }];
    }];
}

- (void)flowInTCP:(NEAppProxyTCPFlow *)flow {
    __weak typeof(self) weakSelf = self;
    [flow readDataWithCompletionHandler:^(NSData *data, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;

        if (error || data.length == 0) {
            // 读取结束或出错，关闭读端
            [flow closeReadWithError:error];
            return;
        }

        // 解析 DNS 响应（跳过 2 字节长度前缀）
        if (data.length >= 2) {
            uint16_t dnsLength = ntohs(*(uint16_t *)[data bytes]);
            if (dnsLength > 0 && dnsLength <= data.length - 2) {
                NSData *dnsPacket = [data subdataWithRange:NSMakeRange(2, dnsLength)];
                
                // 提取域名（用于匹配缓存）
                NSString *domain = [strongSelf parseDNSQueryDomain:dnsPacket]; 

                // 解析响应中的 IP 列表
                NSArray<NSString *> *ips = [strongSelf parseDNSResponseIPs:dnsPacket];
                if (domain && ips.count > 0) {
                    NSLog(@"DNS Response (TCP) for %@: %@", domain, ips);
                    [strongSelf recordDomain:domain ips:ips];
                }
            }
        }

        // 将原始数据（含 2 字节长度前缀）写回给 App
        [flow writeData:data withCompletionHandler:^(NSError *writeError) {
            if (writeError) {
                NSLog(@"TCP write error (inbound): %@", writeError);
                [flow closeWriteWithError:writeError];
                return;
            }

            // 继续读取下一段响应
            [strongSelf flowInTCP:flow];
        }];
    }];
}
#pragma mark - DNS解析
- (NSString *)parseDNSQueryDomain:(NSData *)data {
    if (!data || data.length < 12 + 1) {
        return nil; // 至少要有 header + 1 字节域名
    }

    const uint8_t *bytes = (const uint8_t *)[data bytes];
    NSUInteger index = 12; // 跳过 12 字节 DNS header
    NSUInteger originalIndex = index;
    NSMutableString *domain = [NSMutableString string];
    int jumpCount = 0;
    const int maxJumps = 10; // 防止指针循环

    while (index < data.length && jumpCount < maxJumps) {
        uint8_t len = bytes[index];

        // 检查是否为压缩指针 (RFC 1035: 14. 章节)
        if ((len & 0xC0) == 0xC0) {
            if (index + 1 >= data.length) {
                return nil; // 指针不完整
            }
            // 指针占 2 字节，高 2 位是标志，低 14 位是偏移
            uint16_t pointer = ((len & 0x3F) << 8) | bytes[index + 1];
            if (pointer >= 12) { // 偏移必须 >= 12（不能指向 header）
                index = pointer;
                jumpCount++;
                continue;
            } else {
                return nil; // 无效指针
            }
        }

        // 长度为 0 表示域名结束
        if (len == 0) {
            break;
        }

        // 普通标签
        if (index + 1 + len > data.length) {
            return nil; // 标签超出数据范围
        }

        // 提取标签内容
        NSString *label = [[NSString alloc] initWithBytes:&bytes[index + 1]
                                                  length:len
                                                encoding:NSUTF8StringEncoding];
        if (!label) {
            return nil; // 非 UTF-8 标签（理论上不应发生）
        }

        if (domain.length > 0) {
            [domain appendString:@"."];
        }
        [domain appendString:label];

        index += 1 + len; // 跳过长度字节 + 标签内容
    }

    // 如果 domain 为空，说明解析失败
    if (domain.length == 0) {
        return nil;
    }

    return [domain copy];
}


- (NSArray<NSString *> *)parseDNSResponseIPs:(NSData *)data {
    if (data.length < sizeof(dns_header_t)) return @[];
    
    const uint8_t *bytes = data.bytes;
    dns_header_t *header = (dns_header_t *)bytes;
    uint16_t qdCount = ntohs(header->qdcount);
    uint16_t anCount = ntohs(header->ancount);
    
    if (anCount == 0) return @[];
    
    NSMutableArray *ips = [NSMutableArray array];
    NSUInteger index = sizeof(dns_header_t);
    
    // 跳过问题部分
    for (int i = 0; i < qdCount; i++) {
        while (index < data.length && bytes[index] != 0) {
            if ((bytes[index] & 0xC0) == 0xC0) { // 指针
                index += 2;
                break;
            } else { // 标签
                index += bytes[index] + 1;
            }
        }
        index += 5; // 0x00 + QTYPE(2) + QCLASS(2)
        if (index >= data.length) break;
    }
    
    // 解析回答部分
    for (int i = 0; i < anCount; i++) {
        if (index + 12 > data.length) break;
        
        // 跳过名称（可能是指针）
        while (index < data.length && bytes[index] != 0) {
            if ((bytes[index] & 0xC0) == 0xC0) {
                index += 2;
                break;
            } else {
                index += bytes[index] + 1;
            }
        }
        index += (bytes[index] == 0) ? 1 : 0;
        
        if (index + 10 > data.length) break;
        
        uint16_t type = ntohs(*(uint16_t *)&bytes[index]);
        uint16_t dataLen = ntohs(*(uint16_t *)&bytes[index + 8]);
        index += 10;
        
        // A记录（IPv4）
        if (type == 1 && dataLen == 4 && index + 4 <= data.length) {
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &bytes[index], ipStr, INET_ADDRSTRLEN);
            [ips addObject:@(ipStr)];
        }
        // AAAA记录（IPv6）
        else if (type == 28 && dataLen == 16 && index + 16 <= data.length) {
            char ipStr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &bytes[index], ipStr, INET6_ADDRSTRLEN);
            [ips addObject:@(ipStr)];
        }
        
        index += dataLen;
    }
    
    return ips;
}

#pragma mark - 辅助方法
- (NSMutableData *)createNXResponse:(NSData *)request protocol:(NSUInteger)protocol {
    if (request.length < sizeof(dns_header_t)) return nil;
    
    NSMutableData *response = [request mutableCopy];
    dns_header_t *header = (dns_header_t *)response.mutableBytes;
    
    // 调整头部（TCP需跳过长度前缀）
    if (protocol == SOCK_STREAM) {
        header = (dns_header_t *)((char *)header + sizeof(uint16_t));
    }
    
    header->flags = htons(ntohs(header->flags) | 0x8000 | 0x0003); // 设置响应+NXDOMAIN
    header->ancount = 0; // 清空回答
    
    return response;
}

-(void)recordDomain:(NSString*)domain ips:(NSArray<NSString *> *)ips{
    if(!domain || ips.count == 0){
        return;
    }
    
    //使用set去重自动排序
    NSArray<NSString*> *uniqueIPs = [[NSSet setWithArray:ips] allObjects];
    
    //添加到队列当中异步执行
    dispatch_barrier_async(_dnsQueue , ^{
        self->domainToIPs[domain] = uniqueIPs;
    });
}

-(NSArray<NSString*>*)lookupIPsForDomain:(NSString*)domain{
    __block NSArray<NSString*> *result = nil;
    dispatch_sync(_dnsQueue, ^{
        result = [domainToIPs objectForKey:domain];
    });
    return result ?:@[];
}

-(NSDictionary<NSString* , NSArray<NSString*>*>*)copyAllDomainIPsMapping{
    __block NSDictionary<NSString* , NSArray<NSString*>*> *snapshot = nil;
    dispatch_sync(_dnsQueue, ^{
        snapshot = [domainToIPs copy];
    });
    return snapshot;
}

-(void)cleanAllMapping{
    dispatch_sync(_dnsQueue, ^{
        [domainToIPs removeAllObjects];
    });
}
@end
