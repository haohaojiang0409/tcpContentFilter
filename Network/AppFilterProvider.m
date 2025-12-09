//
//  AppFilterProvider.m
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import "AppFilterProvider.h"
#include <sys/time.h>
#import <Network/Network.h>
#include <arpa/inet.h>

@implementation AppFilterProvider
#pragma mark - 加载过滤配置
- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    
    // 1️⃣ 初始化规则管理器
    FirewallRuleManager *rulesManager = [FirewallRuleManager sharedManager];

    // 2️⃣ 初始化规则加载器
    NSURL* ruleURL = [NSURL URLWithString:@"https://sp.pre.eagleyun.cn/api/agent/v1/edr/firewall_policy/get_firewall_detail_config"];
    RulePollingManager* _rulePollingManager = [[RulePollingManager alloc] initWithURL:ruleURL];
    
    _rulePollingManager.onJSONReceived = ^(NSDictionary<NSString *, id> * _Nonnull json) {
        // 注意：json 已经是解析好的 NSDictionary，无需再用 NSJSONSerialization 解析！
            if (!json || json.count == 0) {
                os_log(firewallLog , "Failed to read rule.json or file is empty");
                return;
            }
            
            NSDictionary *dataDict = json[@"data"];
            NSArray *rawRules = dataDict[@"rules"];
            
            if (![rawRules isKindOfClass:[NSArray class]] || rawRules.count == 0) {
                os_log(firewallLog , "No rules in 'data.rules'");
                return;
            }
            
            FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
            [manager removeAllRules]; // 清空前一次规则
            
            NSUInteger total = 0;
            for (NSDictionary *rawRule in rawRules) {
                NSArray<FirewallRule *> *rules = [FirewallRule rulesWithDictionary:rawRule];
                for (FirewallRule *rule in rules) {
                    [manager addRule:rule];
                    total++;
                }
            }
            
            os_log(firewallLog , "Loaded and registered %lu firewall rule objects", (unsigned long)total);
    };
    // 开始轮询
    [_rulePollingManager startPolling];
    // 4️⃣ 初始化日志变量
    firewallLog = os_log_create("com.eagleyun.BorderControl", "Network");
    os_log(firewallLog , "Filter started");
       NSFileManager *filemgr;
       // end pcap initialization
        NENetworkRule* networkRule = [
          [NENetworkRule alloc]
          initWithRemoteNetwork:nil
          remotePrefix:0
          localNetwork:nil
          localPrefix:0
          protocol:NENetworkRuleProtocolAny
          direction:NETrafficDirectionAny
        ];
        NEFilterRule* filterRule = [
          [NEFilterRule alloc]
          initWithNetworkRule:networkRule
          action:NEFilterActionFilterData
        ];
        NEFilterSettings* filterSettings = [
          [NEFilterSettings alloc]
          initWithRules:@[filterRule]
          defaultAction:NEFilterActionFilterData
        ];
        [self applySettings:filterSettings completionHandler:^(NSError * _Nullable error) {
            if (error) {
                os_log(firewallLog , "Failed to start filter: %{public}@", error.localizedDescription);
            } else {
                os_log(firewallLog , "Network filter started successfully");
            }
            completionHandler(error);
        }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"Packet filter stopped: %ld", (long)reason);
    completionHandler();
}

- (void)allowPacket:(NEPacket *)packet{
    
}

#pragma mark - 处理新到来的流
//1.建立连接之前还是之后：建立连接之前
//2.扩展截获的是发往所有网卡的数据包？可以选，默认所有网卡
//3.IPPROTO_UDP 和 NENetworkRuleProtocolUDP的区别？ 前者是应用于socket层，后者应用于IP层
- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        os_log(firewallLog , "[FLOW] Non-socket flow, allowing.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    return [NEFilterNewFlowVerdict allowVerdict];
    // 标记所有流都要数据
    //return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:512 filterOutbound:YES peekOutboundBytes:1024];
}

#pragma mark -- 处理出站的所有流
///建立连接之前就可以获取到流
- (NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow
                                readBytesStartOffset:(NSUInteger)offset
                                           readBytes:(NSData *)readBytes {
    os_log(firewallLog , "handleOutboundDataCompleteForFlow");
    // 获取当前时间
    NSDate *currentDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    NSString *currentTimeString = [dateFormatter stringFromDate:currentDate];
    
    // 打印流ID和当前时间
    os_log(firewallLog , "Flow ID: %{public}@, Time: %{public}@ ", flow.identifier, currentTimeString);
    
    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    NEFilterSocketFlow* socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint* remoteEP = socketFlow.remoteEndpoint;
    NSString* remoteHostName = nil;
    NSString* port = 0;

    //1.获取远程主机名
    //从URL获取主机名
    if(nil != socketFlow.URL.host){
        remoteHostName = socketFlow.URL.host;
        os_log(firewallLog ,"---- %{public}@ socket URL host:%{public}@ is not nil" , flow.identifier , remoteHostName);
    }//从flow中获取主机名
    else if(nil != socketFlow.remoteHostname){
        remoteHostName = socketFlow.remoteHostname;
        os_log(firewallLog ,"---- %{public}@ socket remoteHost Name:%{public}@ is not nil " , flow.identifier , remoteHostName);
    }//获取ip地址
    else if(nil != remoteEP.hostname){
        remoteHostName = remoteEP.hostname;
        os_log(firewallLog ,"---- %{public}@ remoteEP hostname:%{public}@is not nil"  , flow.identifier , remoteHostName);
    }

    FirewallRule* matchedRule = nil;
    port = remoteEP.port;
    BOOL isIPv4 = NO;
    if (remoteHostName.length > 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, [remoteHostName UTF8String], &addr) == 1) {
            isIPv4 = YES;
        }
    }
    if(isIPv4){
        NSString* domainName = [[DomainIPCache sharedCache] domainForIP:remoteHostName];
        if(domainName){
            os_log(firewallLog , "the %{public}@ is a ipv4 addresss and hostName is %{public}@" , remoteHostName , domainName);
        }else{
            os_log(firewallLog, "the %{public}@ has no domain in cache" , remoteHostName);
        }
    }
    if(ipv4StringToUInt32(remoteHostName))
    //分情况讨论：TCP和UDP和其他
    if(IPPROTO_TCP == socketFlow.socketProtocol){
        os_log(firewallLog ,"---- %{public}@ isTCPFlow----",flow.identifier);
         matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName remotePort:port protocol:@"tcp"];
        if(matchedRule && matchedRule.allow == NO){
            //有对应规则且规则中为阻塞，就把这个流过滤掉
            os_log(firewallLog, "==== firewallRule is matched : %{public}@ ",remoteHostName);
            return [NEFilterDataVerdict dropVerdict];
        }
    }else if(IPPROTO_UDP == socketFlow.socketProtocol){
        //分两种情况：DNS-UDP和其他UDP
        if([self isDNSFlow:flow]){
            os_log(firewallLog , "[ID : %{public}@ is DNS",flow.identifier);
        }else{
            os_log(firewallLog ,"---- %{public}@  isUDPFlow ----",flow.identifier);
            matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName remotePort:port protocol:@"udp"];
            if(matchedRule && matchedRule.allow == NO){
                os_log(firewallLog, "==== firewallRule is matched : %{public}@ ",remoteHostName);
                return [NEFilterDataVerdict dropVerdict];
            }
        }
    }
    return [NEFilterDataVerdict allowVerdict];
}

#pragma mark -- 判断是否是DNS流
- (BOOL)isDNSFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        return NO;
    }
    
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    NWEndpoint *remoteEndpoint = socketFlow.remoteEndpoint;
    
    // 检查是否是 host endpoint（排除 UNIX socket 等）
    if (![remoteEndpoint isKindOfClass:[NWHostEndpoint class]]) {
        return NO;
    }
    
    NWHostEndpoint *hostEndpoint = (NWHostEndpoint *)remoteEndpoint;
    NSString *port = hostEndpoint.port;
    
    // DNS 标准端口是 53（字符串 "53"）
    return [port isEqualToString:@"53"];
}

#pragma mark -- 处理入站的流
- (NEFilterDataVerdict *) handleInboundDataFromFlow:(NEFilterFlow *) flow
                                readBytesStartOffset:(NSUInteger) offset
                                           readBytes:(NSData *) readBytes{
    NEFilterSocketFlow* socketFlow = (NEFilterSocketFlow*)flow;
    NSString* remoteHostName = nil;
    NWHostEndpoint* remoteEP = socketFlow.remoteEndpoint;
    //1.获取远程IP
    remoteHostName = remoteEP.hostname;
    NSString* port = remoteEP.port;
    os_log(firewallLog , "---- %{public}@ socket remoteEP ip Name:%{public}@ is not nil " , flow.identifier , remoteHostName);
    
    //2.进行入站匹配
    NSDate *currentDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    NSString *currentTimeString = [dateFormatter stringFromDate:currentDate];
    
    //3. 打印流ID和当前时间
    os_log(firewallLog , "Flow ID: %{public}@, Time: %{public}@ ", flow.identifier, currentTimeString);
    
    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    
    FirewallRule * rule = nil;
    //4. 判断协议
    if(IPPROTO_TCP == socketFlow.socketProtocol){
        os_log(firewallLog , "---socketFlow[%{public}@] is a tcp flow---",flow.identifier);
        rule = [manager firstMatchedRuleForInBound:remoteHostName localPort:port protocol:@"tcp"];
    } else if (IPPROTO_UDP == socketFlow.socketProtocol) {
        // 入站 UDP：可能是 DNS 响应
        if ([self isDNSResponseWithData:readBytes]) {
            os_log(firewallLog, "---socketFlow[%{public}@] is a DNS RESPONSE---", flow.identifier);
            
            // 异步解析 DNS，不阻塞当前线程
            NSData *dnsDataCopy = [readBytes copy]; // 防止原 data 被释放
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                @autoreleasepool {
                    [self parseDNSResponse:dnsDataCopy forFlow:flow];
                }
            });
            return [NEFilterDataVerdict allowVerdict];
        } else {
            os_log(firewallLog, "---socketFlow[%{public}@] is a UDP flow---", flow.identifier);
            rule = [manager firstMatchedRuleForInBound:remoteHostName localPort:port protocol:@"udp"];
        }
    }else{
        os_log(firewallLog , "===the flow[%{public}@] is not network flow===",flow.identifier);
    }
    if(rule && rule.allow == NO){
        return [NEFilterDataVerdict dropVerdict];
    }
    return [NEFilterDataVerdict allowVerdict];
}

#pragma mark -- 判断是否是DNS response报文
- (BOOL)isDNSResponseWithData:(NSData *)data {
    if (data.length < 12) {
        return NO; // DNS header 至少 12 字节
    }
    
    const uint8_t *bytes = [data bytes];
    uint8_t flagsByte = bytes[2]; // 第 3 个字节（索引从 0 开始）
    
    // QR 位是 flagsByte 的最高位（bit 7）
    BOOL isResponse = (flagsByte & 0x80) != 0; // 0x80 = 1000 0000
    
    return isResponse;
}

#pragma mark -- 解析 DNS Response，提取域名和IP映射
- (void)parseDNSResponse:(NSData *)data forFlow:(NEFilterFlow *)flow {
    //1.跳过DNS头部
    if (data.length < 12) return;
    
    const uint8_t *bytes = (const uint8_t *)[data bytes];
    //2.读取QDcount和ANCount数量，由网络字节序转为主机序
    uint16_t qdCount = ntohs(*(uint16_t*)(bytes + 4));  // Questions count
    uint16_t anCount = ntohs(*(uint16_t*)(bytes + 6));  // Answers count
    if (qdCount == 0 || anCount == 0) {
        os_log(firewallLog, "DNS response has no question or answer");
        return;
    }
    
    // Step 1: 解析 Question -> 获取原始域名
    //从偏移12开始，开始读取域名
    NSString *queryDomain = [self parseDomainFromDNSAtOffset:&bytes[12] data:data startOffset:12];
    if (!queryDomain || queryDomain.length == 0) {
        os_log(firewallLog, "Failed to parse query domain in DNS response");
        return;
    }
    
    // Step 2: 跳过 Question Section（每个 Question = QNAME + QTYPE(2) + QCLASS(2)）
    NSUInteger offset = 12;
    NSString *dummy = [self parseDomainFromDNSAtOffset:&bytes[offset] data:data startOffset:offset];
    if (!dummy) return;
    // 计算实际跳过的字节数（需重新解析以获取长度）
    NSUInteger questionEnd = [self getDomainLengthAtOffset:offset data:data];
    if (questionEnd == NSNotFound) return;
    offset = questionEnd + 4; // +4 for QTYPE + QCLASS
    
    // Step 3: 遍历 Answer Section
    for (int i = 0; i < anCount && offset < data.length; i++) {
        // 跳过 NAME（可能是压缩指针）
        NSUInteger nameStart = offset;
        NSString *name = [self parseDomainFromDNSAtOffset:&bytes[offset] data:data startOffset:offset];
        if (!name) break;
        NSUInteger nameEnd = [self getDomainLengthAtOffset:nameStart data:data];
        if (nameEnd == NSNotFound) break;
        
        if (offset + (nameEnd - nameStart) + 10 > data.length) break; // 至少还有 TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
        
        uint16_t type = ntohs(*(uint16_t*)(bytes + nameEnd + 0));
        // uint16_t class = ntohs(*(uint16_t*)(bytes + nameEnd + 2));
        // uint32_t ttl = ntohl(*(uint32_t*)(bytes + nameEnd + 4));
        uint16_t rdlength = ntohs(*(uint16_t*)(bytes + nameEnd + 8));
        const uint8_t *rdata = &bytes[nameEnd + 10];
        
        if (type == 1 && rdlength == 4) { // A record (IPv4)
            struct in_addr addr;
            memcpy(&addr, rdata, 4);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
            NSString *ip = [NSString stringWithCString:ipStr encoding:NSUTF8StringEncoding];
            
            os_log(firewallLog, "[DNS Cache] %{public}@ → %{public}@", queryDomain, ip);
            
            // 存入全局缓存（假设你有 DomainIPCache 单例）
            [[DomainIPCache sharedCache] addMappingForDomain:queryDomain ip:ip];
            
        } else if (type == 28 && rdlength == 16) { // AAAA record (IPv6)
            struct in6_addr addr6;
            memcpy(&addr6, rdata, 16);
            char ip6Str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6, ip6Str, INET6_ADDRSTRLEN);
            NSString *ip6 = [NSString stringWithCString:ip6Str encoding:NSUTF8StringEncoding];
            os_log(firewallLog, "[DNS Cache] %{public}@ → %{public}@", queryDomain, ip6);
            [[DomainIPCache sharedCache] addMappingForDomain:queryDomain ip:ip6];
        }
        
        // 移动到下一个 RR
        offset = nameEnd + 10 + rdlength;
    }
}

- (NSString *)parseDomainFromDNSAtOffset:(const uint8_t *)start data:(NSData *)data startOffset:(NSUInteger)startOffset {
    NSMutableString *domain = [NSMutableString string];
    const uint8_t *bytes = (const uint8_t *)[data bytes];
    NSUInteger offset = startOffset;
    int jumps = 0;
    const int maxJumps = 5;
    
    while (offset < data.length && jumps < maxJumps) {
        uint8_t len = bytes[offset];
        if (len == 0) {
            break; // end of name
        }
        
        if ((len & 0xC0) == 0xC0) {
            // Compressed pointer
            if (offset + 1 >= data.length) return nil;
            uint16_t pointer = ((len & 0x3F) << 8) | bytes[offset + 1];
            if (pointer >= data.length) return nil;
            offset = pointer;
            jumps++;
            continue;
        }
        
        if (offset + 1 + len > data.length) return nil;
        
        NSString *label = [[NSString alloc] initWithBytes:&bytes[offset + 1]
                                                  length:len
                                                encoding:NSASCIIStringEncoding]; // DNS labels are ASCII
        if (!label) return nil;
        
        if (domain.length > 0) [domain appendString:@"."];
        [domain appendString:label];
        
        offset += 1 + len;
    }
    
    return domain.length > 0 ? [domain copy] : nil;
}

- (NSUInteger)getDomainLengthAtOffset:(NSUInteger)offset data:(NSData *)data {
    const uint8_t *bytes = (const uint8_t *)[data bytes];
    NSUInteger originalOffset = offset;
    int jumps = 0;
    const int maxJumps = 5;
    
    while (offset < data.length && jumps < maxJumps) {
        uint8_t len = bytes[offset];
        if (len == 0) {
            return offset + 1; // include the zero byte
        }
        if ((len & 0xC0) == 0xC0) {
            // Pointer: consumes 2 bytes at current position
            return originalOffset + 2;
        }
        if (offset + 1 + len > data.length) {
            return NSNotFound;
        }
        offset += 1 + len;
    }
    return NSNotFound;
}
@end

    
    
