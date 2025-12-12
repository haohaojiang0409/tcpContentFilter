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
@interface AppFilterProvider(){
    BOOL hasReceivedInitialLoad;
}
@property (nonatomic, strong) RulePollingManager *rulePollingManager;
@end
@implementation AppFilterProvider
#pragma mark - 加载过滤配置
- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    Logger *log = [Logger sharedLogger];
    [log info:@"-------[startFilterWithCompletionHandler] is started------"];

    NSURL *ruleURL = [NSURL URLWithString:@"https://sp.pre.eagleyun.cn/api/agent/v1/edr/firewall_policy/get_firewall_detail_config"];
    self.rulePollingManager = [[RulePollingManager alloc] initWithURL:ruleURL];
    
    // 加载初始规则
    [self loadInitialRulesWithCompletion:^(NSError *error) {
        //如果通过网络初始化规则就加载本地规则
        if (error) {
            [[Logger sharedLogger] info:@"Failed to load initial rules: %@", error.localizedDescription];
            [self tryLoadCachedRules]; // fallback 到本地
        } else {
            [[Logger sharedLogger] info:@"Initial rules loaded successfully"];
        }
        
        // 应用过滤设置
        [self applyFilterSettingsWithCompletion:completionHandler];

        // 启动定期轮询（注意：不要在 completionHandler 内部启动，避免阻塞）
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [self.rulePollingManager startPolling];
        });
    }];
}

#pragma mark - 加载规则
- (void)loadInitialRulesWithCompletion:(void(^)(NSError *error))completion {
    
    //避免重复调用
    if (hasReceivedInitialLoad) {
        completion(nil);
        return;
    }

    //信号量初始化
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSError *loadError = nil;

    // 设置回调函数
    self.rulePollingManager.onJSONReceived = ^(NSDictionary<NSString *, id> *json) {
        @autoreleasepool {
            // 确保只处理一次
            BOOL success = NO;
            if (json && [json isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dataDict = json[@"data"];
                NSArray *rawRules = dataDict ? dataDict[@"rules"] : nil;
                
                if ([rawRules isKindOfClass:[NSArray class]] && rawRules.count > 0) {
                    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
                    [manager removeAllRules];
                    
                    NSUInteger total = 0;
                    for (NSDictionary *rawRule in rawRules) {
                        NSArray<FirewallRule *> *rules = [FirewallRule rulesWithDictionary:rawRule];
                        for (FirewallRule *rule in rules) {
                            [manager addRule:rule];
                            total++;
                        }
                    }
                    [[Logger sharedLogger] info:@"Loaded %lu firewall rule objects", (unsigned long)total];
                    success = YES;
                } else {
                    loadError = [NSError errorWithDomain:@"RuleLoadError" code:-2
                               userInfo:@{NSLocalizedDescriptionKey:@"No rules in 'data.rules'"}];
                    [[Logger sharedLogger] info:@"No rules in 'data.rules'"];
                }
            } else {
                loadError = [NSError errorWithDomain:@"RuleLoadError" code:-1
                           userInfo:@{NSLocalizedDescriptionKey:@"Invalid or empty JSON response"}];
                [[Logger sharedLogger] info:@"Rules JSON is invalid or empty"];
            }
            //发送信号
            dispatch_semaphore_signal(semaphore);
        }
    };

    // 发起首次请求
    [self.rulePollingManager fetchOnce];

    // 等待最多 10 秒
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
        // 超时
        loadError = [NSError errorWithDomain:@"RuleLoadError" code:-3
                   userInfo:@{NSLocalizedDescriptionKey:@"Initial rule load timeout"}];
        [[Logger sharedLogger] error:@"Initial rule load timeout"];
    }

    completion(loadError);
}

#pragma mark -- 应用过滤设置
-(void)applyFilterSettingsWithCompletion:(void(^)(NSError * _Nullable))completionHandler{
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
        [self applySettings:filterSettings completionHandler:completionHandler];
}

#pragma mark -- 停止过滤
- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"Packet filter stopped: %ld", (long)reason);
    if (self.rulePollingManager) {
        [self.rulePollingManager stopPolling];
        self.rulePollingManager = nil;
    }

    completionHandler();
}

- (void)allowPacket:(NEPacket *)packet{
    
}

#pragma mark - 处理新到来的流
//1.建立连接之前还是之后：建立连接之前
//2.扩展截获的是发往所有网卡的数据包？可以选，默认所有网卡
//3.IPPROTO_UDP 和 NENetworkRuleProtocolUDP的区别？ 前者是应用于socket层，后者应用于IP层
- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if([self isOwnFlow:flow]){
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        [[Logger sharedLogger] info:@"[FLOW] Non-socket flow, allowing."];
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    // 标记所有流都要数据
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO peekInboundBytes:0 filterOutbound:YES peekOutboundBytes:1024];
}

#pragma mark -- 判断是否自己的流
-(BOOL)isOwnFlow:(NEFilterFlow *)flow{
    NSString * ownBundleID = @"com.eagleyun.BorderControl.Network";
    return [ownBundleID isEqualToString:flow.description];
}

#pragma mark -- 处理出站的所有流
///建立连接之前就可以获取到流
- (NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow
                                readBytesStartOffset:(NSUInteger)offset
                                           readBytes:(NSData *)readBytes {
    [[Logger sharedLogger] info:@"handleOutboundDataCompleteForFlow"];
    // 获取当前时间
    NSDate *currentDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    NSString *currentTimeString = [dateFormatter stringFromDate:currentDate];
    
    // 打印流ID和当前时间
    [[Logger sharedLogger] info:@"Flow ID: %@, Time: %@ " , flow.identifier , currentTimeString];
    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    NEFilterSocketFlow* socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint* remoteEP = socketFlow.remoteEndpoint;
    NSString* remoteHostName = nil;
    NSString* port = 0;

    //1.获取远程主机名
    //从URL获取主机名
    if(nil != socketFlow.URL.host){
        remoteHostName = socketFlow.URL.host;
//        os_log(firewallLog ,"---- %{public}@ socket URL host:%{public}@ is not nil" , flow.identifier , remoteHostName);
    }//从flow中获取主机名
    else if(nil != socketFlow.remoteHostname){
        remoteHostName = socketFlow.remoteHostname;
//        os_log(firewallLog ,"---- %{public}@ socket remoteHost Name:%{public}@ is not nil " , flow.identifier , remoteHostName);
    }//获取ip地址
    else if(nil != remoteEP.hostname){
        remoteHostName = remoteEP.hostname;
        [[Logger sharedLogger] info:@"%@ remoteEP hostname:%@is not nil" , flow.identifier , remoteHostName];
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
            [[Logger sharedLogger] info:@"the %@ is a ipv4 addresss and hostName is %@" , remoteHostName, domainName];
        }else{
            [[Logger sharedLogger] info:@"the %@ has no domain in cache" , remoteHostName];
        }
    }
    
    //获取进程信息
    NSData* processData = flow.sourceProcessAuditToken;
    Process* process = [[Process alloc] initWithFlowMetadata:flow.sourceProcessAuditToken];
    
    //分情况讨论：TCP和UDP和其他
    if(IPPROTO_TCP == socketFlow.socketProtocol){
        [[Logger sharedLogger] info:@"---- %@ isTCPFlow----" , flow.identifier];
        matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName remotePort:port protocol:@"tcp" process:process];
        if(matchedRule && matchedRule.allow == NO){
            //有对应规则且规则中为阻塞，就把这个流过滤掉
            [[Logger sharedLogger] info:@"firewallRule is matched : %@ " , remoteHostName];
            return [NEFilterDataVerdict dropVerdict];
        }
    } else if (IPPROTO_UDP == socketFlow.socketProtocol) {

        if ([self isDNSFlow:flow]) {
            [[Logger sharedLogger] info:@"[ID : %@ is DNS", flow.identifier];
        } else {
            [[Logger sharedLogger] info:@"---- %@ is UDPFlow ----", flow.identifier];
            matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName
                                                  remotePort:port
                                                    protocol:@"udp"
                                                     process:process];
            if (matchedRule && !matchedRule.allow) {
                [[Logger sharedLogger] info:@"==== firewallRule is matched : %@ ====", remoteHostName];
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
- (NEFilterDataVerdict *)handleInboundDataFromFlow:(NEFilterFlow *)flow
                              readBytesStartOffset:(NSUInteger)offset
                                         readBytes:(NSData *)readBytes {
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    NSString *remoteHostName = nil;
    NWHostEndpoint *remoteEP = socketFlow.remoteEndpoint;
    
    // 1. 获取远程 IP
    remoteHostName = remoteEP.hostname;
    NSString *port = remoteEP.port;
    [[Logger sharedLogger] info:[NSString stringWithFormat:@"---- %@ socket remoteEP ip Name: %@ is not nil", flow.identifier, remoteHostName]];
    
    // 2. 进行入站匹配
    NSDate *currentDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    NSString *currentTimeString = [dateFormatter stringFromDate:currentDate];
    
    // 3. 打印流 ID 和当前时间
    [[Logger sharedLogger] info:@"Flow ID: %@, Time: %@", flow.identifier, currentTimeString];
    
    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    FirewallRule *rule = nil;
    
    // 获取进程信息
    NSData *processData = flow.sourceProcessAuditToken;
    Process *process = [[Process alloc] initWithFlowMetadata:flow.sourceProcessAuditToken];
    ProcessRule *_processRule = [ProcessRule ruleWithProcess:process];
    
    // 4. 判断协议
    if (IPPROTO_TCP == socketFlow.socketProtocol) {
        [[Logger sharedLogger] info:@"---socketFlow[%@] is a tcp flow---", flow.identifier];
        rule = [manager firstMatchedRuleForInBound:remoteHostName localPort:port protocol:@"tcp" process:_processRule];
    } else if (IPPROTO_UDP == socketFlow.socketProtocol) {
        // 入站 UDP：可能是 DNS 响应
        if ([self isDNSResponseWithData:readBytes]) {
            [[Logger sharedLogger] info:@"---socketFlow[%@] is a DNS RESPONSE---", flow.identifier];
            
            // 异步解析 DNS，不阻塞当前线程
            NSData *dnsDataCopy = [readBytes copy];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                @autoreleasepool {
                    [self parseDNSResponse:dnsDataCopy forFlow:flow];
                }
            });
            return [NEFilterDataVerdict allowVerdict];
        } else {
            [[Logger sharedLogger] info:@"---socketFlow[%@] is a UDP flow---", flow.identifier];
            rule = [manager firstMatchedRuleForInBound:remoteHostName localPort:port protocol:@"udp" process:process];
        }
    } else {
        [[Logger sharedLogger] info:@"===the flow[%@] is not network flow===", flow.identifier];
    }
    
    if (rule && !rule.allow) {
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
    // 1. 跳过 DNS 头部
    if (data.length < 12) return;
    
    const uint8_t *bytes = (const uint8_t *)[data bytes];
    // 2. 读取 QDcount 和 ANCount 数量，由网络字节序转为主机序
    uint16_t qdCount = ntohs(*(uint16_t *)(bytes + 4));  // Questions count
    uint16_t anCount = ntohs(*(uint16_t *)(bytes + 6));  // Answers count
    if (qdCount == 0 || anCount == 0) {
        [[Logger sharedLogger] info:@"DNS response has no question or answer"];
        return;
    }
    
    // Step 1: 解析 Question -> 获取原始域名
    NSString *queryDomain = [self parseDomainFromDNSAtOffset:&bytes[12] data:data startOffset:12];
    if (!queryDomain || queryDomain.length == 0) {
        [[Logger sharedLogger] info:@"Failed to parse query domain in DNS response"];
        return;
    }
    
    // Step 2: 跳过 Question Section（每个 Question = QNAME + QTYPE(2) + QCLASS(2)）
    NSUInteger offset = 12;
    NSString *dummy = [self parseDomainFromDNSAtOffset:&bytes[offset] data:data startOffset:offset];
    if (!dummy) return;
    NSUInteger questionEnd = [self getDomainLengthAtOffset:offset data:data];
    if (questionEnd == NSNotFound) return;
    offset = questionEnd + 4; // +4 for QTYPE + QCLASS
    
    // Step 3: 遍历 Answer Section
    for (int i = 0; i < anCount && offset < data.length; i++) {
        NSUInteger nameStart = offset;
        NSString *name = [self parseDomainFromDNSAtOffset:&bytes[offset] data:data startOffset:offset];
        if (!name) break;
        NSUInteger nameEnd = [self getDomainLengthAtOffset:nameStart data:data];
        if (nameEnd == NSNotFound) break;
        
        if (offset + (nameEnd - nameStart) + 10 > data.length) break;
        
        uint16_t type = ntohs(*(uint16_t *)(bytes + nameEnd + 0));
        uint16_t rdlength = ntohs(*(uint16_t *)(bytes + nameEnd + 8));
        const uint8_t *rdata = &bytes[nameEnd + 10];
        
        if (type == 1 && rdlength == 4) { // A record (IPv4)
            struct in_addr addr;
            memcpy(&addr, rdata, 4);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
            NSString *ip = [NSString stringWithCString:ipStr encoding:NSUTF8StringEncoding];
            
            [[Logger sharedLogger] info:@"[DNS Cache] %@ → %@", queryDomain, ip];
            [[DomainIPCache sharedCache] addMappingForDomain:queryDomain ip:ip];
            
        } else if (type == 28 && rdlength == 16) { // AAAA record (IPv6)
            struct in6_addr addr6;
            memcpy(&addr6, rdata, 16);
            char ip6Str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6, ip6Str, INET6_ADDRSTRLEN);
            NSString *ip6 = [NSString stringWithCString:ip6Str encoding:NSUTF8StringEncoding];
            [[Logger sharedLogger] info:@"[DNS Cache] %@ → %@", queryDomain, ip6];
            [[DomainIPCache sharedCache] addMappingForDomain:queryDomain ip:ip6];
        }
        
        // 移动到下一个 RR
        offset = nameEnd + 10 + rdlength;
    }
}
#pragma mark -- 解析DNS报文
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

#pragma mark - 加载本地规则兜底
- (void)tryLoadCachedRules {
    // 构建本地规则文件路径
    NSString *jsonPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"rule" ofType:@"json"];
    if (!jsonPath) {
        [[Logger sharedLogger] error:@"Local rule.json not found in bundle path: %@" , jsonPath];
        return;
    }
    
    // 读取 JSON 文件
    NSData *jsonData = [NSData dataWithContentsOfFile:jsonPath];
    if (!jsonData) {
        [[Logger sharedLogger] error:@"Failed to read local rule.json file"];
        return;
    }
    
    // 解析 JSON
    NSError *jsonError = nil;
    NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData
                                                             options:0
                                                               error:&jsonError];
    if (jsonError || ![jsonDict isKindOfClass:[NSDictionary class]]) {
        [[Logger sharedLogger] error:@"%@", [NSString stringWithFormat:@"Failed to parse local rule.json: %@", jsonError.localizedDescription]];
        return;
    }
    
    // 解析并加载规则（与网络加载逻辑相同）
    NSDictionary *dataDict = jsonDict[@"data"];
    NSArray *rawRules = dataDict[@"rules"];
    
    if (![rawRules isKindOfClass:[NSArray class]] || rawRules.count == 0) {
        [[Logger sharedLogger] info:@"No rules in local rule.json 'data.rules'"];
        return;
    }
    
    // 获取规则管理器并加载规则
    FirewallRuleManager *rulesManager = [FirewallRuleManager sharedManager];
    [rulesManager removeAllRules]; // 清空现有规则
    
    NSUInteger total = 0;
    for (NSDictionary *rawRule in rawRules) {
        NSArray<FirewallRule *> *rules = [FirewallRule rulesWithDictionary:rawRule];
        for (FirewallRule *rule in rules) {
            [rulesManager addRule:rule];
            total++;
        }
    }
    
    [[Logger sharedLogger] info:@"%@", [NSString stringWithFormat:@"Loaded %lu rules from local cache", (unsigned long)total]];
}
@end

    
    
