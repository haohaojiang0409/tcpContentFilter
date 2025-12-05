//
//  Rule.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/21.
//

#import "Rule.h"
#pragma mark - 复合键规则类 out udp 会转化为 out_udp
@implementation RuleCompositeKeyGenerator
+ (NSString *)compositeKeyWithDirection:(NSString *)direction protocol:(NSString *)protocol {
    // 统一格式（方向小写，协议小写），避免大小写导致的键不唯一
    NSString *lowerDir = [direction lowercaseString];
    NSString *lowerProto = [protocol lowercaseString];
    // 格式：方向_协议（如 "out_tcp"、"in_udp"）
    return [NSString stringWithFormat:@"%@_%@", lowerDir, lowerProto];
}

+ (NSDictionary<NSString *, NSString *> *)parseDirectionAndProtocolFromCompositeKey:(NSString *)compositeKey {
    NSArray *parts = [compositeKey componentsSeparatedByString:@"_"];
    if (parts.count != 2) return nil;
    return @{
        @"direction": parts[0],
        @"protocol": parts[1]
    };
}
@end

///ip和域名存储类
@implementation fiveINetTuple

- (instancetype)initWithIpStart:(uint32_t)ipStart
                         ipEnd:(uint32_t)ipEnd
                     portStart:(uint16_t)portStart
                       portEnd:(uint16_t)portEnd
                      hostName:(NSString *)hostName {
    if (self = [super init]) {
        _ipStart = ipStart;
        _ipEnd = ipEnd;
        _portStart = portStart;
        _portEnd = portEnd;
        _hostName = [hostName copy];
    }
    return self;
}
@end

///防火墙具体规则类
@implementation FirewallRule

- (instancetype)init {
    // 提供一个安全的默认初始化（虽然通常应使用指定初始化器）
    return [self initWithDirection:FlowDirectionOutbound
                          protocol:@[]
                       fiveTuples:@[]
                      processName:nil
                      processPath:nil
                    developerName:nil
                            allow:YES];
}

- (instancetype)initWithDirection:(FlowDirection)direction
                         protocol:(NSArray<NSNumber *> *)protocolTypes // 建议参数名与属性一致
                     fiveTuples:(NSArray<fiveINetTuple *> *)fiveTuples
                    processName:(nullable NSString *)processName
                    processPath:(nullable NSString *)processPath
                  developerName:(nullable NSString *)developerName
                          allow:(BOOL)allow {
    if (self = [super init]) {
        _direction = direction;
        _protocolTypes = [protocolTypes copy]; // 强制 copy
        _fiveTuples = [fiveTuples copy];
        _processName = processName;
        _processPath = processPath;
        _developerName = developerName;
        _allow = allow;
    }
    return self;
}


- (BOOL)isDNSRule {
    return YES;
}

+ (NSArray<FirewallRule *> *)rulesWithDictionary:(NSDictionary *)dict {
    // 1. 解析 direction
    NSString *dirStr = dict[@"direction"];
    if (![dirStr isEqualToString:@"out"] && ![dirStr isEqualToString:@"in"]) {
        NSLog(@"[RULE PARSE] Invalid direction: %@", dirStr ?: @"(null)");
        return @[];
    }
    FlowDirection direction = [dirStr isEqualToString:@"out"] ? FlowDirectionOutbound : FlowDirectionInbound;
    NSString *dirLog = (direction == FlowDirectionOutbound) ? @"OUT" : @"IN";

    // 2. 解析 action
    NSString *action = dict[@"action"];
    BOOL allow = [action isEqualToString:@"pass"]; // "block" → NO
    NSString *actionLog = allow ? @"PASS" : @"BLOCK";

    // 3. 解析元数据
    NSString *policyName = dict[@"policy_name"] ?: @"(unnamed)";
    NSString *policyId = dict[@"policy_id"] ?: @"(no-id)";

    // 4. 解析协议
    NSMutableArray<NSNumber *> *protocolTypes = [NSMutableArray array];
    NSString *protoStr = dict[@"proto"];
    if ([protoStr isKindOfClass:[NSString class]]) {
        NSArray<NSString *> *protoList = [protoStr componentsSeparatedByString:@"|"];
        for (NSString *p in protoList) {
            if ([p isEqualToString:@"tcp"]) {
                [protocolTypes addObject:@(TransportProtocolTCP)];
            } else if ([p isEqualToString:@"udp"]) {
                [protocolTypes addObject:@(TransportProtocolUDP)];
            } else if ([p isEqualToString:@"icmp"]) {
                [protocolTypes addObject:@(TransportProtocolICMP)];
            }
        }
    }
    if (protocolTypes.count == 0) {
        NSLog(@"[RULE PARSE] ❌ No valid protocols in rule (proto: %@)", protoStr ?: @"(null)");
        return @[];
    }

    // 协议转字符串用于日志
    NSMutableArray<NSString *> *protoLogs = [NSMutableArray array];
    for (NSNumber *protoNum in protocolTypes) {
        TransportProtocol p = [protoNum integerValue];
        if (p == TransportProtocolTCP) [protoLogs addObject:@"TCP"];
        else if (p == TransportProtocolUDP) [protoLogs addObject:@"UDP"];
        else if (p == TransportProtocolICMP) [protoLogs addObject:@"ICMP"];
    }
    NSString *protoSummary = [protoLogs componentsJoinedByString:@", "];

    // 5. 解析五元组
    NSMutableArray<fiveINetTuple *> *tuples = [NSMutableArray array];
    NSArray *rawTuples = dict[@"tuples"];
    if ([rawTuples isKindOfClass:[NSArray class]]) {
        for (NSDictionary *t in rawTuples) {
            NSString *host = t[@"dst_host"] ?: @"";
            NSLog(@"hostName : %@",host);
            NSArray *ports = t[@"dst_port"];
            if (![ports isKindOfClass:[NSArray class]]) continue;
            uint32_t ipStart = 0, ipEnd = 0;
            uint32_t ip = 0;
            if(direction == FlowDirectionOutbound){
                // 👇 解析 source_ip（单个 IP 字符串）
                NSString *ipStr = t[@"dst_ip"]; // 假设 JSON 中是字符串，如 "192.168.1.1"
                                    if ([ipStr isKindOfClass:[NSString class]] && ipStr.length > 0) {
                    //将ipv4地址转为数字进行比较
                    ip = ipv4StringToUInt32(ipStr);
                    if (ip != 0 || [ipStr isEqualToString:@"0.0.0.0"]) {
                        // 特别处理 "0.0.0.0"：ipv4StringToUInt32("0.0.0.0") 返回 0，但它是合法的
                        ipStart = ipEnd = ip;
                        NSLog(@"outBound rule --- ip address : %@:%u",ipStr,ip);
                    } else {
                        NSLog(@"[RULE PARSE] ⚠️ Invalid dst_ip: %@", ipStr);
                        continue; // 可选：跳过整个 tuple，或当作 0.0.0.0-255.255.255.255？
                    }
                }
            }else if(direction == FlowDirectionInbound){
                NSString* ipStr = t[@"source_ip"];
                //将ipv4地址转为数字进行比较
                ip = ipv4StringToUInt32(ipStr);
                if (ip != 0 || [ipStr isEqualToString:@"0.0.0.0"]) {
                    // 特别处理 "0.0.0.0"：ipv4StringToUInt32("0.0.0.0") 返回 0，但它是合法的
                    ipStart = ipEnd = ip;
                    NSLog(@"inBound rule --- ip address : %@",ipStr);
                } else {
                    NSLog(@"[RULE PARSE] ⚠️ Invalid source_ip: %@", ipStr);
                    continue; // 可选：跳过整个 tuple，或当作 0.0.0.0-255.255.255.255？
                }
            }
            for (NSString *portSpec in ports) {
                uint16_t start, end;
                if ([portSpec containsString:@"-"]) {
                    NSArray *parts = [portSpec componentsSeparatedByString:@"-"];
                    if (parts.count == 2) {
                        start = (uint16_t)[parts[0] integerValue];
                        end = (uint16_t)[parts[1] integerValue];
                    } else {
                        continue;
                    }
                } else {
                    start = end = (uint16_t)[portSpec integerValue];
                }
                fiveINetTuple *tuple = [[fiveINetTuple alloc]
                    initWithIpStart:ipStart
                           ipEnd:ipEnd
                       portStart:start
                         portEnd:end
                       hostName:host];
                [tuples addObject:tuple];
            }
        }
    }

    if (tuples.count == 0) {
        NSLog(@"[RULE PARSE] ⚠️ Rule has no valid tuples (policy: %@)", policyName);
    }

    // 6. 创建规则
    FirewallRule *rule = [[FirewallRule alloc]
        initWithDirection:direction
                 protocol:protocolTypes
             fiveTuples:tuples
            processName:nil
            processPath:nil
          developerName:nil
                  allow:allow];

    // 7. 设置元数据
    rule.policyName = policyName;
    rule.policyId = policyId;
    rule.level = [dict[@"level"] integerValue];
    rule.shouldReport = [[dict objectForKey:@"report"] boolValue];
    rule.localizedTitle = dict[@"chinese"][@"title"];
    rule.localizedSuggestion = dict[@"chinese"][@"suggestion"];
    return @[rule];
}

@end
///规则管理类
@implementation FirewallRuleManager

+ (instancetype)sharedManager {
    static FirewallRuleManager *instance = nil;
    static dispatch_once_t onceToken;
    //保证多线程下数据一致性
    dispatch_once(&onceToken, ^{
        instance = [[FirewallRuleManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    //初始化内部数据结构
    if (self = [super init]) {
        _ruleGroups = [NSMutableDictionary dictionary];
        //初始化ip映射域名字典
        _ipToHostnamesMap = [[NSMutableDictionary alloc] init];
        _syncQueue = dispatch_queue_create("com.bordercontrol.rulemanager.sync", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)addRule:(FirewallRule *)rule {
    dispatch_sync(self.syncQueue, ^{
        for (NSNumber *protoNum in rule.protocolTypes) {
            TransportProtocol proto = (TransportProtocol)[protoNum unsignedIntegerValue];
            
            NSString *dirStr = (rule.direction == FlowDirectionOutbound) ? @"out" : @"in";
            NSString *protoStr = nil;
            switch (proto) {
                case TransportProtocolTCP:
                    protoStr = @"tcp";
                    break;
                case TransportProtocolUDP:
                    protoStr = @"udp";
                    break;
                case TransportProtocolICMP:
                    protoStr = @"icmp";
                    break;
                default:
                    continue; // 跳过无效协议
            }
            
            NSString *key = [RuleCompositeKeyGenerator compositeKeyWithDirection:dirStr protocol:protoStr];
            NSMutableArray<FirewallRule *> *group = self.ruleGroups[key];
            if (!group) {
                group = [NSMutableArray array];
                self.ruleGroups[key] = group;
            }
            // 🔽 按 level 降序插入（高优先级在前）
            NSInteger insertIndex = [self indexOfInsertionForRule:rule inSortedArray:group];
            NSLog(@"insertIndex : %ld level of rule : %ld" , (long)insertIndex , (long)rule.level);
            [group insertObject:rule atIndex:insertIndex];
        }
    });
}

//二分插入
- (NSInteger)indexOfInsertionForRule:(FirewallRule *)newRule
                      inSortedArray:(NSArray<FirewallRule *> *)sortedArray {
    NSInteger low = 0;
    NSInteger high = sortedArray.count;
    
    while (low < high) {
        NSInteger mid = low + (high - low) / 2;
        FirewallRule *midRule = sortedArray[mid];
        
        if (newRule.level < midRule.level) {
            high = mid; // 新规则优先级更高（数字更小），应插在前面
        } else {
            low = mid + 1;
        }
    }
    return low;
}


- (void)removeAllRules {
    dispatch_sync(self.syncQueue, ^{
        [self.ruleGroups removeAllObjects];
    });
}


- (NSArray<FirewallRule *> *)rulesForDirection:(FlowDirection)_direction
                                      protocol:(NSString*)_protocol {
    NSString *dirStr = (_direction == FlowDirectionOutbound) ? @"out" : @"in";
    NSString *key = [RuleCompositeKeyGenerator compositeKeyWithDirection:dirStr protocol:_protocol];
    
    __block NSArray<FirewallRule *> *result = @[];
    dispatch_sync(self.syncQueue, ^{
        result = [self.ruleGroups[key] copy] ?: @[];
    });
    return result;
}

//返回所有规则列表
- (NSArray<FirewallRule *> *)allRules {
    __block NSMutableSet<FirewallRule *> *uniqueRules = [NSMutableSet set];
    dispatch_sync(self.syncQueue, ^{
        for (NSArray<FirewallRule *> *group in [self.ruleGroups allValues]) {
            [uniqueRules addObjectsFromArray:group];
        }
    });
    return [uniqueRules allObjects];
}

///出站判断函数，出站可匹配ip地址，可匹配域名
-(FirewallRule*)firstMatchedRuleForOutBound:(NSString*)_remoteHostName
                                 remotePort:(NSString*)_remotePort
                                   protocol:(NSString*)_Protocol{
    // 1. 获取该 direction + protocol 下的所有规则
    NSArray<FirewallRule *> *candidateRules = [self rulesForDirection:FlowDirectionOutbound protocol:_Protocol];
    if (candidateRules.count == 0) {
        NSLog(@"firstMatchedRuleForHostname : candidataeRules is nil");
        return nil;
    }else{
        NSLog(@"the number of rules is : %lu",(unsigned long)candidateRules.count);
    }
    //2.判断是否是IPV4地址,出站只获取远端域名/ip和远端端口即可
    BOOL isIPv4 = NO;
    if (_remoteHostName.length > 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, [_remoteHostName UTF8String], &addr) == 1) {
            isIPv4 = YES;
        }
    }
    //2.开始逐个判断
    for(FirewallRule* rule in candidateRules){
        BOOL isMatched = NO;
        // 3.出站：检查每个 fiveTuple 的 hostName 和 remotePort 是否在范围内
        for (fiveINetTuple *tuple in rule.fiveTuples) {
            // 端口匹配：remotePort ∈ [portStart, portEnd]
            NSUInteger remotePort = [_remotePort integerValue];
            NSLog(@"remote port :%lu , tuplestart : %hu , tupleend : %hu",(unsigned long)remotePort , tuple.portStart , tuple.portEnd);
            if (remotePort < tuple.portStart || remotePort > tuple.portEnd) {
                NSLog(@"port is not in range");
                continue;
            }
            // 主机名匹配（支持 nil 表示任意）
            if(!isIPv4){
                if ([tuple.hostName isEqualToString:_remoteHostName]) {
                    isMatched = YES;
                    NSLog(@"hostname is matched");
                    break;
                }else{
                    NSLog(@"hostname is not matched and tuple.hostName : %@ != %@", tuple.hostName , _remoteHostName);
                }
            }else {
                // IPv4 匹配
                uint32_t remoteIp = ipv4StringToUInt32(_remoteHostName);
                if (tuple.ipStart == 0 && tuple.ipEnd == 0) {
                    // 规则未指定 IP 范围 → 匹配任意 IP
                    isMatched = YES;
                    NSLog(@"IP wildcard (0.0.0.0-0.0.0.0) matched for %@", _remoteHostName);
                    break;
                }else if (remoteIp >= tuple.ipStart && remoteIp <= tuple.ipEnd) {
                    isMatched = YES;
                    NSLog(@"IP range matched: %@ in [%u, %u]", _remoteHostName, tuple.ipStart, tuple.ipEnd);
                    break;
                }else{
                    NSLog(@"IP %@ NOT in range [%u, %u]", _remoteHostName, tuple.ipStart, tuple.ipEnd);
                }
            }
        }
        if(isMatched){
            return rule;
        }
    }
    NSLog(@"---don't have any matched rule---");
    return nil;
}

//入站匹配函数
-(FirewallRule*_Nonnull)firstMatchedRuleForInBound:(NSString*_Nonnull)_remoteIP
                                        localPort:(NSString*_Nonnull)_localPort
                                          protocol:(NSString*_Nonnull)_Protocol{
    // 1. 获取该 direction + protocol 下的所有规则
    NSArray<FirewallRule *> *candidateRules = [self rulesForDirection:FlowDirectionInbound protocol:_Protocol];
    if (candidateRules.count == 0) {
        NSLog(@"firstMatchedRuleForHostname : candidataeRules is nil");
        return nil;
    }else{
        NSLog(@"the number of rules is : %lu",(unsigned long)candidateRules.count);
    }
    ///判断是否是IPV4地址
    BOOL isIPv4 = NO;
    if (_remoteIP.length > 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, [_remoteIP UTF8String], &addr) == 1) {
            isIPv4 = YES;
        }
    }
    //2.开始逐个判断
    for(FirewallRule* rule in candidateRules){
        BOOL isMatched = NO;
        // 3.入站：检查每个 fiveTuple 的 hostName 和 remotePort 是否在范围内
        for (fiveINetTuple *tuple in rule.fiveTuples) {
            // 本地端口匹配：remotePort ∈ [portStart, portEnd]
            NSLog(@"tuplestart : %hu , tupleend : %hu , tupleipstart : %u , tupleipend : %u",tuple.portStart , tuple.portEnd , tuple.ipStart , tuple.ipEnd);
            NSUInteger Port = [_localPort integerValue];
            NSLog(@"local port :%lu , tuplestart : %hu , tupleend : %hu",(unsigned long)Port , tuple.portStart , tuple.portEnd);
            if (Port < tuple.portStart || Port > tuple.portEnd) {
                NSLog(@"port is not in range");
                continue;
            }
            // ip匹配（支持 nil 表示任意）
            if(isIPv4){
                // IPv4 匹配
                uint32_t remoteIp = ipv4StringToUInt32(_remoteIP);
                //如果ip为0.0.0.0那么匹配所有ip
                if(tuple.ipStart == 0 && tuple.ipEnd == 0){
                    isMatched = YES;
                    NSLog(@"IP wildcard (0.0.0.0-0.0.0.0) matched for %@", _remoteIP);
                    break;
                }else if(remoteIp >= tuple.ipStart && remoteIp <= tuple.ipEnd){
                    isMatched = YES;
                    NSLog(@"IP range matched: %@ in [%u, %u]", _remoteIP, tuple.ipStart, tuple.ipEnd);
                    break;
                }else{
                    NSLog(@"IP %@ NOT in range [%u, %u]", _remoteIP, tuple.ipStart, tuple.ipEnd);
                    break;
                }
            }else{
                NSLog(@"ip is not IPV4 address");
            }
        }
        if(isMatched){
            return rule;
        }
    }
    NSLog(@"---don't have any matched rule---");
    return nil;
}


// 主机名通配符匹配工具方法（支持 *.example.com）
- (BOOL)hostName:(NSString *)host matchesPattern:(NSString *)pattern {
    if ([host isEqualToString:pattern]) {
        return YES;
    }

    // 支持前缀通配符 *.example.com
    if ([pattern hasPrefix:@"*."]) {
        NSString *suffix = [pattern substringFromIndex:2]; // 去掉 "*."
        if ([host length] > [suffix length] && [host hasSuffix:suffix]) {
            // 确保至少有一个子域（不能直接匹配 example.com）
            NSRange dotRange = [host rangeOfString:@"." options:NSBackwardsSearch];
            if (dotRange.location != NSNotFound && dotRange.location > 0) {
                NSString *prefix = [host substringToIndex:dotRange.location];
                if (prefix.length > 0) {
                    return YES;
                }
            }
        }
    }

    // TODO: 可扩展支持更多模式（如 api.*.com 需要正则）
    return NO;
}

@end
