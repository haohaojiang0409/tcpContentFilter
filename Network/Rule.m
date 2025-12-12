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

#pragma mark -- ip和域名存储类
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

#pragma mark -- 防火墙具体规则类
@implementation FirewallRule

- (instancetype)init {
    // 提供一个安全的默认初始化（虽然通常应使用指定初始化器）
    return [self initWithDirection:0
                          protocol:@[]
                       fiveTuples:@[]
                            allow:YES
                      processRules:@[]];
}
// 初始化完整规则
- (instancetype)initWithDirection:(FlowDirection)direction
                         protocol:(NSArray<NSNumber *> *)protocolTypes // 建议参数名与属性一致
                       fiveTuples:(NSArray<fiveINetTuple *> *)fiveTuples
                            allow:(BOOL)allow
                     processRules:(NSArray<ProcessRule*>* _Nullable) processRules {
    if (self = [super init]) {
        _direction = direction;
        _protocolTypes = [protocolTypes copy]; // 强制 copy
        _fiveTuples = [fiveTuples copy];
        _allow = allow;
        _processArr = [processRules copy];
    }
    return self;
}

+ (NSArray<FirewallRule *> *)rulesWithDictionary:(NSDictionary *)dict {
    [[Logger sharedLogger] info:@"[rulesWithDictionary] is started!"];
    // 1. 解析 direction
    NSString *dirStr = dict[@"direction"];
    if (![dirStr isEqualToString:@"out"] && ![dirStr isEqualToString:@"in"]) {
        NSLog(@"[RULE PARSE] Invalid direction: %@", dirStr ?: @"(null)");
        return @[];
    }
    FlowDirection direction = [dirStr isEqualToString:@"out"] ? FlowDirectionOutbound : FlowDirectionInbound;

    // 2. 解析 action
    NSString *action = dict[@"action"];
    BOOL allow = [action isEqualToString:@"pass"]; // "block" → NO

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

    //加载进程的相关规则
    
    NSMutableArray<ProcessRule *> * processArr = [NSMutableArray array];
    NSArray *processStrs = dict[@"processes"];
    
    for (NSDictionary *ruleDict in processStrs) {
        ProcessRule *rule = [[ProcessRule alloc] init];
        
        // 必填或常用字段
        rule.processName        = ruleDict[@"process_name"] ?: @"";
        rule.hash256            = ruleDict[@"hash256"] ?: @"";
        rule.path               = ruleDict[@"path"] ?: @"";
        
        // 可选字段
        rule.company            = ruleDict[@"company"] ?: @"";
        rule.processDescription = ruleDict[@"process_des"] ?: @"";
        rule.originFilename     = ruleDict[@"origin_filename"] ?: @"";
        rule.productDescription = ruleDict[@"product_des"] ?: @"";
        rule.signer = ruleDict[@"signer"] ?: @"";
        
        [processArr addObject:rule];
    }

    // 所有解析后的 ProcessRule 对象数量
    [[Logger sharedLogger] info:@"[RuleManager] Parsed %lu rules" , (unsigned long)processArr.count];
    // 6. 创建规则
    FirewallRule *rule = [[FirewallRule alloc]
                        initWithDirection:direction
                                 protocol:protocolTypes
                               fiveTuples:tuples
                                    allow:allow
                             processRules:processArr];

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
            NSLog(@"insertIndex : %ld , level of rule : %ld", (long)insertIndex , (long)rule.level);
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
                                   protocol:(NSString*)_Protocol
                                    process:(Process*)_process{
    // 1. 获取该 direction + protocol 下的所有规则
    NSArray<FirewallRule *> *candidateRules = [self rulesForDirection:FlowDirectionOutbound protocol:_Protocol];
    if (candidateRules.count == 0) {
        return nil;
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
            if (remotePort < tuple.portStart || remotePort > tuple.portEnd) {
                //NSLog(@"port is not in range");
                continue;
            }
            // 主机名匹配（支持 nil 表示任意）
            if(!isIPv4){
                if ([tuple.hostName isEqualToString:_remoteHostName]) {
                    isMatched = YES;
                    break;
                }else{
                    //NSLog(@"hostname is not matched and tuple.hostName : %@ != %@", tuple.hostName , _remoteHostName);
                }
            }else {
                // IPv4 匹配
                uint32_t remoteIp = ipv4StringToUInt32(_remoteHostName);
                if ((tuple.ipStart == 0 && tuple.ipEnd == 0) ||( remoteIp >= tuple.ipStart && remoteIp <= tuple.ipEnd)) {
                    // 规则未指定 IP 范围 → 匹配任意 IP
                    [[Logger sharedLogger] info:@"[RuleManager OutBound ip has matched a rule]"];
                    //TODO : 匹配进程
                    //转化为oc对象
                    ProcessRule* processRule = [ProcessRule ruleWithProcess:_process];
                    isMatched = [self matchesProcess:processRule rules:candidateRules];
                    if(isMatched)
                        break;
                }else{
                    [[Logger sharedLogger] info:@ "[RuleManager] OutBound has not matched a rule ipstart:%u ipend : %u" , tuple.ipStart , tuple.ipEnd];
                }
            }
        }
        if(isMatched){
            return rule;
        }
    }
    [[Logger sharedLogger] info: @"---don't have any matched rule --- "];
    return nil;
}

//入站匹配函数
-(FirewallRule*_Nonnull)firstMatchedRuleForInBound:(NSString*_Nonnull)_remoteIP
                                        localPort:(NSString*_Nonnull)_localPort
                                          protocol:(NSString*_Nonnull)_Protocol
                                           process:(ProcessRule*)_processrule{
    // 1. 获取该 direction + protocol 下的所有规则
    NSArray<FirewallRule *> *candidateRules = [self rulesForDirection:FlowDirectionInbound protocol:_Protocol];
    if (candidateRules.count == 0) {
        //NSLog(@"firstMatchedRuleForHostname : candidataeRules is nil");
        [[Logger sharedLogger] error:@"firstMatchedRuleForHostname : candidataeRules is nil"];
        return nil;
    }else{
        [[Logger sharedLogger] info:@"the number of rules is : %lu" , (unsigned long)candidateRules.count];
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
            NSUInteger Port = [_localPort integerValue];
            if (Port < tuple.portStart || Port > tuple.portEnd) {
                continue;
            }
            // ip匹配（支持 nil 表示任意）
            if(isIPv4){
                // IPv4 匹配
                uint32_t remoteIp = ipv4StringToUInt32(_remoteIP);
                if((tuple.ipStart == 0 && tuple.ipEnd == 0) || (remoteIp >= tuple.ipStart && remoteIp <= tuple.ipEnd)){
                    //TODO : 匹配进程
                    isMatched = [self matchesProcess:_processrule rules:candidateRules];
                    if(isMatched)
                        break;
                }
            }else{
               [[Logger sharedLogger] info :@"ip is not IPV4 address"];
            }
        }
        if(isMatched){
            return rule;
        }
    }
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

#pragma mark -- 是否匹配规则中设定的某个进程
- (BOOL)matchesProcess:(ProcessRule *)processInfo  rules:(NSArray<FirewallRule *> *)candidateRules{
    for (FirewallRule *rule in candidateRules) {
        NSArray<ProcessRule *> * processRules = rule.processArr;
        for(ProcessRule * proRule in processRules){
            if ([proRule matchesProcess:processInfo]) {
                [[Logger sharedLogger] info:@"[RuleManager] is matched a process rule"];
                return YES; // 命中一条即匹配
            }else{
                [[Logger sharedLogger] info:@"[RuleManager] is not matched a process rule"];
            }
        }
    }
    return NO;
}

@end

#pragma mark - 进程规则类
@implementation ProcessRule

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:self.processName forKey:@"processName"];
    [coder encodeObject:self.company forKey:@"company"];
    [coder encodeObject:self.hash256 forKey:@"hash256"];
    [coder encodeObject:self.processDescription forKey:@"processDescription"];
    [coder encodeObject:self.originFilename forKey:@"originFilename"];
    [coder encodeObject:self.productDescription forKey:@"productDescription"];
    [coder encodeObject:self.path forKey:@"path"];
    [coder encodeObject:self.signer forKey:@"signer"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {
    if (self = [super init]) {
            _processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
            _company = [coder decodeObjectOfClass:[NSString class] forKey:@"company"];
            _hash256 = [coder decodeObjectOfClass:[NSString class] forKey:@"hash256"];
            _processDescription = [coder decodeObjectOfClass:[NSString class] forKey:@"processDes"];
            _originFilename = [coder decodeObjectOfClass:[NSString class] forKey:@"originFilename"];
            _productDescription = [coder decodeObjectOfClass:[NSString class] forKey:@"productDes"];
            _path = [coder decodeObjectOfClass:[NSString class] forKey:@"path"];
            _signer = [coder decodeObjectOfClass:[NSString class] forKey:@"signer"];
        }
        return self;
}

// 判断当前规则是否匹配给定的进程信息
- (BOOL)matchesProcess:(ProcessRule *)processInfo {
    if (!processInfo){
        [[Logger sharedLogger] error:@"[%@::%s] processInfo is nil" , NSStringFromClass([self class]), __FUNCTION__];
        return NO;
    }


    // 定义局部 block
    BOOL (^matchField)(NSString *, NSString *) = ^BOOL(NSString *ruleValue, NSString *actualValue) {
        if (ruleValue.length == 0) {
            return YES; // 规则为空 → 不限制
        }
        if (!actualValue){
            return NO;
        }
        [[Logger sharedLogger] info:@"--[%s] is executed--" , __FUNCTION__];
        return [ruleValue isEqualToString:actualValue];
    };

    return matchField(self.processName, processInfo.processName)
        && matchField(self.company, processInfo.company)
        && matchField(self.hash256, processInfo.hash256)
        && matchField(self.processDescription, processInfo.processDescription)
        && matchField(self.originFilename, processInfo.originFilename)
        && matchField(self.productDescription, processInfo.productDescription)
        && matchField(self.path, processInfo.path)
        && matchField(self.signer, processInfo.signer);
}

//C结构体转化为OC对象
+ (instancetype)ruleWithProcess:(Process *)process {
    ProcessRule *rule = [[ProcessRule alloc] init];
    
    // 基础标识
    rule.processName = [ NSString stringWithUTF8String:process.getCoreData.name];
    
    // SHA256
    rule.hash256 = SHA256DataToHexString(process.getCoreData.sha256);
    
    // 路径
    rule.path = [NSString stringWithUTF8String:process.getCoreData.processPath];
    
    // 从 Info.plist 提取
    if (process.infoPlist) {
        rule.originFilename = process.infoPlist[@"CFBundleExecutable"] ?: @"";
        rule.processDescription = process.infoPlist[@"CFBundleName"] ?: @"";
        rule.productDescription = [NSString stringWithFormat:@"%@ %@",
                                   process.infoPlist[@"CFBundleIdentifier"] ?: @"",
                                   process.infoPlist[@"CFBundleShortVersionString"] ?: @""];
        
        // 尝试获取公司
        rule.company = process.infoPlist[@"NSHumanReadableCopyright"] ?:
                       process.infoPlist[@"CFBundleDevelopmentRegion"] ?:
                       @"";
    }
    
    // 签名者（需额外实现，见下文）
    rule.signer = [self extractSignerFromProcess:process];
    
    return rule;
}

+ (NSString *)extractSignerFromProcess:(Process *)process {
    // TODO: 从代码签名中提取 Team ID 或 Common Name
    // 暂时返回空，后续可扩展
    return @"";
}
@end

