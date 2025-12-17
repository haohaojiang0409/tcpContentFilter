//
//  RuleManager.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/16.
//

#import "RuleManager.h"

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
        _lastRulesetHash = nil;
    }
    return self;
}

#pragma mark - 添加单条规则
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

#pragma mark - 辅助方法：二分插入
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

#pragma mark - 删除单个规则
- (void)removeRule:(FirewallRule *)ruleToRemove {
    dispatch_sync(self.syncQueue, ^{
        // 获取待删除规则的唯一标识
        NSString *targetId = ruleToRemove.policyId;
        if (targetId.length == 0) {
            NSLog(@"[Firewall] ⚠️ Cannot remove rule: no valid policyId or contentHash");
            return;
        }
        
        for (NSNumber *protoNum in ruleToRemove.protocolTypes) {
            TransportProtocol proto = (TransportProtocol)[protoNum unsignedIntegerValue];
            
            NSString *dirStr = (ruleToRemove.direction == FlowDirectionOutbound) ? @"out" : @"in";
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
                    continue;
            }
            
            NSString *key = [RuleCompositeKeyGenerator compositeKeyWithDirection:dirStr protocol:protoStr];
            NSMutableArray<FirewallRule *> *group = self.ruleGroups[key];
            if (!group || group.count == 0) {
                continue;
            }
            
            // 遍历查找匹配的规则（基于唯一 ID）
            __block NSInteger foundIndex = NSNotFound;
            for (NSInteger i = 0; i < group.count; i++) {
                FirewallRule *existingRule = group[i];
                NSString *existingId = existingRule.policyId;
                
                if ([targetId isEqualToString:existingId]) {
                    foundIndex = i;
                    break;
                }
            }
            
            if (foundIndex != NSNotFound) {
                [group removeObjectAtIndex:foundIndex];
                NSLog(@"[Firewall] Removed rule with ID: %@ from group: %@", targetId, key);
            } else {
                NSLog(@"[Firewall] Rule not found in group %@ for removal (ID: %@)", key, targetId);
            }
        }
    });
}

#pragma mark - 删除所有规则
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

#pragma mark - 返回所有规则列表
- (NSArray<FirewallRule *> *)allRules {
    __block NSMutableSet<FirewallRule *> *uniqueRules = [NSMutableSet set];
    dispatch_sync(self.syncQueue, ^{
        for (NSArray<FirewallRule *> *group in [self.ruleGroups allValues]) {
            [uniqueRules addObjectsFromArray:group];
        }
    });
    return [uniqueRules allObjects];
}

#pragma mark - 出站判断函数，出站可匹配ip地址，可匹配域名
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

#pragma mark - 入站匹配函数
-(FirewallRule*_Nonnull)firstMatchedRuleForInBound:(NSString*_Nonnull)_remoteIP
                                        localPort:(NSString*_Nonnull)_localPort
                                          protocol:(NSString*_Nonnull)_Protocol
                                           process:(Process*)_process{
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
        BOOL isProcess = NO;
        //先判断是否是对应进程
        ProcessRule * processRule = [ProcessRule ruleWithProcess:_process];
        isProcess = [self matchesProcess:processRule rules:candidateRules];
        if(isProcess){
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
                        isMatched = YES;
                        if(isMatched)
                            break;
                    }
                }else{
                    [[Logger sharedLogger] info :@"ip is not IPV4 address"];
                }
            }
            if(isMatched){
                [[Logger sharedLogger] info:@"[RuleManager] has matched a rule"];
                return rule;
            }
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

#pragma mark - 热更新判断
- (BOOL)reloadRulesIfNeededWithJSON:(NSArray<NSDictionary *> * _Nullable)ruleDictionaries {
    if (!ruleDictionaries || ruleDictionaries.count == 0) {
        [[Logger sharedLogger] info:@"[Firewall] Empty rules received, skipping."];
        return NO;
    }
    //1.将JSON转为对象数组
    NSMutableArray<FirewallRule *> *newRules = [NSMutableArray array];
    for (NSDictionary *dict in ruleDictionaries) {
        NSArray<FirewallRule *> *rules = [FirewallRule rulesWithDictionary:dict];
        [newRules addObjectsFromArray:rules];
    }

    // 2. 按照复合键分组构建新json的规则集
    NSMutableDictionary<NSString *,NSMutableArray<FirewallRule *> * > *newRuleGroups = [NSMutableDictionary dictionary];
    for(FirewallRule* rule in newRules){
        for(NSNumber *protoNum in rule.protocolTypes){
            NSString* protoStr = [self protocolStringFromNumber:protoNum.integerValue];
            if(!protoStr) continue;
            NSString* dirStr = (rule.direction == FlowDirectionInbound) ? @"in" : @"out";
            NSString* compositeKey = [NSString stringWithFormat:@"%@_%@",  dirStr ,protoStr];
            NSMutableArray<FirewallRule *> *bucket = newRuleGroups[compositeKey];
            if (!bucket) {
                bucket = [NSMutableArray array];
                newRuleGroups[compositeKey] = bucket;
            }
            [bucket addObject:rule];
        }
    }

    NSArray<NSString *> *allKeys = @[@"in_tcp", @"out_tcp", @"in_udp", @"out_udp"];
    for (NSString *key in allKeys) {
        if (!newRuleGroups[key]) {
            newRuleGroups[key] = [NSMutableArray array];
        }
    }
    // 3. 计算新规则集哈希
    NSString *newHash = [self hashForRuleGroups:newRuleGroups];
    if ([newHash isEqualToString:_lastRulesetHash]) {
        [[Logger sharedLogger] info:@"[Firewall] Rules unchanged (hash: %@), skip reload.", newHash];
        return NO;
    }
    // 4. 哈希变了，执行增量更新
    dispatch_async(_syncQueue, ^{
        [self performIncrementalUpdateWithNewRuleGroups:newRuleGroups newHash:newHash allKeys:allKeys];
    });
    return YES;
}

#pragma mark - 增量更新核心逻辑
- (void)performIncrementalUpdateWithNewRuleGroups:
(NSMutableDictionary<NSString *, NSMutableArray<FirewallRule *> *> *)newRuleGroups newHash:(NSString *)newHash allKeys:(NSArray<NSString*>*)allKeys{
    
    for (NSString *key in allKeys) {
        NSMutableArray<FirewallRule *> *oldBucket = self.ruleGroups[key] ?: [NSMutableArray array];
        NSMutableArray<FirewallRule *> *newBucket = newRuleGroups[key] ?: [NSMutableArray array];

        // 构建 ID 映射（以 policyId 为唯一标识）
        NSMutableDictionary<NSString *, FirewallRule *> *oldMap = [NSMutableDictionary dictionary];
        for (FirewallRule *rule in oldBucket) {
            NSString *id = rule.policyId;
            oldMap[id] = rule;
        }

        NSMutableDictionary<NSString *, FirewallRule *> *newMap = [NSMutableDictionary dictionary];
        for (FirewallRule *rule in newBucket) {
            NSString *id = rule.policyId;
            newMap[id] = rule;
        }

        // 找出差异
        NSMutableSet<NSString *> *toRemove = [NSMutableSet set];
        for (NSString *id in oldMap.allKeys) {
            if (!newMap[id]) {
                [toRemove addObject:id];
            }
        }

        NSMutableSet<NSString *> *toAdd = [NSMutableSet set];
        for (NSString *id in newMap.allKeys) {
            if (!oldMap[id]) {
                [toAdd addObject:id];
            }
        }

        // 先删
        for (NSString *id in toRemove) {
            FirewallRule *rule = oldMap[id];
            [self removeRule:rule];
            [[Logger sharedLogger] info:@"[Firewall] Removed from %@: %@", key, rule.policyName ?: id];
        }

        // 再加
        for (NSString *id in toAdd) {
            FirewallRule *rule = newMap[id];
            [self addRule:rule];
        }
        // 在 toRemove / toAdd 之后，增加：
        NSMutableSet<NSString *> *toUpdate = [NSMutableSet set];
        for (NSString *id in newMap.allKeys) {
            if (oldMap[id]) {
                FirewallRule *oldRule = oldMap[id];
                FirewallRule *newRule = newMap[id];
                
                // 判断规则是否“实质改变”（不能只比指针！）
                if (![oldRule isEqualToRule:newRule]) {
                    [toUpdate addObject:id];
                }
            }
        }

        // 处理修改：先删旧，再加新
        for (NSString *id in toUpdate) {
            FirewallRule *oldRule = oldMap[id];
            FirewallRule *newRule = newMap[id];
            
            [self removeRule:oldRule];
            [self addRule:newRule];
            
            [[Logger sharedLogger] info:@"[Firewall] Updated rule in %@: %@", key, newRule.policyName ?: id];
        }
        // 更新该桶
        self.ruleGroups[key] = [newBucket mutableCopy];
    }

    _lastRulesetHash = newHash;
    [[Logger sharedLogger] info:@"[Firewall] Incremental update done for all groups."];
}

#pragma mark - 辅助方法
- (NSString *)protocolStringFromNumber:(int)proto {
    switch (proto) {
        case IPPROTO_TCP: return @"tcp";
        case IPPROTO_UDP: return @"udp";
        case IPPROTO_ICMP: return @"icmp";
        default: return nil;
    }
}



#pragma mark - 规则集哈希计算
- (NSString *)hashForRuleGroups:(NSDictionary<NSString *, NSArray<FirewallRule *> *> *)groups {
    // 1. 按 composite key 排序（如 in_tcp, out_tcp...)
    NSArray<NSString *> *sortedKeys = [[groups allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *key = [NSMutableString string];
    
    for (NSString *k in sortedKeys) {
        NSArray<FirewallRule *> *rules = groups[k];
        if (!rules || rules.count == 0) {
            // 空桶也要参与哈希，避免结构变化被忽略
            [key appendFormat:@"%@|EMPTY|", k];
            continue;
        }
        
        // 2. 桶内规则按 level 升序排序（level 越小优先级越高，且全局唯一）
        NSArray<FirewallRule *> *sortedRules = [rules sortedArrayUsingComparator:^NSComparisonResult(FirewallRule *a, FirewallRule *b) {
            if (a.level < b.level) return NSOrderedAscending;
            if (a.level > b.level) return NSOrderedDescending;
            // 因为 level 全局唯一，理论上不会相等，但加个断言更安全
            NSAssert(NO, @"Duplicate level detected: %ld vs %ld", (long)a.level, (long)b.level);
            return NSOrderedSame;
        }];
        
        // 3. 拼接关键字段：composite key + 唯一ID + level + 动作
        for (FirewallRule *rule in sortedRules) {
            NSString *ruleId = rule.policyId;
            [key appendFormat:@"%@|%@|%ld|%d|",
                 k,
                 ruleId,
                 (long)rule.level,
                 rule.allow ? 1 : 0
            ];
        }
    }
    
    return [self sha256OfString:key];
}

- (NSString *)sha256OfString:(NSString *)input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    return [hash copy];
}
@end
