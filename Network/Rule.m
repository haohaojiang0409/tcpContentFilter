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

- (BOOL)isEqual:(fiveINetTuple *)object {
    if (![object isKindOfClass:[fiveINetTuple class]]) return NO;
    
    fiveINetTuple *other = (fiveINetTuple *)object;
    return self.ipStart == other.ipStart &&
           self.ipEnd == other.ipEnd &&
           self.portStart == other.portStart &&
           self.portEnd == other.portEnd &&
           [self.hostName isEqualToString:other.hostName];
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

#pragma mark - 通过字典初始化规则
+ (NSArray<FirewallRule *> *)rulesWithDictionary:(NSDictionary *)dict {
    // 1. 解析 direction
    NSString *dirStr = dict[@"direction"];
    if (![dirStr isEqualToString:@"out"] && ![dirStr isEqualToString:@"in"]) {
        [[Logger sharedLogger] error:@"[RULE PARSE] Invalid direction: %@", dirStr ?:@"(null)"];
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
        [[Logger sharedLogger] error:@"[RULE PARSE] No valid protocols in rule (proto: %@)", protoStr ?: @"(null)"];
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
            [[Logger sharedLogger] info:@"hostName : %@",host];
            NSArray *ports = t[@"dst_port"];
            if (![ports isKindOfClass:[NSArray class]]) continue;
            uint32_t ipStart = 0, ipEnd = 0;
            //ip地址
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
                        [[Logger sharedLogger] info: @"outBound rule --- ip address : %@:%u",ipStr,ip];
                    } else {
                        [[Logger sharedLogger] info: @"[RULE PARSE] Invalid dst_ip: %@", ipStr];
                        continue; // 可选：跳过整个 tuple，或当作 0.0.0.0-255.255.255.255？
                    }
                }
            } else if (direction == FlowDirectionInbound) {
                NSString *ipStr = t[@"source_ip"];
                
                if ([ipStr containsString:@"|"]) {
                    // 处理 "IP|Mask" 格式
                    NSArray<NSString *> *parts = [ipStr componentsSeparatedByString:@"|"];
                    if (parts.count == 2) {
                        NSString *ipPart = parts[0];
                        NSString *maskPart = parts[1];
                        
                        uint32_t ipVal = ipv4StringToUInt32(ipPart);
                        uint32_t netmask = maskStringToUInt32(maskPart);
                        
                        if (netmask == 0 && ![maskPart isEqualToString:@"0.0.0.0"]) {
                            [[Logger sharedLogger] error:@"Invalid subnet mask in source_ip: %@", ipStr];
                            continue;
                        }
                        
                        // 计算网络地址和广播地址
                        uint32_t network = ipVal & netmask;
                        uint32_t broadcast = network | (~netmask);
                        
                        ipStart = network;
                        ipEnd = broadcast;
                        
                        [[Logger sharedLogger] error:@"inBound rule --- IP range: %@ -> [%u, %u]", ipStr, (unsigned int)ipStart, (unsigned int)ipEnd];
                    } else {
                        [[Logger sharedLogger] error:@"Incorrect JSON format for source_ip (expected 'IP|Mask'): %@", ipStr];
                        continue;
                    }
                } else {
                    // 单个 IP 地址
                    uint32_t ipVal = ipv4StringToUInt32(ipStr);
                    
                    // ipv4StringToUInt32 返回 0 可能是失败，也可能是 "0.0.0.0"
                    if (ipVal == 0 && ![ipStr isEqualToString:@"0.0.0.0"]) {
                        [[Logger sharedLogger] info:@"Invalid source_ip (not a valid IPv4): %@", ipStr];
                        continue;
                    }
                    
                    ipStart = ipEnd = ipVal;
                    NSLog(@"inBound rule --- Single IP: %@", ipStr);
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

#pragma mark - 比较两个进程是否相等
- (BOOL)isEqualToRule:(FirewallRule *)other {
    if (!other) return NO;
    if (self == other) return YES;

    // 1. 比较基础类型
    if (self.direction != other.direction ||
        self.allow != other.allow ||
        self.level != other.level ||
        self.shouldReport != other.shouldReport) {
        return NO;
    }
    // 2. 比较 NSArray
    if (![self.protocolTypes isEqualToArray:other.protocolTypes]) {
        return NO;
    }
    //3. 比较五元组
    if (![self.fiveTuples isEqual:other.fiveTuples]) {
        return NO;
    }
    return YES;
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

