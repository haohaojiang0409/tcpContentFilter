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

NSString *myPcapFileName = @"/tmp/mySimplePcap.pcap";
long lastUpdateTime = 0;
size_t pcapSize = 0;

NSString *myFile = @"/Users/haohaojiang0409/Code/file.txt";
size_t myFileSize = 0;
@implementation AppFilterProvider

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* 魔数（用于标识文件格式和字节序） */
    uint16_t version_major;  /* 主版本号 */
    uint16_t version_minor;  /* 次版本号 */
    int32_t  thiszone;       /* 本地时间与 GMT（格林尼治标准时间）的时区偏移（秒） */
    uint32_t sigfigs;        /* 时间戳精度（通常为0，表示精确到微秒） */
    uint32_t snaplen;        /* 每个数据包最大捕获长度（单位：字节） */
    uint32_t network;        /* 链路层类型（例如：1 表示以太网 Ethernet） */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* 时间戳：秒部分（自 Unix 纪元 1970-01-01 00:00:00 UTC 起） */
    uint32_t ts_usec;        /* 时间戳：微秒部分 */
    uint32_t incl_len;       /* 文件中保存的数据包实际长度（单位：字节） */
    uint32_t orig_len;       /* 数据包原始真实长度（单位：字节，可能大于 incl_len） */
} pcaprec_hdr_t;

//typedef struct {
//    BOOL isValid;
//    NSString *protocol;      // @"tcp", @"udp", @"icmp"
//    uint32_t srcIP;          // 网络字节序（大端）
//    uint32_t dstIP;          // 网络字节序
//    uint16_t srcPort;
//    uint16_t dstPort;
//} ParsedPacketInfo;

size_t pcapSize;

typedef struct {
    char remoteHostname[256];   // 域名，最大255字符 + '\0'
    int remotePort;             // 远程端口
    int localPort;              // 本地端口
    char direction[8];          // "OUT" 或 "IN"
    char protocol[8];           // "TCP", "UDP", "OTHER"
    char verdict[16];           // "ALLOW", "BLOCK"
    char matchedRule[128];      // 匹配的规则名（若无则为空）
} FlowLogEntry;

#pragma mark - Lifecycle

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    
    // 1️⃣ 初始化规则管理器（单例已自动创建）
    FirewallRuleManager *rulesManager = [FirewallRuleManager sharedManager];
    // 2️⃣ 加载并注册 JSON 规则（内部会清空旧规则）
    [self loadAndRegisterFirewallRules];
    
    //3 初始化日志变量
    firewallLog = os_log_create("com.eagleyun.BorderControl", "Network");
    os_log(firewallLog , "Filter started");
    
//    //生成可以解析的抓包文件
//    NSFileManager *filemgr;
//    pcap_hdr_t pcapHeader = {0};
//    NSData *databuffer = nil;
//    BOOL res = NO;
//    
//    pcapHeader.magic_number = 0xa1b2c3d4;
//    pcapHeader.version_major = 2;
//    pcapHeader.version_minor = 4;
//    pcapHeader.thiszone = 0; // Set to GMT for now
//    pcapHeader.sigfigs = 0;
//    pcapHeader.snaplen = 65535;
//    pcapHeader.network = 1; // Ethernet for now
//    
//    databuffer = [NSData dataWithBytes: &pcapHeader length: (sizeof pcapHeader)];
//    filemgr = [NSFileManager defaultManager];
//    
//    //创建抓包文件
//    res = [filemgr createFileAtPath: myPcapFileName contents: databuffer attributes: nil];
//    if (NO == res)
//    {
//        NSString *msg = [NSString stringWithFormat:@"Failed to create pcap file: %@", myPcapFileName];
//        NSLog(@"%@", msg);
//    }
//    // end pcap initialization
//    
//    pcapSize = sizeof(pcap_hdr_t);
//    NSLog(@"startFilterWithCompletionHandler");
//    //回调读取数据包
//    self.packetHandler = ^NEFilterPacketProviderVerdict(NEFilterPacketContext * _Nonnull context, nw_interface_t  _Nonnull interface, NETrafficDirection direction, const void * _Nonnull packetBytes, const size_t packetLength) {
//
//        (void)[AppFilterProvider handlePacketwithContext: context
//                                              fromInterface: interface
//                                                  direction: direction
//                                               withRawBytes: packetBytes
//                                                     length: packetLength];
//
//        return NEFilterPacketProviderVerdictAllow;
//    };
//
//    completionHandler(nil);

//    self.packetHandler = ^NEFilterPacketProviderVerdict(
//        NEFilterPacketContext * _Nonnull context,
//        nw_interface_t  _Nonnull interface,
//        NETrafficDirection direction,
//        const void * _Nonnull packetBytes,
//        const size_t packetLength) {
//
//        // ====== 包解析阶段 ======
//        ParsedPacketInfo info = parsePacket(packetBytes, packetLength);
//        if (!info.isValid) {
//            // 可选：记录无效包（初期可关闭，避免刷屏）
//            // NSLog(@"[Packet] ⚠️ Invalid packet (length=%zu)", packetLength);
//            return NEFilterPacketProviderVerdictAllow;
//        }
//
//        NSString *dirStr = (direction == NETrafficDirectionOutbound) ? @"OUT" : @"IN";
//        NSLog(@"[Packet]  [%@] %@@%u → %@@%u | proto: %@",
//              dirStr,
//              [self ipToString:info.srcIP], (unsigned int)info.srcPort,
//              [self ipToString:info.dstIP], (unsigned int)info.dstPort,
//              info.protocol ?: @"?");
//
//        // ====== 协议映射 ======
//        TransportProtocol proto = TransportProtocolUnknown;
//        if ([info.protocol isEqualToString:@"tcp"]) {
//            proto = TransportProtocolTCP;
//        } else if ([info.protocol isEqualToString:@"udp"]) {
//            proto = TransportProtocolUDP;
//        } else if ([info.protocol isEqualToString:@"icmp"]) {
//            proto = TransportProtocolICMP;
//        }
//
//        if (proto == TransportProtocolUnknown) {
//            NSLog(@"[Packet] ❓ Unknown protocol, allowing.");
//            return NEFilterPacketProviderVerdictAllow;
//        }
//
//        // ====== 规则查询 ======
//        BOOL isOutbound = (direction == NETrafficDirectionOutbound);
//        FlowDirection flowDir = isOutbound ? FlowDirectionOutbound : FlowDirectionInbound;
//        FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
//        NSArray<FirewallRule *> *candidates = [manager rulesForDirection:flowDir protocol:proto];
//
//        if (candidates.count == 0) {
//            // NSLog(@"[Rule] ℹ️ No rules for %@/%@, allowing.",
//            //       isOutbound ? @"out" : @"in", info.protocol);
//            return NEFilterPacketProviderVerdictAllow;
//        }
//
//        // ====== 规则匹配 ======
//        FirewallRule *bestMatch = nil;
//        NSInteger highestLevel = NSNotFound;
//
//        for (FirewallRule *rule in candidates) {
//            BOOL matched = NO;
//            for (fiveINetTuple *tuple in rule.fiveTuples) {
//                uint16_t targetPort = isOutbound ? info.dstPort : info.srcPort;
//                if (targetPort < tuple.portStart || targetPort > tuple.portEnd) {
//                    continue;
//                }
//
//                uint32_t targetIP = isOutbound ? info.dstIP : info.srcIP;
//
//                if (tuple.resolvedIPs.count > 0) {
//                    for (NSNumber *ipNum in tuple.resolvedIPs) {
//                        if (targetIP == [ipNum unsignedIntValue]) {
//                            matched = YES;
//                            break;
//                        }
//                    }
//                    if (matched) break;
//                } else {
//                    matched = YES;
//                    break;
//                }
//            }
//
//            if (matched && rule.level > highestLevel) {
//                highestLevel = rule.level;
//                bestMatch = rule;
//            }
//        }
//
//        // ====== 决策与日志 ======
//        if (bestMatch) {
//            if (!bestMatch.allow) {
//                NSString *domain = @"";
//                for (fiveINetTuple *t in bestMatch.fiveTuples) {
//                    if (t.hostName.length > 0) {
//                        domain = t.hostName;
//                        break;
//                    }
//                }
//                NSLog(@"[BLOCK] Blocked by rule '%@' (level=%ld): %@:%u (%@)",
//                      bestMatch.policyName,
//                      (long)bestMatch.level,
//                      [self ipToString:info.dstIP],
//                      (unsigned int)info.dstPort,
//                      domain.length ? domain : @"no domain");
//                return NEFilterPacketProviderVerdictDrop;
//            } else {
//                NSLog(@"[ALLOW] Allowed by rule '%@'", bestMatch.policyName);
//            }
//        }
//
//        return NEFilterPacketProviderVerdictAllow;
//    };
//
//    NSLog(@"[AppFilterProvider] Packet handler installed. Filter is now active.");
//    completionHandler(nil);
     //4️⃣ 配置 NEFilterSettings：拦截所有 TCP/UDP 流量以触发 handleNewFlow
//        NENetworkRule *tcpOut = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                           localNetwork:nil localPrefix:0
//                                                             protocol:NENetworkRuleProtocolTCP
//                                                             direction:NETrafficDirectionOutbound];
//        NENetworkRule *tcpIn  = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                           localNetwork:nil localPrefix:0
//                                                             protocol:NENetworkRuleProtocolTCP
//                                                             direction:NETrafficDirectionInbound];
//        NENetworkRule *udpOut = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                           localNetwork:nil localPrefix:0
//                                                             protocol:NENetworkRuleProtocolUDP
//                                                             direction:NETrafficDirectionOutbound];
//        NENetworkRule *udpIn  = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                           localNetwork:nil localPrefix:0
//                                                             protocol:NENetworkRuleProtocolUDP
//                                                             direction:NETrafficDirectionInbound];
//    
//        NEFilterRule *tcpOutRule = [[NEFilterRule alloc] initWithNetworkRule:tcpOut action:NEFilterActionFilterData];
//        NEFilterRule *tcpInRule  = [[NEFilterRule alloc] initWithNetworkRule:tcpIn  action:NEFilterActionFilterData];
//        NEFilterRule *udpOutRule = [[NEFilterRule alloc] initWithNetworkRule:udpOut action:NEFilterActionFilterData];
//        NEFilterRule *udpInRule  = [[NEFilterRule alloc] initWithNetworkRule:udpIn  action:NEFilterActionFilterData];
//    
//        NSArray<NEFilterRule *> *allRules = @[tcpOutRule, tcpInRule, udpOutRule, udpInRule];
//        NEFilterSettings *settings = [[NEFilterSettings alloc] initWithRules:allRules defaultAction:NEFilterActionAllow];
//
       NSFileManager *filemgr;
//       NSData *databuffer = nil;
        BOOL res = NO;
//       databuffer = [NSData dataWithBytes: &pcapHeader length: (sizeof pcapHeader)];
       filemgr = [NSFileManager defaultManager];
   
       //创建抓包文件
       res = [filemgr createFileAtPath: myFile contents: nil attributes: nil];
       if (NO == res)
       {
           NSString *msg = [NSString stringWithFormat:@"Failed to create pcap file: %@", myPcapFileName];
           os_log(firewallLog , "%{public}@", msg);
       }
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
// parsePacket 函数（前面已提供，确保返回网络字节序 IP）

#pragma mark - 过滤packet的逻辑
+ (void)handlePacketwithContext: (NEFilterPacketContext *_Nonnull) context
                  fromInterface: (nw_interface_t _Nonnull) interface
                      direction: (NETrafficDirection) direction
                   withRawBytes: (const void *_Nonnull) packetBytes
                         length: (const size_t) packetLength
{
    //只处理有线和wifi接口
    nw_interface_type_t nicType = nw_interface_get_type(interface);
    
    // Only capture Ether traffic for now
    if ((nw_interface_type_wired != nicType) && (nw_interface_type_wifi != nicType))
    {
        return;
    }
    //写入pcap文件
    NSFileHandle *file;
    NSMutableData *data;
    //时间戳
    struct timeval tv = {0};
    
    //头部：时间戳
    pcaprec_hdr_t pktHeader = {0};
    
    gettimeofday(&tv, NULL);
    
    pktHeader.ts_sec = (uint32_t)tv.tv_sec;
    pktHeader.ts_usec = tv.tv_usec;
    pktHeader.incl_len = (uint32_t)packetLength;
    pktHeader.orig_len = (uint32_t)packetLength;
    
    //将时间作为头部放入数据体中
    data = [NSMutableData dataWithBytes: &pktHeader length: sizeof(pktHeader)];
    //把读到的数据包追加写在尾部
    [data appendBytes: packetBytes length: packetLength];
    
    file = [NSFileHandle fileHandleForUpdatingAtPath: myPcapFileName];
    
    if (file != nil)
    {
        [file seekToEndOfFile];
        
        [file writeData: data];
        
        [file closeFile];
    }
    else
    {
        NSLog(@"Failed to open file");
        
    }
    pcapSize += packetLength + sizeof(pcaprec_hdr_t);
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"Packet filter stopped: %ld", (long)reason);
    completionHandler();
}

- (void)allowPacket:(NEPacket *)packet{
    
}

#pragma mark - 加载json文件的逻辑

- (void)loadAndRegisterFirewallRules {
    NSString *jsonPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"rule" ofType:@"json"];
    if (!jsonPath) {
        NSLog(@"rule.json not found in extension bundle. Check Target Membership!");
        return;
    }
    
    NSData *jsonData = [NSData dataWithContentsOfFile:jsonPath];
    if (!jsonData || jsonData.length == 0) {
        NSLog(@"Failed to read rule.json or file is empty");
        return;
    }
    
    NSError *error = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    if (!jsonObject || ![jsonObject isKindOfClass:[NSDictionary class]]) {
        NSLog(@"Invalid JSON root: %@", error.localizedDescription);
        return;
    }
    
    NSDictionary *dataDict = jsonObject[@"data"];
    NSArray *rawRules = dataDict[@"rules"];
    if (![rawRules isKindOfClass:[NSArray class]] || rawRules.count == 0) {
        NSLog(@"No rules in 'data.rules'");
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
    
    NSLog(@"Loaded and registered %lu firewall rule objects", (unsigned long)total);
}

#pragma mark - 处理流
- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    os_log(firewallLog , "handleNewFlow start");
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        os_log(firewallLog , "[FLOW] Non-socket flow, allowing.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }

    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    NWHostEndpoint *remoteEP = (NWHostEndpoint *)socketFlow.remoteEndpoint;
    NWHostEndpoint *localEP  = (NWHostEndpoint *)socketFlow.localEndpoint;
    NSString *remoteHostName = nil;
    //获取远程主机名：可能为ip
    if(nil != socketFlow.URL.host){
        remoteHostName = socketFlow.URL.host;
    }else if(nil != socketFlow.remoteHostname){
        remoteHostName = socketFlow.remoteHostname;
    }else if(nil != remoteEP.hostname){
        remoteHostName = remoteEP.hostname;
    }
    //获取远程端口
    NSInteger remotePort = [remoteEP.port integerValue];
    //获取本地端口
    NSInteger localPort  = [localEP.port integerValue];
    //方向
    NETrafficDirection direction = socketFlow.direction;
    FlowDirection dir = (direction == NETrafficDirectionOutbound)
                        ? FlowDirectionOutbound
                        : FlowDirectionInbound;
    //方向字符串
    NSString *directionStr = (direction == NETrafficDirectionOutbound) ? @"OUT" : @"IN";
    //协议字符串
    NSString *protoStr = @"";
    //协议
    TransportProtocol proto;

    if (socketFlow.socketProtocol == NENetworkRuleProtocolTCP) {
        proto = TransportProtocolTCP;
        protoStr = @"TCP";
    } else if (socketFlow.socketProtocol == NENetworkRuleProtocolUDP) {
        proto = TransportProtocolUDP;
        protoStr = @"UDP";
    } else {
        protoStr = @"OTHER";
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    // 初始化日志结构体
    FlowLogEntry logEntry = {0}; // 清零

    // 填充字段
    strncpy(logEntry.remoteHostname, remoteHostName.UTF8String, sizeof(logEntry.remoteHostname) - 1);
    logEntry.remotePort = (int)remotePort;
    logEntry.localPort = (int)localPort;
    strncpy(logEntry.direction, [directionStr UTF8String], sizeof(logEntry.direction) - 1);
    strncpy(logEntry.protocol, [protoStr UTF8String], sizeof(logEntry.protocol) - 1);

    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    FirewallRule *matchedRule = [manager firstMatchedRuleForHostname:remoteHostName
                                                           remotePort:remotePort
                                                            localPort:localPort
                                                             protocol:proto
                                                            direction:dir];
    if (matchedRule) {
        NSString *ruleName = matchedRule.policyName ?: @"NULL";
        strncpy(logEntry.matchedRule, ruleName.UTF8String, sizeof(logEntry.matchedRule) - 1);

        if (!matchedRule.allow) {
            strncpy(logEntry.verdict, "BLOCK", sizeof(logEntry.verdict) - 1);
            os_log(firewallLog , "[BLOCK] Blocked by rule: %{public}@", ruleName);
            [self appendFlowLogToFile:&logEntry];
            return [NEFilterNewFlowVerdict dropVerdict];
        } else {
            strncpy(logEntry.verdict, "ALLOW", sizeof(logEntry.verdict) - 1);
            os_log(firewallLog , "[ALLOW] Allowed by rule: %{public}@", ruleName);
        }
    } else {
        strncpy(logEntry.verdict, "ALLOW", sizeof(logEntry.verdict) - 1);
        os_log(firewallLog , "[ALLOW] No matching rule, default allow.");
    }

    [self appendFlowLogToFile:&logEntry];
    return [NEFilterNewFlowVerdict allowVerdict];
}

#pragma mark - 将flow中的所有元数据加载到结构体，存入文本文件中
- (void)appendFlowLogToFile:(const FlowLogEntry *)entry {
    @autoreleasepool {
        NSString *logPath = myFile;
        
        // 构造日志行
        NSString *logLine = [NSString stringWithFormat:
            @"%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
            entry->remoteHostname,
            entry->remotePort,
            entry->localPort,
            entry->direction,
            entry->protocol,
            entry->verdict,
            entry->matchedRule[0] ? entry->matchedRule : "(none)"
        ];

        NSFileHandle *file = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (!file) {
            // 文件不存在，先创建
            [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
            file = [NSFileHandle fileHandleForWritingAtPath:logPath];
        }
        if (!file) {
            os_log(firewallLog ,"ERROR: Cannot open log file at %{public}@", logPath);
            return;
        }else{
            [file seekToEndOfFile];
            [file writeData:[logLine dataUsingEncoding:NSUTF8StringEncoding]];
            [file closeFile];
            
            [[IPCConnection shared] sendStr:logLine whthCompletionHandler:^(bool success){
                if (!success)
                {
                    os_log(firewallLog , "Unable to send packet to app.");
                }else{
                    os_log(firewallLog , "connect with main App success");
                }
            }];
        }
    }
}


- (NEFilterDataVerdict *)handleOutboundDataCompleteForFlow:(NEFilterFlow *)flow {
    os_log(firewallLog , "handleOutboundDataCompleteForFlow");
    return [NEFilterDataVerdict allowVerdict];
}

- (NEFilterDataVerdict *)handleInboundDataCompleteForFlow:(NEFilterFlow *)flow {
    os_log(firewallLog , "handleInboundDataCompleteForFlow");
    return [NEFilterDataVerdict allowVerdict];
}
//
//+ (void)initialize{
//    dispatch_once(&onceToken, ^{
//        gIPToHostnameMap = [[NSMutableDictionary alloc] init];
//    });
//}

//static ParsedPacketInfo parsePacket(const void *packetBytes, size_t packetLength) {
//    ParsedPacketInfo info = {0};
//    info.isValid = NO;
//
//    if (packetLength < 20) return info; // IPv4 最小 20 字节
//
//    const uint8_t *bytes = (const uint8_t *)packetBytes;
//
//    // IPv4: Version and IHL
//    uint8_t versionIHL = bytes[0];
//    if ((versionIHL >> 4) != 4) return info; // 不是 IPv4
//
//    uint8_t ihl = (versionIHL & 0x0F) * 4;
//    if (ihl < 20 || packetLength < ihl) return info;
//
//    uint8_t protocol = bytes[9];
//    uint32_t srcIP = *(uint32_t *)(bytes + 12);
//    uint32_t dstIP = *(uint32_t *)(bytes + 16);
//
//    // 端口只对 TCP/UDP 有意义
//    uint16_t srcPort = 0, dstPort = 0;
//
//    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
//        if (packetLength < ihl + 4) return info;
//        srcPort = *(uint16_t *)(bytes + ihl);
//        dstPort = *(uint16_t *)(bytes + ihl + 2);
//        // 注意：网络字节序，但比较时保持一致即可
//    }
//
//    info.srcIP = srcIP;
//    info.dstIP = dstIP;
//    info.srcPort = ntohs(srcPort);
//    info.dstPort = ntohs(dstPort);
//    info.isValid = YES;
//
//    if (protocol == IPPROTO_TCP) {
//        info.protocol = @"tcp";
//    } else if (protocol == IPPROTO_UDP) {
//        info.protocol = @"udp";
//    } else if (protocol == IPPROTO_ICMP) {
//        info.protocol = @"icmp";
//    } else {
//        info.protocol = @"other";
//    }
//
//    return info;
//}

@end


