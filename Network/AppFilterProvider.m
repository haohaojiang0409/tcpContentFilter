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
//1.建立连接之前还是之后：建立连接之前
//2.扩展截获的是发往所有网卡的数据包？可以选，默认所有网卡
//3.IPPROTO_UDP 和 NENetworkRuleProtocolUDP的区别？ 前者是应用于socket层，后者应用于IP层
- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    os_log(firewallLog , "handleNewFlow start");
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        os_log(firewallLog , "[FLOW] Non-socket flow, allowing.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        return [NEFilterNewFlowVerdict allowVerdict];
    }
//    NWEndpoint *remote = socketFlow.remoteEndpoint;
//    NSString* _strHostName = ((NWHostEndpoint *)remote).hostname;
//    NSString* _port = ((NWHostEndpoint *)remote).port;
//    NSLog(@"New flow: %@:%@", _strHostName , _port);
    
    // 标记所有流都要数据
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:64 filterOutbound:YES peekOutboundBytes:64];
    
//    //方向
//    NETrafficDirection direction = socketFlow.direction;
//    
//    FlowDirection dir = (direction == NETrafficDirectionOutbound) ? FlowDirectionOutbound : FlowDirectionInbound;
//    //方向字符串
//    NSString *directionStr = (direction == NETrafficDirectionOutbound) ? @"OUT" : @"IN";
//    if (socketFlow.socketProtocol == NENetworkRuleProtocolTCP && [directionStr isEqualToString:@"OUT"]) {
//        NSString* protoStr = @"TCP";
//        os_log(firewallLog , "Protocol: %{public}@", protoStr);
//        os_log(firewallLog , "Flow direction: %{public}@", directionStr);
//        return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO peekInboundBytes:0 filterOutbound:YES peekOutboundBytes:128];
//    } else if (socketFlow.socketProtocol == NENetworkRuleProtocolUDP && [directionStr isEqualToString:@"OUT"]) {
//        NSString* protoStr = @"UDP";
//        os_log(firewallLog , "Protocol: %{public}@", protoStr);
//        os_log(firewallLog , "Flow direction: %{public}@", directionStr);
//        return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO peekInboundBytes:0 filterOutbound:YES peekOutboundBytes:128];
//    } else if (socketFlow.socketProtocol == NENetworkRuleProtocolTCP && [directionStr isEqualToString:@"IN"]){
//        NSString* protoStr = @"TCP";
//        os_log(firewallLog , "Protocol: %{public}@", protoStr);
//        os_log(firewallLog , "Flow direction: %{public}@", directionStr);
//        return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:128 filterOutbound:NO peekOutboundBytes:0];
//    } else if (socketFlow.socketProtocol == NENetworkRuleProtocolUDP && [directionStr isEqualToString:@"IN"]){
//        NSString* protoStr = @"UDP";
//        os_log(firewallLog , "Protocol: %{public}@", protoStr);
//        os_log(firewallLog , "Flow direction: %{public}@", directionStr);
//        return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:128 filterOutbound:NO peekOutboundBytes:0];
//    } else {
//        NSLog(@"----the flow is other protocol，default allowed----");
//        return [NEFilterNewFlowVerdict allowVerdict];
//    }


//    FirewallRule *matchedRule = [manager firstMatchedRuleForHostname:remoteHostName
//                                                           remotePort:remotePort
//                                                            localPort:localPort
//                                                             protocol:proto
//                                                            direction:dir];
//    if (matchedRule) {
//        NSString *ruleName = matchedRule.policyName ?: @"NULL";
//
//        if (!matchedRule.allow) {
//            os_log(firewallLog , "[BLOCK] Blocked by rule: %{public}@", ruleName);
//            return [NEFilterNewFlowVerdict dropVerdict];
//        } else {
//            os_log(firewallLog , "[ALLOW] Allowed by rule: %{public}@", ruleName);
//        }
//    } else {
//        os_log(firewallLog , "[ALLOW] No matching rule, default allow.");
//    }
}
///建立连接之前就可以获取到流
- (NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow
                                readBytesStartOffset:(NSUInteger)offset
                                           readBytes:(NSData *)readBytes {
    os_log(firewallLog , "handleOutboundDataCompleteForFlow");
    
    // 打印流ID
    os_log(firewallLog , "Flow ID: %{public}@", flow.identifier);
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
    if(nil != socketFlow.URL.host){
        remoteHostName = socketFlow.URL.host;
        os_log(firewallLog ,"---- %{public}@ socket URL host:%{public}@ is not nil" , flow.identifier , remoteHostName);
    }else if(nil != socketFlow.remoteHostname){
        remoteHostName = socketFlow.remoteHostname;
        os_log(firewallLog ,"---- %{public}@ socket remoteHost Name:%{public}@ is not nil " , flow.identifier , remoteHostName);
    }else if(nil != remoteEP.hostname){
        remoteHostName = remoteEP.hostname;
        os_log(firewallLog ,"---- %{public}@ remoteEP hostname:%{public}@is not nil"  , flow.identifier , remoteHostName);
    }
    //2.判断是否是IPV4地址
    BOOL isIPv4 = NO;
    if (remoteHostName.length > 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, [remoteHostName UTF8String], &addr) == 1) {
            isIPv4 = YES;
            os_log(firewallLog, "---- %{public}@ host '%{public}@' is IPv4 address", flow.identifier, remoteHostName);
        } else {
            os_log(firewallLog, "---- %{public}@ host '%{public}@' is a domain name", flow.identifier, remoteHostName);
        }
    }
    if(IPPROTO_TCP == socketFlow.socketProtocol){
        os_log(firewallLog ,"---- %{public}@ isTCPFlow----",flow.identifier);
        ///出站只获取远端域名和远端端口即可
        //1.获取远程端口
        port = remoteEP.port;
        //2.判断域名是否为空
        if(!isIPv4){
            FirewallRule* matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName remotePort:port protocol:@"tcp"];
            if(matchedRule && matchedRule.allow == NO){
                os_log(firewallLog, "==== firewallRule is matched : %{public}@ ",remoteHostName);
                return [NEFilterDataVerdict dropVerdict];
            }
        }else{
            os_log(firewallLog ,"the remoteHostName is IPv4 address");
        }
    }else if(IPPROTO_UDP == socketFlow.socketProtocol){
        if([self isDNSFlow:flow]){
            //是DNS就保存域名和ip的对应关系
            NSString* domain = [self parseDNSQueryDomain:readBytes];
            os_log(firewallLog , "[ID : %{public}@ ]DNS Query: %{public}@",flow.identifier, domain);
            if ([domain hasSuffix:@"www.baidu.com"]) {
                return [NEFilterDataVerdict dropVerdict]; // 拦截
            }
        }else{
            os_log(firewallLog ,"---- %{public}@  isUDPFlow ----",flow.identifier);
        }
    }else{
        os_log(firewallLog ,"---- %{public}@  is not socket Flow ----" , flow.identifier);
    }
    
    return [NEFilterDataVerdict allowVerdict];
}

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

-(BOOL)isHTTPFlow:(NEFilterFlow*)flow{
    NEFilterSocketFlow* socketFlow = (NEFilterSocketFlow*)flow;
    NWEndpoint* remoteEndpoint = socketFlow.remoteEndpoint;

    NWHostEndpoint* hostEndpoint = (NWHostEndpoint*)remoteEndpoint;
    NSString* port = hostEndpoint.port;
    
    //HTTP标准是80
    return [port isEqualToString:@"80"];
}
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
                NSLog(@"------- point is not full ------ ");
                return nil; // 指针不完整
            }
            // 指针占 2 字节，高 2 位是标志，低 14 位是偏移
            uint16_t pointer = ((len & 0x3F) << 8) | bytes[index + 1];
            if (pointer >= 12) { // 偏移必须 >= 12（不能指向 header）
                index = pointer;
                jumpCount++;
                continue;
            } else {
                NSLog(@"------- point is not full ------ ");
                return nil; // 无效指针
            }
        }

        // 长度为 0 表示域名结束
        if (len == 0) {
            NSLog(@"------- len == 0 break ------ ");
            break;
        }

        // 普通标签
        if (index + 1 + len > data.length) {
            NSLog(@"------- index is beyond length ------ ");
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
        NSLog(@"----domain is nil----");
        return nil;
    }
    NSLog(@"---domain is got successfully----");
    return [domain copy];
}

- (NEFilterDataVerdict *) handleInboundDataFromFlow:(NEFilterFlow *) flow
                                readBytesStartOffset:(NSUInteger) offset
                                           readBytes:(NSData *) readBytes{

    return [NEFilterDataVerdict allowVerdict];
}

@end


