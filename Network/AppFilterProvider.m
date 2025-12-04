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
    
    // 1️⃣ 初始化规则管理器（单例已自动创建）
    FirewallRuleManager *rulesManager = [FirewallRuleManager sharedManager];
    // 2️⃣ 加载并注册 JSON 规则（内部会清空旧规则）
    [self loadAndRegisterFirewallRules];

    //3 初始化日志变量
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

#pragma mark - 处理新到来的流
//1.建立连接之前还是之后：建立连接之前
//2.扩展截获的是发往所有网卡的数据包？可以选，默认所有网卡
//3.IPPROTO_UDP 和 NENetworkRuleProtocolUDP的区别？ 前者是应用于socket层，后者应用于IP层
- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        os_log(firewallLog , "[FLOW] Non-socket flow, allowing.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        return [NEFilterNewFlowVerdict allowVerdict];
    }

    // 标记所有流都要数据
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO peekInboundBytes:0 filterOutbound:YES peekOutboundBytes:64];

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
            //是DNS就保存域名和ip的对应关系
            NSString* domain = [self parseDNSQueryDomain:readBytes];
            os_log(firewallLog , "[ID : %{public}@ ]DNS Query: %{public}@",flow.identifier, domain);
            if ([domain hasSuffix:@".example.com"]) {
                return [NEFilterDataVerdict dropVerdict]; // 拦截
            }
        }else{
            os_log(firewallLog ,"---- %{public}@  isUDPFlow ----",flow.identifier);
            matchedRule = [manager firstMatchedRuleForOutBound:remoteHostName remotePort:port protocol:@"udp"];
            if(matchedRule && matchedRule.allow == NO){
                os_log(firewallLog, "==== firewallRule is matched : %{public}@ ",remoteHostName);
                return [NEFilterDataVerdict dropVerdict];
            }
        }
    }else{
        os_log(firewallLog ,"---- %{public}@  is not socket Flow ----" , flow.identifier);
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

#pragma mark -- 此函数暂时用不到 DNS报文解析获取域名用
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

#pragma mark -- 处理入站的流，暂未开发
- (NEFilterDataVerdict *) handleInboundDataFromFlow:(NEFilterFlow *) flow
                                readBytesStartOffset:(NSUInteger) offset
                                           readBytes:(NSData *) readBytes{
    NEFilterSocketFlow* socketFlow = (NEFilterSocketFlow*)flow;
    NSString* remoteHostName = nil;
    NWHostEndpoint* remoteEP = socketFlow.remoteEndpoint;
    //1.获取远程IP
    remoteHostName = remoteEP.hostname;
    os_log(firewallLog , "---- %{public}@ socket remoteEP ip Name:%{public}@ is not nil " , flow.identifier , remoteHostName);
    
    //2.进行入站匹配
    NSDate *currentDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    NSString *currentTimeString = [dateFormatter stringFromDate:currentDate];
    
    // 打印流ID和当前时间
    os_log(firewallLog , "Flow ID: %{public}@, Time: %{public}@ ", flow.identifier, currentTimeString);
    
    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    return [NEFilterDataVerdict allowVerdict];
}

@end

    
    
