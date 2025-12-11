//
//  Rule.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/21.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "tools.h"
#import "log.h"
#import "AppFilterProvider.h"
#import "Process.h"

// 方向
typedef NS_ENUM(NSUInteger, FlowDirection) {
    FlowDirectionOutbound,
    FlowDirectionInbound
};

// 协议
typedef NS_ENUM(NSUInteger, TransportProtocol) {
    TransportProtocolTCP,
    TransportProtocolUDP,
    TransportProtocolICMP,
    TransportProtocolUnknown
};

#pragma mark -- 复合键生成器：将「方向+协议」转为唯一字符串Key
@interface RuleCompositeKeyGenerator : NSObject
// 生成复合键（方向：in/out + 协议：tcp/udp/icmp）
+ (NSString *)compositeKeyWithDirection:(NSString *)direction protocol:(NSString *)protocol;
// 从复合键解析方向和协议（反向解析，用于规则管理）
+ (NSDictionary<NSString *, NSString *> *)parseDirectionAndProtocolFromCompositeKey:(NSString *)compositeKey;
@end

///入站只需要匹配目的地址和目的端口
///出站则源地址和源端口号

#pragma mark - ip、端口结构 存储起始端口-结束端口 起始ip-结束ip
@interface fiveINetTuple : NSObject
//源ip
@property (nonatomic, assign) uint32_t ipStart;
//目的ip
@property (nonatomic, assign) uint32_t ipEnd;
//源端口
@property (nonatomic, assign) uint16_t portStart;
//目的端口
@property (nonatomic, assign) uint16_t portEnd;
//主机名
@property (nonatomic , copy , nullable) NSString* hostName;
//解析后的 IP 列表
- (instancetype _Nonnull )initWithIpStart:(uint32_t)ipStart
                         ipEnd:(uint32_t)ipEnd
                     portStart:(uint16_t)portStart
                       portEnd:(uint16_t)portEnd
                       hostName:(NSString*_Nonnull)hostName;

@end

#pragma mark -- 进程规则类（暂时只支持精细匹配）
@interface ProcessRule : NSObject <NSSecureCoding>

@property (nonatomic, copy) NSString * _Nullable processName;      // 进程名
@property (nonatomic, copy) NSString * _Nullable company;          // 公司名
@property (nonatomic, copy) NSString * _Nullable hash256;          // SHA-256 哈希
@property (nonatomic, copy) NSString * _Nullable processDescription;// 进程描述
@property (nonatomic, copy) NSString * _Nullable originFilename;   // 原始文件名
@property (nonatomic, copy) NSString * _Nullable productDescription;// 产品描述
@property (nonatomic, copy) NSString * _Nullable path;             // 可执行路径
@property (nonatomic, copy) NSString * _Nullable signer;           // 签名者

// 判断当前规则是否匹配给定的进程信息
- (BOOL)matchesProcess:(ProcessRule *_Nonnull)processInfo;

// C结构和OC对象的相互转化
+ (instancetype _Nonnull )ruleWithProcess:(Process *_Nonnull)process;

@end


#pragma mark -- 防火墙单个规则类
@interface FirewallRule : NSObject

/// 匹配方向：出站 / 入站
@property (nonatomic, assign) FlowDirection direction;

/// 传输层协议：TCP / UDP / ICMP
@property (nonatomic, strong) NSArray<NSNumber *> * _Nonnull protocolTypes;

@property (nonatomic, strong) NSArray<fiveINetTuple *> * _Nonnull fiveTuples;

#pragma mark - 进程信息
//规则中包含的进程拦截
@property (nonatomic , copy , nullable) NSArray<ProcessRule *> * processArr;

#pragma mark - 动作
/// 是否允许通过（YES = 放行，NO = 拦截）
@property (nonatomic, assign) BOOL allow;

/// 策略名称（如 "chr_test"）
@property (nonatomic, copy, nullable) NSString *policyName;

/// 策略唯一ID
@property (nonatomic, copy, nullable) NSString *policyId;

/// 安全等级（数值越大越严重？）
@property (nonatomic, assign) NSInteger level;

/// 是否需要上报日志
@property (nonatomic, assign) BOOL shouldReport;

/// 多语言提示（可简化为只存英文，或用 NSDictionary）
@property (nonatomic, copy, nullable) NSString *localizedTitle;

@property (nonatomic, copy, nullable) NSString *localizedSuggestion;

/// 工厂方法：从 JSON 字典创建（可能返回多个规则）
+ (NSArray<FirewallRule *> *_Nonnull)rulesWithDictionary:(NSDictionary *_Nonnull)dict;

/// 初始化完整规则
- (instancetype _Nonnull )initWithDirection:(FlowDirection)direction
                                   protocol:(NSArray<NSNumber *> *_Nonnull)protocoltypes
                                 fiveTuples:(NSArray<fiveINetTuple *> *_Nonnull)fiveTuples
                                      allow:(BOOL)allow
                               processRules:(NSArray<ProcessRule*>* _Nullable) processRules;
/// 快捷方法：是否涉及 DNS（目的端口 53 且协议 UDP/TCP）
- (BOOL)isDNSRule;


@end

#pragma mark - 规则管理类，存储规则和方向-协议的对应关系
@interface FirewallRuleManager : NSObject

//复合键对应的一组规则
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableArray<FirewallRule *> *> * _Nonnull ruleGroups;

//队列
@property (nonatomic, strong) dispatch_queue_t _Nonnull syncQueue;

//存储ip和域名的映射：一个ip可能对应多个域名
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSArray<NSString *> *> * _Nonnull ipToHostnamesMap;

+ (instancetype _Nonnull )sharedManager;


/// 添加一条规则（自动按 direction + protocol 分组）
- (void)addRule:(FirewallRule *_Nonnull)rule;

/// 移除所有规则
- (void)removeAllRules;

/// 获取指定方向和协议的所有规则（用于匹配引擎）
- (NSArray<FirewallRule *> *_Nonnull)rulesForDirection:(FlowDirection)_direction
                                              protocol:(NSString*_Nonnull)_protocol;

/// 获取所有规则（用于 UI 展示、导出等）
- (NSArray<FirewallRule *> *_Nonnull)allRules;

- (BOOL)hostName:(NSString *_Nonnull)host matchesPattern:(NSString *_Nonnull)pattern;

//匹配出站的规则
-(FirewallRule*_Nonnull)firstMatchedRuleForOutBound:(NSString*_Nonnull)_remoteHostName
                                         remotePort:(NSString*_Nonnull)_remotePort
                                           protocol:(NSString*_Nonnull)_Protocol
                                            process:(Process* _Nonnull)_process;

//匹配入站的规则
-(FirewallRule*_Nonnull)firstMatchedRuleForInBound:(NSString*_Nonnull)_remoteIP
                                        localPort:(NSString*_Nonnull)_localPort
                                          protocol:(NSString*_Nonnull)_Protocol
                                            process:(Process* _Nonnull)_process;

- (BOOL)matchesProcess:(ProcessRule * _Nullable)processInfo  rules:(NSArray<FirewallRule *> *_Nullable)candidateRules;

@end



