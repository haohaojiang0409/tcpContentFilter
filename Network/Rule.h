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
#import "const.h"

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

//规则中包含的进程拦截
@property (nonatomic , copy , nullable) NSArray<ProcessRule *> * processArr;

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

//是否和某个规则相同
- (BOOL)isEqualToRule:(FirewallRule *_Nullable)other;
@end





