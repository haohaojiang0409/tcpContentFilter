//
//  RuleManager.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/16.
//
#pragma once

#import <Foundation/Foundation.h>
#import "Rule.h"
#import "const.h"

@class FirewallRule;
@class ProcessRule;

#pragma mark - 规则管理类，存储规则和方向-协议的对应关系
@interface FirewallRuleManager : NSObject

//复合键对应的一组规则
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableArray<FirewallRule *> *> * _Nonnull ruleGroups;

//队列
@property (nonatomic, strong) dispatch_queue_t _Nonnull syncQueue;

//存储ip和域名的映射：一个ip可能对应多个域名
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSArray<NSString *> *> * _Nonnull ipToHostnamesMap;

//存储规则集的哈希值
@property (nonatomic, copy , readonly) NSString * _Nullable lastRulesetHash;


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

//检测是否有更新
- (BOOL)reloadRulesIfNeededWithJSON:(NSArray<NSDictionary *> *_Nullable)ruleDictionaries;

//计算规则集哈希
- (NSString * _Nullable)hashForRuleGroups:(NSDictionary<NSString *, NSArray<FirewallRule *> *> *_Nonnull)groups;
@end



