//
//  DomainIPMapping.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/5.
//
// DomainIPMapping.h
// DomainIPCache.h
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DomainIPCache : NSObject

+ (instancetype)sharedCache;

/// 添加域名到IP的映射（一个域名可对应多个IP）
- (void)addMappingForDomain:(NSString *)domain ip:(NSString *)ip;

/// 根据IP反查域名（返回最近一次解析该IP时对应的域名）
- (nullable NSString *)domainForIP:(NSString *)ip;

/// 清空缓存（调试用）
- (void)clear;

@end

NS_ASSUME_NONNULL_END
