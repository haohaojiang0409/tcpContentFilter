//
//  DomainIPMapping.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/5.
//

#import "DomainIPCache.h"

@interface DomainIPCache ()

//先用字符串存储域名，完成功能后续更换存储域名的数据结构
//因为负载均衡一个域名可能对应多个ip
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *domainToIPs;

//反向映射map：可根据ip找到对应域名，后续也需要更新，因为一个ip可能对应多个域名
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *ipToDomain; // 反向映射：IP -> 域名

@property (nonatomic, strong) dispatch_queue_t cacheQueue;

@end

#pragma mark -- 记录域名-->ip ip-->域名的映射
@implementation DomainIPCache


+ (instancetype)sharedCache {
    static DomainIPCache *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[DomainIPCache alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        _cacheQueue = dispatch_queue_create("com.yourapp.DomainIPCache", DISPATCH_QUEUE_SERIAL);
        _domainToIPs = [NSMutableDictionary dictionary];
        _ipToDomain = [NSMutableDictionary dictionary];
    }
    return self;
}

#pragma mark -- FUNC：添加域名和ip的映射
- (void)addMappingForDomain:(NSString *)domain ip:(NSString *)ip {
    dispatch_async(self.cacheQueue, ^{
        // 正向：domain -> set of IPs
        NSMutableSet *ipSet = self.domainToIPs[domain];
        if (!ipSet) {
            ipSet = [NSMutableSet set];
            self.domainToIPs[domain] = ipSet;
        }
        [ipSet addObject:ip];

        // 反向：IP -> domain（覆盖旧值，保留最新域名）
        self.ipToDomain[ip] = domain;
    });
}

#pragma mark -- FUNC：通过ip获取域名
- (nullable NSString *)domainForIP:(NSString *)ip {
    __block NSString *result = nil;
    dispatch_sync(self.cacheQueue, ^{
        result = self.ipToDomain[ip];
    });
    return result;
}

#pragma mark -- FUNC：清除map中所有映射
- (void)clear {
    dispatch_async(self.cacheQueue, ^{
        [self.domainToIPs removeAllObjects];
        [self.ipToDomain removeAllObjects];
    });
}

@end
