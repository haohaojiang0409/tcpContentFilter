//
//  Process.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/9.
//

// Process.h
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#import <bsm/libbsm.h>
#import "const.h"

#import "log.h"
NS_ASSUME_NONNULL_BEGIN

//进程元数据
typedef struct {
    pid_t pid;
    char name[64];
    uint8_t sha256[32];
    char processPath[PROC_PIDPATHINFO_MAXSIZE];
}ProcessCoreData;


@interface Process : NSObject

// 进程信息
- (instancetype)initWithFlowMetadata:(NSData *)metadata;

//apple数字签名
@property (nonatomic, readonly, nullable) NSDictionary<NSString *, id> *infoPlist;

// 安全属性
@property (nonatomic , copy)NSString* sha256HashStr; // 可执行文件 SHA256

- (void)logAllProperties;

-(ProcessCoreData)getCoreData;
@end

NS_ASSUME_NONNULL_END
