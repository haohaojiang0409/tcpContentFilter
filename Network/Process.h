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

NS_ASSUME_NONNULL_BEGIN
typedef struct {
    pid_t pid;
    char name[64];
    uint8_t sha256[32];
    BOOL hasSha256;
    char processPath[512];
}ProcessCoreData;


@interface Process : NSObject

// 从 NEAppProxyFlowMetadata 初始化
- (instancetype)initWithFlowMetadata:(NSData *)metadata;

// 基础信息（来自 metadata，无需额外权限）
@property (nonatomic, readonly, nullable) NSString *bundleIdentifier; // CFBundleIdentifier

// 派生信息（需文件访问，可能为 nil，受沙盒限制）
@property (nonatomic, readonly, nullable) NSString *bundlePath;

//apple数字签名
@property (nonatomic, readonly, nullable) NSDictionary<NSString *, id> *infoPlist;

// 安全属性
@property (nonatomic , copy)NSString* sha256HashStr; // 可执行文件 SHA256

- (void)logAllProperties;
@end

NS_ASSUME_NONNULL_END
