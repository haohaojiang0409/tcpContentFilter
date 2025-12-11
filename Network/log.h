//
//  Logger.h
//  BorderControl
//
//  Created by YourName on 2025/12/10.
//

#import <Foundation/Foundation.h>
#import <os/log.h>

#import "const.h"
NS_ASSUME_NONNULL_BEGIN
static os_log_t osLog = NULL;

typedef NS_ENUM(NSUInteger, LoggerLevel) {
    LoggerLevelDebug = 0,    // 调试信息
    LoggerLevelInfo,         // 一般信息
    LoggerLevelWarning,      // 警告
    LoggerLevelError,        // 错误
    LoggerLevelFatal         // 致命错误
};

@interface Logger : NSObject

/**
 *  获取单例实例
 */
+ (instancetype)sharedLogger;

/**
 *  设置日志级别（低于此级别的日志不会输出）
 */
- (void)setLogLevel:(LoggerLevel)level;

/**
 *  设置是否输出到文件
 */
- (void)setFileOutput:(BOOL)enabled;

/**
 *  设置日志文件路径
 */
- (void)setLogFile:(NSString *)filePath;

/**
 *  设置日志文件最大大小（字节），超过会自动轮转
 */
- (void)setMaxFileSize:(NSUInteger)maxSize;

#pragma mark - 日志输出方法

- (void)debug:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);
- (void)info:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);
- (void)warning:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);
- (void)error:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);
- (void)fatal:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);

#pragma mark - 内部使用方法

- (void)logWithLevel:(LoggerLevel)level
            category:(NSString *)category
              format:(NSString *)format, ... NS_FORMAT_FUNCTION(3,4);

@end

NS_ASSUME_NONNULL_END
