//
//  Logger.m
//  BorderControl
//
//  Created by YourName on 2025/12/10.
//

#import "log.h"
#import <libkern/OSAtomic.h>

@interface Logger ()
@property (nonatomic, assign) LoggerLevel logLevel;
@property (nonatomic, assign) BOOL fileOutputEnabled;
@property (nonatomic, strong) NSString *logFilePath;
@property (nonatomic, assign) NSUInteger maxFileSize;
@property (nonatomic, strong) NSObject *logLock; // 用于线程安全
@end

@implementation Logger

#pragma mark - 单例实现

+ (instancetype)sharedLogger {
    static Logger *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[Logger alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    if (self = [super init]) {
        _logLevel = LoggerLevelDebug;
        _fileOutputEnabled = YES;
        _maxFileSize = LOG_FILE_MAXSIZE; // 10MB
        _logLock = [[NSObject alloc] init];
        if (osLog == NULL) {
            osLog = os_log_create("com.eagleyun.BorderControl", "Network");
        }
        // 设置默认日志文件路径
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *documentsDirectory = [paths firstObject];
        _logFilePath = [documentsDirectory stringByAppendingPathComponent:@"app.log"];
        os_log(osLog , "Documents Directory: %{public}@", _logFilePath);
    }
    return self;
}

#pragma mark - 配置方法(线程安全)
- (void)setLogLevel:(LoggerLevel)level {
    @synchronized(self.logLock) {
        _logLevel = level;
    }
}
- (void)setFileOutput:(BOOL)enabled {
    @synchronized(self.logLock) {
        _fileOutputEnabled = enabled;
    }
}
- (void)setLogFile:(NSString *)filePath {
    @synchronized(self.logLock) {
        _logFilePath = filePath;
    }
}
- (void)setMaxFileSize:(NSUInteger)maxSize {
    @synchronized(self.logLock) {
        _maxFileSize = maxSize;
    }
}

#pragma mark - 日志输出方法

- (void)debug:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:LoggerLevelDebug category:@"DEBUG" format:format arguments:args];
    va_end(args);
}

- (void)info:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:LoggerLevelInfo category:@"INFO" format:format arguments:args];
    va_end(args);
}

- (void)warning:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:LoggerLevelWarning category:@"WARN" format:format arguments:args];
    va_end(args);
}

- (void)error:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:LoggerLevelError category:@"ERROR" format:format arguments:args];
    va_end(args);
}

- (void)fatal:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:LoggerLevelFatal category:@"FATAL" format:format arguments:args];
    va_end(args);
}

#pragma mark - 内部实现方法

- (void)logWithLevel:(LoggerLevel)level
            category:(NSString *)category
              format:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    [self logWithLevel:level category:category format:format arguments:args];
    va_end(args);
}

- (void)logWithLevel:(LoggerLevel)level
            category:(NSString *)category
              format:(NSString *)format
           arguments:(va_list)args {
    
    // 检查日志级别
    if (level < self.logLevel) {
        return;
    }
    
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    NSString *timestamp = [self getCurrentTimestamp];
    NSString *threadInfo = [self getCurrentThreadInfo];
    
    NSString *logLine = [NSString stringWithFormat:@"%@ | %@ | %@ | %@\n",
                        timestamp, category, threadInfo, message];
    
    @synchronized(self.logLock) {
        // 输出到文件
        if (self.fileOutputEnabled) {
            [self writeToFile:logLine];
        }
    }
}

- (NSString *)getCurrentTimestamp {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    return [formatter stringFromDate:[NSDate date]];
}

- (NSString *)getCurrentThreadInfo {
    if ([NSThread isMainThread]) {
        return @"Main";
    } else {
        NSString *threadName = [NSThread currentThread].name;
        if (threadName && threadName.length > 0) {
            return [NSString stringWithFormat:@"Thread:%@", threadName];
        } else {
            return [NSString stringWithFormat:@"Thread:%p", [NSThread currentThread]];
        }
    }
}

- (void)writeToFile:(NSString *)logLine {
    @try {
        // 检查文件大小，如果超过限制则轮转
        if ([self shouldRotateLogFile]) {
            [self rotateLogFile];
        }
        
        // 追加写入日志
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
        if (!fileHandle) {
            // 文件不存在，创建新文件
            [[NSFileManager defaultManager] createFileAtPath:self.logFilePath
                                                    contents:nil
                                                  attributes:nil];
            fileHandle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
        }
        
        if (fileHandle) {
            [fileHandle seekToEndOfFile];
            NSData *data = [logLine dataUsingEncoding:NSUTF8StringEncoding];
            [fileHandle writeData:data];
            [fileHandle closeFile];
        }
    }
    @catch (NSException *exception) {
        // 避免日志系统自身出错影响主程序
        NSLog(@"Logger error: %@", exception.reason);
    }
}
- (BOOL)shouldRotateLogFile {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:self.logFilePath]) {
        return NO;
    }
    
    NSDictionary *attrs = [fileManager attributesOfItemAtPath:self.logFilePath error:nil];
    NSNumber *fileSize = attrs[NSFileSize];
    
    return [fileSize unsignedLongLongValue] > self.maxFileSize;
}

- (void)rotateLogFile {
    NSString *backupPath = [self.logFilePath stringByAppendingString:@".old"];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    // 删除旧的备份文件
    if ([fileManager fileExistsAtPath:backupPath]) {
        [fileManager removeItemAtPath:backupPath error:nil];
    }
    
    // 重命名当前日志文件为备份
    if ([fileManager fileExistsAtPath:self.logFilePath]) {
        [fileManager moveItemAtPath:self.logFilePath toPath:backupPath error:nil];
    }
}

@end
