//
//  RulePollingManager.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/8.
//
#pragma once

#import <Foundation/Foundation.h>
#import "log.h"
@interface RulePollingManager : NSObject

@property (nonatomic, strong) dispatch_source_t _Nullable timer;

@property (nonatomic, strong) NSURL * _Nullable url;

@property (nonatomic, copy) NSString * _Nullable authToken;
//每隔多少时间间隔拉取一次
-(instancetype _Nonnull )initWithURL:(NSURL * _Nonnull)url;

-(void)startPolling;

-(void)stopPolling;

- (void)fetchOnce;

-(NSError *_Nullable)waitForInitialLoadWithTimeout:(NSTimeInterval)timeout;

/// 成功回调（在主线程调用）
@property (nonatomic, copy, nullable) void (^onJSONReceived)(NSDictionary<NSString *, id> * _Nonnull json);

/// 错误回调（在主线程调用）
@property (nonatomic, copy, nullable) void (^onError)(NSError * _Nullable error);

@end
