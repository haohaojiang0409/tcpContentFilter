//
//  RulePollingManager.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/8.
//

#import "RulePollingManager.h"
// ✅ 类扩展：声明私有属性（包括 authToken）
@interface RulePollingManager ()
@property (nonatomic, strong) NSURLSession *session;

// 信号量用于同步等待
@property (nonatomic, strong) dispatch_semaphore_t loadSemaphore;

// 标记是否为首次加载
@property (nonatomic, assign) BOOL isInitialLoad;

// 保存最后一次加载错误
@property (nonatomic, strong) NSError *lastLoadError;
@end

@implementation RulePollingManager

//每隔多少时间间隔拉取一次
-(instancetype _Nonnull )initWithURL:(NSURL * _Nonnull)url{
    if(self = [super init]){
        _url = url;
        //配置默认session
        NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
        //强制忽略本地缓存
        config.requestCachePolicy = NSURLRequestReloadIgnoringCacheData;
        //单次请求的超时时间
        config.timeoutIntervalForRequest = 15.0;
        //整个资源的总加载时间
        config.timeoutIntervalForResource = 30.0;
        _session = [NSURLSession sessionWithConfiguration:config];
        
        //初始化信号量
        _loadSemaphore = dispatch_semaphore_create(0);
        _isInitialLoad = YES;
    }
    return self;
}

- (void)startPolling {
    //拉取一次json
    [self fetchJson];
    // 创建 GCD Timer
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
    self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

    // 设置为每隔 10 分钟触发一次
    uint64_t interval = 600ull * NSEC_PER_SEC;

    dispatch_source_set_timer(self.timer,
                              dispatch_time(DISPATCH_TIME_NOW, interval),
                              interval,
                              5ull * NSEC_PER_SEC);  // 允许 5 秒误差

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.timer, ^{
        [weakSelf fetchJson];
    });

    dispatch_resume(self.timer);
}

- (void)stopPolling {
    if (self.timer) {
        dispatch_source_cancel(self.timer);
        self.timer = nil;
    }
}

-(NSError *)waitForInitialLoadWithTimeout:(NSTimeInterval)timeout {
    if(!_isInitialLoad){
        return nil;
    }
    
    // 等待信号量
    dispatch_time_t waitTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
    long result = dispatch_semaphore_wait(self.loadSemaphore, waitTime);
    
    if (result == 0) {
        // 成功等待到信号量
        _isInitialLoad = NO; // 标记首次加载已完成
        return self.lastLoadError; // 返回加载错误（如果有的话）
    } else {
        // 超时
        return [NSError errorWithDomain:@"RulePollingError"
                                 code:-1
                             userInfo:@{NSLocalizedDescriptionKey:@"Initial rule load timeout"}];
    }
}

- (void)fetchJson {
    // 1. 构建URL http get请求
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:self.url];
    request.HTTPMethod = @"GET";

    // 设置 Cookie
    NSString *cookieString = @"__Host-brizoo-token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3NwLnByZS5lYWdsZXl1bi5jbi9zYW1sL21ldGFkYXRhIiwiZXhwIjoyMDc4MTE1MzMzLCJpYXQiOjE3NjI3NTUzMzMsIm5iZiI6MTc2Mjc1NTMzMywicHJpdmF0ZV9kYXRhIjoib2lsRVZOV2ZpYU1SRXE4SkU4dDNMaFI5dVBRNmxUVWR5OGQwejJjcTFMQ3ZDT0JLZ1RUVEtjQkN2RUlPZ1ZuaE1NVW11dHVhUjI0bnlSWmtPMnhIY3ZLZDc2V1FHV0k2Wi9XVXdiUm5DQ3BpRnRCREFjV1huSjd6WGx3NzZ5UjY2MDVINGNpY2t1WHpFSXRlekl2MzQyOFA0OUhwQnJMTFd5U1gvYXBaUkN3VjlvVDFXbTZ0ejd4Qmo0M1A0VkZmVEd2blV3UkNsT25uQnBVRmpPd1N3QkFCV1lTYjZOczczMzc4V1JzbDVNYk9hQWRIWEdROWZDVVFHdHRQRzBIdnY4TVh6ZmV4ZzluekF3cllIKzJ0UGV6SG9sWEtSU2t5UExSNm4xRVFQV3VaaVgwcnovRVZYd1QxblRKWnJyV2l5djFwaWk4ZkU4QlJvb00yeTRlRGwvU1dWM3NxMUlQVlVzY2xwa29aaHZNR2pTbGdVeU95OG5hSXZjWTJsRzdMU29kZ0dNeXc4QmcxYkk5VnRyWXJJYlNqQ2grLzBEQkRxaGo5clZSQ0hjeTdtN1pvallFZlRIYkhPSXpiYW1EN0x1enN2TU01WElZNWRGa2p5dmZlN2c9PSIsInB1YmxpY19kYXRhIjoie1wiaW5zX2lkXCI6XCJzcGFfNGY4MWQzNWEtMGExYy00NTYwLTgzODctNWY4NGJhMWU2NWU3XCJ9In0.iC2ZeUQBLQljvA4c4X1K-RMKnmZVhRUIdHkJ-yIymYFkRZ2XkzN3-rDqVtp_VXXzKvTp2qYz6oE1gzWGl4qtoDiUe5Vy2lQztl1QyTVExsVhgOd1pOl94g2qUr7bYEoMYEJV-FopvckeCkeJgVf7kDiSovYY1Tvdoc9DvayhuqXpfb2re734RC9CrXk-IE5xhi8PcW3LaL54jrK8ZGctfpU2U6rKyONx1ZuBnHvYLvgFj-5N2IDKUwuNBHp-gM7RuyQLM6xNVX8WV4NYHfImQB_N-Ltta2JOcaBvVePLYGJmevBGhiJWBChckfQAYbmrHpSZO9ZG1UmGwYBFggn8Zg";
    //设置cookie
    [request setValue:cookieString forHTTPHeaderField:@"Cookie"];
    
    // 设置接受返回结果
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    
    NSURLSessionDataTask *task =
    [self.session dataTaskWithRequest:request
                                    completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
        NSError* loadError = nil;
        if (error || !data ) {
            NSLog(@"[RulePolling] Request failed: %@", error);
            loadError = error ?: [NSError errorWithDomain:@"RulePollingError"
               code:-2
           userInfo:@{NSLocalizedDescriptionKey:@"No data received"}];
        }else {
            NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
            if(200 != httpResponse.statusCode){
                NSLog(@"[RulePolling] HTTP Error : %ld" , (long)httpResponse.statusCode);
                loadError = [NSError errorWithDomain:@"RulePollingError"
                                                             code:httpResponse.statusCode
                                                         userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"HTTP Error %ld", (long)httpResponse.statusCode]}];
            }else{
                // 3. 解析 JSON
                NSError *jsonError = nil;
                NSDictionary *jsonDict =
                    [NSJSONSerialization JSONObjectWithData:data
                                                    options:NSJSONReadingMutableContainers
                                                      error:&jsonError];

                if (jsonError || ![jsonDict isKindOfClass:[NSDictionary class]]) {
                    NSLog(@"[RulePolling] JSON parse failed: %@", jsonError);
                    loadError = jsonError ?: [NSError errorWithDomain:@"RulePollingError"
                          code:-3
                         userInfo:@{NSLocalizedDescriptionKey:@"Invalid JSON format"}];
                }else{
                    NSLog(@"[RulePolling] JSON received: %@", jsonDict);

                    // 4. 调用回调
                    if (self.onJSONReceived) {
                        self.onJSONReceived(jsonDict);
                    }
                }
            }
        }
        self.lastLoadError = loadError;
        
        dispatch_semaphore_signal(self.loadSemaphore);
    }];

    //发送请求
    [task resume];
}

@end
