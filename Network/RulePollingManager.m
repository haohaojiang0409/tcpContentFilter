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
@end

@implementation RulePollingManager

//每隔多少时间间隔拉取一次
-(instancetype _Nonnull )initWithURL:(NSURL * _Nonnull)url{
    if(self = [super init]){
        _url = url;
        //配置session
        NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.requestCachePolicy = NSURLRequestReloadIgnoringCacheData;
        config.timeoutIntervalForRequest = 15.0;
        config.timeoutIntervalForResource = 30.0;
        _session = [NSURLSession sessionWithConfiguration:config];
    }
    return self;
}

- (void)startPolling {
    //拉取一次json
    [self fetchJson];
}

- (void)stopPolling {

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
    [[NSURLSession sharedSession] dataTaskWithRequest:request
                                    completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {

        if (error) {
            NSLog(@"[RulePolling] Request failed: %@", error);
            return;
        }

        // 3. 解析 JSON
        NSError *jsonError = nil;
        NSDictionary *jsonDict =
            [NSJSONSerialization JSONObjectWithData:data
                                            options:NSJSONReadingMutableContainers
                                              error:&jsonError];

        if (jsonError || ![jsonDict isKindOfClass:[NSDictionary class]]) {
            NSLog(@"[RulePolling] JSON parse failed: %@", jsonError);
            return;
        }

        NSLog(@"[RulePolling] JSON received: %@", jsonDict);

        // 4. 调用回调
        if (self.onJSONReceived) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.onJSONReceived(jsonDict);
            });
        }
    }];

    //发送请求
    [task resume];
}

@end
