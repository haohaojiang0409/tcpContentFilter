//
//  XPCServer.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/1.
//

#import "XPCServer.h"

@implementation IPCConnection

static IPCConnection* _sharedInstance;
+(IPCConnection* _Nonnull)shared{
    if(nil == _sharedInstance){
        _sharedInstance = [IPCConnection new];
    }
    return _sharedInstance;
}

//从info中获取扩展服务名
- (NSString *)extensionMachServiceNameFromBundle:(NSBundle *_Nonnull)bundle
{
    NSDictionary *networkExtensionKeys = [bundle objectForInfoDictionaryKey:@"NetworkExtension"];
    if (nil != networkExtensionKeys)
    {
        NSString *machServiceName = networkExtensionKeys[@"NEMachServiceName"];
        if (nil == machServiceName)
        {
            NSLog(@"Mach service name is missing from the Info.plist");
        }else{
            NSLog(@"Mach service name is found");
        }
        return machServiceName;
    }

    return nil;
}

//开启XPC监听
- (void)startListener {
    NSString * machServiceName = [self extensionMachServiceNameFromBundle:[NSBundle mainBundle]];
    if(nil != machServiceName){
        NSLog(@"Starting XPC listener");
        NSXPCListener* newListener = [[NSXPCListener alloc] initWithMachServiceName:machServiceName];
        newListener.delegate = self;
        [newListener resume];
        self.listener = newListener;
    }
}

- (void)registerWithExtension:(NSBundle *)bundle
                 withDelegate:(NSObject<AppCommunication> *)delegate
        withCompletionHandler:(void (^)(bool success))completionHandler{
    self.delegate = delegate;

    if (nil != self.connection)
    {
        NSLog(@"Already registered with the provider");
        completionHandler(true);
        return;
    }

    NSXPCConnectionOptions options = {0};
    NSString *machServiceName = [self extensionMachServiceNameFromBundle:bundle];

    NSXPCConnection *newConnection = [[NSXPCConnection alloc] initWithMachServiceName:machServiceName options:options];

    // The exported object is the delegate.
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AppCommunication)];
    newConnection.exportedObject = delegate;

    // The remote object is the provider's IPCConnection instance.
    newConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProviderCommunication)];

    self.connection = newConnection;
    [newConnection resume];

    NSObject<ProviderCommunication> *providerProxy =
    [newConnection remoteObjectProxyWithErrorHandler:^(NSError *_Nonnull registerError) {
        NSLog(@"Failed to register with the provider: %@", [registerError localizedDescription]);
        if (self.connection != nil)
        {
            [self.connection invalidate];
            self.connection = nil;
        }
        completionHandler(false);
    }];
    if (nil == providerProxy)
    {
        NSLog(@"Failed to create a remote object proxy for the provider");
    }
    else
    {
        [providerProxy registerWithCompletionHandler:completionHandler];
    }
}

-(BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection * )newConnection{
    //1.保存协议
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProviderCommunication)];
    newConnection.exportedObject = self;
    
    //2.保存远端对象（主APP）
    newConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AppCommunication)];
    
    newConnection.invalidationHandler = ^{
        self.connection = nil;
    };
    
    newConnection.interruptionHandler = ^{
        self.connection = nil;
    };
    
    self.connection = newConnection;
    [newConnection resume];
    
    return TRUE;
}

- (void)registerWithCompletionHandler:(void (^_Nonnull)(bool success))completionHandler
{
    NSLog(@"App registered");
    completionHandler(true);
}

//向主APP发送字符串内容，并把字符串内容显示在textFiled上
-(void)sendStr:(NSString*)str
whthCompletionHandler:(void (^_Nonnull)(bool success))reply{
    if(nil == self.connection){
        return;
    }
    //获取APP代理
    NSObject<AppCommunication>* appProxy = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *_Nonnull error) {
        NSLog(@"Failed to send data to app, err: %@", [error localizedDescription]);
        self.connection = nil;
        reply(false);
    }];
    
    //发送字符串
    NSMutableString* mesString = [NSMutableString stringWithFormat:@"%@" , str];
    if (nil != appProxy)
    {
        [appProxy showTextMessageWithMessage:mesString
                           completionHandler:reply];
    }
}
@end
