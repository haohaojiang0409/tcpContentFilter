//
//  NetworkExtension.m
//  BorderControl
//
//  Created by azimgd on 13.06.2023.
//

#import <Foundation/Foundation.h>
#import "NetworkExtension.h"

//过滤数据包的网络插件
NSString *const networkExtensionBundleId = @"com.eagleyun.BorderControl.DNSProxy";

@implementation NetworkExtension

static NetworkExtension *sharedInstance = nil;

+ (NetworkExtension *)shared {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[NetworkExtension alloc] init];
  });
  return sharedInstance;
}

- (void)install
{
  OSSystemExtensionRequest *systemRequest = [OSSystemExtensionRequest
    activationRequestForExtension:networkExtensionBundleId
    queue:dispatch_get_main_queue()
  ];
  
  systemRequest.delegate = self;
  [OSSystemExtensionManager.sharedManager submitRequest:systemRequest];
}

#pragma OSSystemExtensionRequestDelegate

- (OSSystemExtensionReplacementAction)request:(nonnull OSSystemExtensionRequest *)request
  actionForReplacingExtension:(nonnull OSSystemExtensionProperties *)existing
  withExtension:(nonnull OSSystemExtensionProperties *)ext
{
  return OSSystemExtensionReplacementActionReplace;
}

- (void)request:(nonnull OSSystemExtensionRequest *)request
  didFailWithError:(nonnull NSError *)error
{
}

- (void)request:(nonnull OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result
{
//  [NEFilterManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
//    NEFilterProviderConfiguration* configuration = [[NEFilterProviderConfiguration alloc] init];
//    configuration.filterPackets = false;
//    configuration.filterPacketProviderBundleIdentifier = nil;
//
//    configuration.filterSockets = true;
//    configuration.filterDataProviderBundleIdentifier = networkExtensionBundleId;
//    
//    NEFilterManager.sharedManager.localizedDescription = networkExtensionBundleId;
//    NEFilterManager.sharedManager.enabled = true;
//      
//    NEFilterManager.sharedManager.providerConfiguration = configuration;
//
//    [NEFilterManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
//    }];
//  }];
    //provider protocol
    __block NEDNSProxyProviderProtocol* protocol =  nil;

    //load prefs
    [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        
        //err?
        if(nil != error)
        {
            return;
        }
        //set description
        NEDNSProxyManager.sharedManager.localizedDescription = @"DNS";
        
        //init protocol
        protocol = [[NEDNSProxyProviderProtocol alloc] init];
        
        //set provider
        protocol.providerBundleIdentifier = networkExtensionBundleId;
        
        //set protocol
        NEDNSProxyManager.sharedManager.providerProtocol = protocol;
        
        //enable
        NEDNSProxyManager.sharedManager.enabled = YES;
            
        //save preferences
        [NEDNSProxyManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if(nil != error)
            {
                NSLog(@"error occur : %@" , error);
                return;
            }
        }];
    }];
     
    return;
}

- (void)requestNeedsUserApproval:(nonnull OSSystemExtensionRequest *)request {
}

- (void)systemExtensionWillBecomeInactive:(OSSystemExtensionManager *)manager
                         request:(OSSystemExtensionRequest *)request {
    NSLog(@"扩展即将进入非活跃状态: %@", request.identifier);
}

@end
