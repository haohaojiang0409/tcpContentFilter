//
//  main.m
//  DNSProxy
//
//  Created by haohaojiang0409 on 2025/12/1.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

int main(int argc, char *argv[])
{
    @autoreleasepool {
        [NEProvider startSystemExtensionMode];
    }
    
    dispatch_main();
}
