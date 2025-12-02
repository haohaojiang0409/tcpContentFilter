//
//  ViewController.m
//  BorderControl
//
//  Created by azimgd on 13.06.2023.
//

#import "ViewController.h"
#import "NetworkExtension.h"
@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];

  // Do any additional setup after loading the view.
}


- (void)setRepresentedObject:(id)representedObject {
  [super setRepresentedObject:representedObject];
  // Update the view, if already loaded.
    
}
- (IBAction)installButton:(id)sender {
    [[NetworkExtension shared] install];
}

//显示在控件上
- (void)showTextMessageWithMessage:(NSString *)message
               completionHandler:(void (^)(BOOL success))completionHandler {
    self.textField.stringValue = message;
    completionHandler(YES);
}
@end
