//
//  ESPubnubJoinChatViewController.h
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/9/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import <Adium/DCJoinChatViewController.h>

@interface ESPubnubJoinChatViewController : DCJoinChatViewController
@property (weak) IBOutlet NSTextField *textfield_channel;

@end
