//
//  ESPubnubJoinChatViewController.m
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/9/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import "ESPubnubJoinChatViewController.h"

@implementation ESPubnubJoinChatViewController

- (NSString *)nibName
{
    return @"ESPubnubJoinChatView";
}

- (void)joinChatWithAccount:(AIAccount *)inAccount
{
    NSString *channel = [_textfield_channel stringValue];
	NSMutableDictionary	*chatCreationInfo;
    
    if ([channel length]<1) {
        return;
    }
    chatCreationInfo = [NSMutableDictionary dictionaryWithObject:channel
                                            forKey:@"room"];
		
    [self doJoinChatWithName:channel
					   onAccount:inAccount
				chatCreationInfo:chatCreationInfo
				invitingContacts:nil
		   withInvitationMessage:nil];
		

    
}
@end
