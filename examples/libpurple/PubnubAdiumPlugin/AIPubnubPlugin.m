//
//  PubnubAdiumPlugin.m
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 4/28/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import "AIPubnubPlugin.h"
#import "ESPubnubService.h"

@implementation AIPubnubPlugin

extern void purple_init_pubnub_plugin();

- (void)installPlugin
{
    purple_init_pubnub_plugin();
    [ESPubnubService registerService];
}

- (void)uninstallPlugin
{
}

- (void)installLibpurplePlugin
{
}

- (void)loadLibpurplePlugin
{
}

- (NSString *)pluginAuthor
{
	return @"Alexey Yesipenko <alex7y@gmail.com>";
}

-(NSString *)pluginVersion
{
	return @"0.1";
}

-(NSString *)pluginDescription
{
	return @"Pubnub";
}

@end
