//
//  ESPurplePubnubAccount.m
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/2/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import "ESPurplePubnubAccount.h"

@implementation ESPurplePubnubAccount

- (const char*)protocolPlugin
{
	return "prpl-avy-pubnub";
}

extern PurplePluginProtocolInfo pubnub_protocol_info;

- (PurplePluginProtocolInfo *)protocolInfo
{
    return &pubnub_protocol_info;
}

- (BOOL)connectivityBasedOnNetworkReachability
{
    return FALSE;
}

@end
