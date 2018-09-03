//
//  HFHttpRequest.h
//  Test
//
//  Created by hongfei xu on 2018/6/27.
//  Copyright © 2018年 xuhongfei. All rights reserved.
//

#import <Foundation/Foundation.h>
//#import <AFNetworking/AFNetworking.h>

@interface HFHttpRequest : NSObject

+ (void)setupHttpRequestHeader:(NSDictionary *)headers;

#pragma mark - get
+ (void)getWithURLString:(NSString *)URLString success:(void (^)(id responseObject))success failure:(void (^)(NSError *error))failure;

#pragma mark - post
+ (void)postWithURLString:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(id responseObject))success failure:(void (^)(NSError *error))failure;


@end
