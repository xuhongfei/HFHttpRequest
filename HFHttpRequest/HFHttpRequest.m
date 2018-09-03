//
//  HFHttpRequest.m
//  Test
//
//  Created by hongfei xu on 2018/6/27.
//  Copyright © 2018年 xuhongfei. All rights reserved.
//

#import "HFHttpRequest.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

#import <AFNetworking/AFNetworkActivityIndicatorManager.h>
#import <AFNetworking/AFNetworking.h>


static NSDictionary *__headerFields;

NSString *const HFHttpRequestSHA1Secret = @"HFHttpRequestSHA1Secret";
NSString *const HFHttpRequestMD5Secret = @"HFHttpRequestMD5Secret";

@implementation HFHttpRequest

+ (void)setupHttpRequestHeader:(NSDictionary *)headers
{
    __headerFields = [headers copy];
}

#pragma mark -
+ (void)getWithURLString:(NSString *)URLString success:(void (^)(id))success failure:(void (^)(NSError *))failure
{
    NSString *urlString = [NSString stringWithFormat:@"%@", URLString];
    urlString = [urlString stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    
    if (![AFNetworkActivityIndicatorManager sharedManager].enabled) {
        [AFNetworkActivityIndicatorManager sharedManager].enabled = YES;
    }
    [[AFNetworkActivityIndicatorManager sharedManager] incrementActivityCount];
    
    // get
    AFHTTPSessionManager *manager = [self customSessionManagerWithURLString:urlString];
    [manager GET:urlString parameters:nil progress:^(NSProgress * _Nonnull downloadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        [[AFNetworkActivityIndicatorManager sharedManager] decrementActivityCount];
        if (success) {
            success(responseObject);
        }
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        [[AFNetworkActivityIndicatorManager sharedManager] decrementActivityCount];
        if (failure) {
            failure(error);
        }
    }];
}

+ (void)postWithURLString:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(id))success failure:(void (^)(NSError *))failure
{
    NSString *urlString = [NSString stringWithFormat:@"%@", URLString];
    urlString = [urlString stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    
    if (![AFNetworkActivityIndicatorManager sharedManager].enabled) {
        [AFNetworkActivityIndicatorManager sharedManager].enabled = YES;
    }
    [[AFNetworkActivityIndicatorManager sharedManager] incrementActivityCount];
    
    //外部参数与公共参数进行组合
    NSMutableDictionary *parametersM = [NSMutableDictionary dictionaryWithDictionary:[self customCommonParamters]];
    [parametersM addEntriesFromDictionary:parameters];
    
    //参数签名
    NSString *signedString = [self signWithParameters:[parametersM copy]];
    [parametersM addEntriesFromDictionary:@{@"sign": signedString}];
    
    //post
    AFHTTPSessionManager *manager = [self customSessionManagerWithURLString:urlString];
    [manager POST:urlString parameters:[parametersM copy] progress:^(NSProgress * _Nonnull uploadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        [[AFNetworkActivityIndicatorManager sharedManager] decrementActivityCount];
        
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            
            NSDictionary *responseDict = responseObject;
            NSInteger code = [[NSString stringWithFormat:@"%@", responseDict[@"code"]] integerValue];
            NSString *msg = [NSString stringWithFormat:@"%@", responseDict[@"msg"]];
            id data = responseObject[@"data"];
            
            //请求有效
            if (code == 0) {
                
                if (success) {
                    success(data);
                }
                
            } else {
                
                /*
                 * 全局特殊code处理，如用户token失效（即登出状态）时，发送用户登出通知
                 */
                
                
                /*
                 * code错误（请求无效）情况下，userInfo传出请求返回的原始结果，可以在请求调用处单独处理特殊code。
                 */
                NSError *error = [NSError errorWithDomain:msg code:code userInfo:responseDict];
                if (failure) {
                    failure(error);
                }
            }
            
        } else {
            NSError *error = [NSError errorWithDomain:@"数据错误" code:-2 userInfo:nil];
            if (failure) {
                failure(error);
            }
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        [[AFNetworkActivityIndicatorManager sharedManager] decrementActivityCount];
        if (failure) {
            failure(error);
        }
    }];
}

#pragma mark - 参数签名部分

+ (NSString *)signWithParameters:(NSDictionary *)parameters
{
    return [self signWithSortedParametersString:[self sortedParametersStringWithParamters:parameters]];
}

/*
 *  参数排序
 *  根据约定好的规则进行排序并组装字符串
 */
+ (NSString *)sortedParametersStringWithParamters:(NSDictionary *)parameters
{
    __block NSMutableString *stringM = [NSMutableString string];
    
    NSArray *sortedParametersArr = [[parameters allKeys] sortedArrayUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        return [obj1 compare:obj2 options:NSNumericSearch];
    }];
    
    [sortedParametersArr enumerateObjectsUsingBlock:^(NSString * _Nonnull key, NSUInteger idx, BOOL * _Nonnull stop) {
        [stringM appendFormat:@"%@%@", key, parameters[key]];
    }];
    
    return [stringM copy];
}

/*
 *  参数签名
 *  具体签名方式跟后端统一
 */
+ (NSString *)signWithSortedParametersString:(NSString *)sortedParametersString
{
    
//    //sha1
//    return [self sha1WithStr:sortedParametersString];
    
    //md5
    NSString *assemblageStr = [sortedParametersString stringByAppendingString:HFHttpRequestMD5Secret];
    return [self md5WithStr:assemblageStr];
}

//sha1
+ (NSString *)sha1WithStr:(NSString *)str
{
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    NSData *keyData = [HFHttpRequestSHA1Secret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *strData = [str dataUsingEncoding:NSUTF8StringEncoding];
    CCHmac(kCCHmacAlgSHA1, [keyData bytes], [HFHttpRequestSHA1Secret length], [strData bytes], [strData length], result);
    
    NSMutableString *authSignatureString = [NSMutableString string];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [authSignatureString appendFormat:@"%02X", result[i]];
    }
    return authSignatureString;
}

//md5
+ (NSString *)md5WithStr:(NSString *)str
{

    const char *original_str = [str UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(original_str, (unsigned int)strlen(original_str), result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
    {
        /*
         %02X是格式控制符：‘x’表示以16进制输出，‘02’表示不足两位，前面补0；
         */
        [hash appendFormat:@"%02X", result[i]];
    }
    NSString *mdfiveString = [hash lowercaseString];
    return mdfiveString;
}

#pragma mark -
//公共参数
+ (NSDictionary *)customCommonParamters
{
    NSMutableDictionary *dictM = [NSMutableDictionary dictionaryWithCapacity:0];
    
    /*
     *  手机系统信息（如手机系统版本）
     *  App信息（如App版本）
     *  其他信息（如时间）
     *  业务相关信息（如用户登录信息token），需判断是否存在进行添加
     */
    
    return [dictM copy];
}

//定义SessionManager
+ (AFHTTPSessionManager *)customSessionManagerWithURLString:(NSString *)URLString {
    
    NSURL *url = [NSURL URLWithString:URLString];
    NSString *baseURLString = [NSString stringWithFormat:@"%@://%@", url.scheme, url.host];
    NSURL *baseURL = [NSURL URLWithString:baseURLString];
    AFHTTPSessionManager *manager = [[AFHTTPSessionManager alloc] initWithBaseURL:baseURL];
    manager.requestSerializer.timeoutInterval = 10.0;
    manager.responseSerializer.acceptableContentTypes = [NSSet setWithObjects:@"text/plain", @"text/json", @"application/json", @"text/javascript", @"text/html", nil];
    
    // 设置请求头
    [__headerFields enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        [manager.requestSerializer setValue:obj forHTTPHeaderField:key];
    }];
    
//    if ([url.scheme isEqualToString:@"https"]) {
//        // 设置验证证书
//        [manager setSecurityPolicy:[self customSecurityPolicy]];
//        [manager.securityPolicy setAllowInvalidCertificates:YES];
//    }
    
    return manager;
}

+ (AFSecurityPolicy *)customSecurityPolicy {
    
    // 先导入证书
    // NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"365os.com" ofType:@"cer"];//证书的路径
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"STAR_dcoin_com" ofType:@"cer"];//证书的路径
    NSData *certData = [NSData dataWithContentsOfFile:cerPath];
    
    // AFSSLPinningModeCertificate 使用证书验证模式
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    // allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
    // 如果是需要验证自建证书，需要设置为YES
    securityPolicy.allowInvalidCertificates = YES;
    
    //validatesDomainName 是否需要验证域名，默认为YES；
    //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    //置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    //如置为NO，建议自己添加对应域名的校验逻辑。
    securityPolicy.validatesDomainName = NO;
    
    securityPolicy.pinnedCertificates = [NSSet setWithObject:certData];
    
    return securityPolicy;
    
}

@end
