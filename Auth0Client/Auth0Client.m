#import "Auth0Client.h"
#import "Auth0WebViewController.h"
#import "Auth0User.h"

@implementation Auth0Client

@synthesize clientId = _clientId;
@synthesize clientSecret = _clientSecret;
@synthesize domain = _domain;
@synthesize scope = _scope;
@synthesize auth0User = _auth0User;

NSString *AuthorizeUrl = @"https://%@/authorize?client_id=%@&scope=%@&redirect_uri=%@&response_type=token&connection=%@";
NSString *LoginWidgetUrl = @"https://%@/login/?client=%@&scope=%@&redirect_uri=%@&response_type=token";
NSString *ResourceOwnerEndpoint = @"https://%@/oauth/ro";
NSString *ResourceOwnerBody = @"client_id=%@&client_secret=%@&connection=%@&username=%@&password=%@&grant_type=password&scope=%@";
NSString *UserInfoEndpoint = @"https://%@/userinfo?%@";
NSString *DefaultCallback = @"https://%@/mobile";

- (id)initAuth0Client:(NSString *)domain clientId:(NSString *)clientId clientSecret:(NSString *)clientSecret
{
    return [self initAuth0Client:domain clientId:clientId clientSecret:clientSecret scope:@"openid"];
}

- (id)initAuth0Client:(NSString *)domain clientId:(NSString *)clientId clientSecret:(NSString *)clientSecret scope:(NSString *)scope
{
    if ((self = [super init])) {
        _clientId = [clientId copy];
        _domain = [domain copy];
        _clientSecret = [clientSecret copy];
        _scope = [scope copy];
    }
    
    return self;
}

- (void)dealloc
{
}

+ (Auth0Client*)auth0Client:(NSString *)domain clientId:(NSString *)clientId clientSecret:(NSString *)clientSecret
{
    static Auth0Client *instance = nil;
    static dispatch_once_t predicate;
    
    dispatch_once(&predicate, ^{ instance = [[Auth0Client alloc] initAuth0Client:domain clientId:clientId clientSecret:clientSecret]; });
    
    return instance;
}

+ (Auth0Client*)auth0Client:(NSString *)domain clientId:(NSString *)clientId clientSecret:(NSString *)clientSecret scope:(NSString *)scope
{
    static Auth0Client *instance = nil;
    static dispatch_once_t predicate;
    
    dispatch_once(&predicate, ^{ instance = [[Auth0Client alloc] initAuth0Client:domain clientId:clientId clientSecret:clientSecret scope:scope]; });
    
    return instance;
}

- (Auth0WebViewController*)getAuthenticator:(NSString *)connection scope:(NSString *)scope withCompletionHandler:(void (^)(BOOL authenticated))block
{
    NSString *callback = [NSString stringWithFormat:DefaultCallback, _domain];
    NSString *url = [NSString stringWithFormat:LoginWidgetUrl,
                     _domain,
                     _clientId,
                     [self urlEncode:scope],
                     callback];
    
    if (connection != nil) {
        url = [NSString stringWithFormat:AuthorizeUrl,
                         _domain,
                         _clientId,
                         [self urlEncode:scope],
                         callback, connection];
    }
    
    Auth0WebViewController *webController = [[Auth0WebViewController alloc] initWithAuthorizeUrl:[NSURL URLWithString:url] returnUrl:callback allowsClose:NO withCompletionHandler:^(NSString *token, NSString * jwtToken){
        if (token) {
            
            [self getUserInfo:token withCompletionHandler:^(NSMutableDictionary* profile) {
                
                NSMutableDictionary* accountProperties = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                                   token ?: [NSNull null], @"access_token",
                                                   jwtToken?: [NSNull null], @"id_token",
                                                   profile?: [NSNull null], @"profile",
                                                   nil];
                
                _auth0User = [Auth0User auth0User:accountProperties];
                block(true);
            }];
        }
        else {
            block(false);
        }
    }];
    
    return webController;
}

- (void)loginAsync:(UIViewController *)controller withCompletionHandler:(void (^)(BOOL authenticated))block
{
    [self loginAsync:controller connection:nil scope:_scope withCompletionHandler:(void (^)(BOOL authenticated))block];
}

- (void)loginAsync:(UIViewController *)controller scope:(NSString *)scope withCompletionHandler:(void (^)(BOOL authenticated))block
{
    [self loginAsync:controller connection:nil scope:scope withCompletionHandler:(void (^)(BOOL authenticated))block];
}

- (void)loginAsync:(UIViewController *)controller connection:(NSString *)connection withCompletionHandler:(void (^)(BOOL authenticated))block
{
    [self loginAsync:controller connection:connection scope:_scope withCompletionHandler:(void (^)(BOOL authenticated))block];
}

- (void)loginAsync:(UIViewController *)controller connection:(NSString *)connection scope:(NSString *)scope withCompletionHandler:(void (^)(BOOL authenticated))block
{
    Auth0WebViewController * webController = (Auth0WebViewController *)[self getAuthenticator:connection scope:scope withCompletionHandler:^(BOOL  authenticated)
    {
        block(authenticated);
        [controller dismissViewControllerAnimated:YES completion:nil];
    }];
    
    UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:webController];
    navController.navigationBar.barStyle = UIBarStyleBlack;
    
    [controller presentViewController:navController animated:YES completion:nil];
}

- (void)loginAsync:(UIViewController*)controller connection:(NSString *)connection username:(NSString *)username password:(NSString *)password withCompletionHandler:(void (^)(BOOL authenticated))block
{
    [self loginAsync:controller connection:connection username:username password:password scope:_scope withCompletionHandler:(void (^)(BOOL authenticated))block];
}

- (void)loginAsync:(UIViewController*)controller connection:(NSString *)connection username:(NSString *)username password:(NSString *)password scope:(NSString *)scope withCompletionHandler:(void (^)(BOOL authenticated))block;
{
    NSString *url = [NSString stringWithFormat:ResourceOwnerEndpoint, _domain];
    NSURL *resourceUrl = [NSURL URLWithString:url];
    
    NSString *postBody =[NSString stringWithFormat:ResourceOwnerBody, _clientId, _clientSecret, connection, username, password, [self urlEncode:scope]];
    
    NSData *postData = [ NSData dataWithBytes: [ postBody UTF8String ] length: [ postBody length ] ];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:resourceUrl];
    [request setHTTPMethod:@"POST"];
    
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:postData];
    
    [NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *error)
     {
         if (error == nil) {
             NSError* parseError;
             NSMutableDictionary* parseData = [[NSMutableDictionary alloc] initWithDictionary:[NSJSONSerialization
                                                                                 JSONObjectWithData:data
                                                                                 options:kNilOptions
                                                                                 error:&parseError]];
             
             NSString *accessToken = [parseData objectForKey:@"access_token"];
             
             if (accessToken) {
                 [self getUserInfo:accessToken withCompletionHandler:^(NSMutableDictionary* profile) {
                     [parseData setObject:profile forKey:@"profile"];
                     _auth0User = [Auth0User auth0User:parseData];
                     block(true);
                 }];
             }
         }
     }];
}

- (void)logout
{
    _auth0User = nil;
    [Auth0WebViewController clearCookies];
}

- (void)getUserInfo:(NSString *)accessToken withCompletionHandler:(void (^)(NSMutableDictionary* profile))block
{
    if (![accessToken hasPrefix:@"access_token"])
    {
        accessToken = [NSString stringWithFormat:@"access_token=%@", accessToken];
    }
    
    NSString *url = [NSString stringWithFormat:UserInfoEndpoint, _domain, accessToken];
    NSURL *enpoint = [NSURL URLWithString:url];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:enpoint];
    [request setHTTPMethod:@"GET"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    
    [NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *error)
     {
         if (error == nil) {
             NSError* parseError;
             NSMutableDictionary* parseData = [[NSMutableDictionary alloc] initWithDictionary:[NSJSONSerialization
                                                                                 JSONObjectWithData:data
                                                                                 options:kNilOptions
                                                                                 error:&parseError]];
             block(parseData);
         }
     }];
}

-(NSString *)urlEncode:(NSString *)url {
	NSString *escapedString =
        (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(
            NULL,
            (__bridge CFStringRef) url,
            NULL,
            CFSTR("!*'();:@&=+$,/?%#[]\" "),
            kCFStringEncodingUTF8));
    
    return escapedString;
}

@end
