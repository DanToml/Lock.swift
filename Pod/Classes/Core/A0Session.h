//  A0Session.h
//
// Copyright (c) 2014 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <Foundation/Foundation.h>

#import "A0SessionStorage.h"
#import "A0Token.h"
#import "A0UserProfile.h"

@interface A0Session : NSObject

@property (readonly, nonatomic) id<A0SessionStorage> storage;
@property (readonly, nonatomic) A0Token *token;
@property (readonly, nonatomic) A0UserProfile *profile;

- (instancetype)initWithSessionStorage:(id<A0SessionStorage>)sessionStorage;

- (BOOL)isExpired;

- (void)refreshWithSuccess:(void(^)(A0Token *))success failure:(void(^)(NSError *))failure;

- (void)clear;

+ (instancetype)newDefaultSession;

@end
