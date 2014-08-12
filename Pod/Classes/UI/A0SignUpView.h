// A0SignUpView.h
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

#import <UIKit/UIKit.h>

#import "A0KeyboardEnabledView.h"
#import "A0ProgressDisplay.h"

@class A0SignUpCredentialValidator, A0ProgressButton;

typedef void(^A0SignUpBlock)(NSString *username, NSString *password);
typedef void(^A0CancelBlock)();

@interface A0SignUpView : UIView<A0KeyboardEnabledView, A0ProgressDisplay>

@property (copy, nonatomic) A0SignUpBlock signUpBlock;
@property (copy, nonatomic) A0CancelBlock cancelBlock;

@property (strong, nonatomic) A0SignUpCredentialValidator *validator;

@property (weak, nonatomic) IBOutlet UITextField *userTextField;
@property (weak, nonatomic) IBOutlet UITextField *passwordTextField;
@property (weak, nonatomic) IBOutlet A0ProgressButton *signUpButton;
@property (weak, nonatomic) IBOutlet UIButton *cancelButton;

@end