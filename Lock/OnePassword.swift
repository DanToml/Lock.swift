// OnePassword.swift
//
// Copyright (c) 2017 Auth0 (http://auth0.com)
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

import Foundation

protocol PasswordManager {
    var fields: [String: InputField] { get set }

    static func isAvailable() -> Bool
    func login(callback: @escaping (Error?, [String: InputField]?) -> Void)
    func store(withPolicy policy: [String: Any]?, callback: @escaping (Error?, [String: InputField]?) -> Void)
}

class OnePassword: PasswordManager {

    let config: PasswordManagerConfig
    weak var controller: UIViewController?
    var fields: [String: InputField] = [:]

    required init(withConfig config: PasswordManagerConfig, controller: UIViewController?) {
        self.config = config
        self.controller = controller
    }

    static func isAvailable() -> Bool {
        return LockOnePasswordExtension.shared().isAppExtensionAvailable()
    }

    func login(callback: @escaping (Error?, [String: InputField]?) -> Void) {
        guard let controller = self.controller else { return }
        LockOnePasswordExtension.shared().findLogin(forURLString: self.config.appIdentifier, for: controller, sender: nil) { (result, error) in
            guard error == nil else {
                return callback(error, nil)
            }
            self.fields[AppExtensionUsernameKey]?.text = result?[AppExtensionUsernameKey] as? String
            self.fields[AppExtensionPasswordKey]?.text = result?[AppExtensionPasswordKey] as? String
            callback(nil, self.fields)
        }
    }

    func store(withPolicy policy: [String: Any]?, callback: @escaping (Error?, [String: InputField]?) -> Void) {
        guard let controller = self.controller else { return }
        var loginDetails: [String: String] = [ AppExtensionTitleKey: self.config.displayName ]
        self.fields.forEach { loginDetails[$0] = $1.text }
        LockOnePasswordExtension.shared().storeLogin(forURLString: self.config.appIdentifier, loginDetails: loginDetails, passwordGenerationOptions: policy, for: controller, sender: nil) { (result, error) in
            guard error == nil else {
                return callback(error, nil)
            }
            self.fields[AppExtensionUsernameKey]?.text = result?[AppExtensionUsernameKey] as? String
            self.fields[AppExtensionPasswordKey]?.text = result?[AppExtensionPasswordKey] as? String
            callback(nil, self.fields)
        }
    }
}

public struct PasswordManagerConfig {
    public var isEnabled: Bool = true
    public let appIdentifier: String
    public let displayName: String

    public init() {
        self.appIdentifier = Bundle.main.bundleIdentifier!
        self.displayName = Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as! String
    }

    public init(appIdentifier: String, displayName: String) {
        self.appIdentifier = appIdentifier
        self.displayName = displayName
    }
}
