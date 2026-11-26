#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
// Only the Keychain access group configured in the signed entitlements.
FOUNDATION_EXPORT NSString *NEXProfileState(void);
FOUNDATION_EXPORT NSString * _Nullable NEXEnroll(NSString *server,NSString *name,NSString *invite,NSString *ca);
FOUNDATION_EXPORT NSString * _Nullable NEXForget(void);
FOUNDATION_EXPORT NSData * _Nullable NEXLoadCredential(NSError **error);
FOUNDATION_EXPORT NSURL * _Nullable NEXPrivateRoot(NSString *leaf,NSError **error);
FOUNDATION_EXPORT BOOL NEXProtectTree(NSURL *root,NSError **error);
NS_ASSUME_NONNULL_END
