#import "ProfileStore.h"
#import <Security/Security.h>
#import <Mobile/Mobile.h>
#import <sys/stat.h>

static NSError *Err(NSString *message) { return [NSError errorWithDomain:@"NetworkEX.Profile" code:1 userInfo:@{NSLocalizedDescriptionKey:message}]; }
static NSDictionary *Query(NSError **error) {
 NSString *group=[NSBundle.mainBundle objectForInfoDictionaryKey:@"NetworkEXKeychainGroup"];
 if (![group isKindOfClass:NSString.class] || group.length==0 || [group containsString:@"$("]) {
  if(error)*error=Err(@"Keychain access group is not configured");return nil;
 }
 return @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
 (__bridge id)kSecAttrService:@"com.xzcode.networkex.profile",
 (__bridge id)kSecAttrAccount:@"device-v1",(__bridge id)kSecAttrAccessGroup:group,
 (__bridge id)kSecAttrSynchronizable:@NO};
}
NSData *NEXLoadCredential(NSError **error) {
 NSDictionary *q=Query(error);if(!q)return nil;
 NSMutableDictionary *request=[q mutableCopy];request[(__bridge id)kSecReturnData]=@YES;
 request[(__bridge id)kSecMatchLimit]=(__bridge id)kSecMatchLimitOne;
 CFTypeRef value=NULL;OSStatus s=SecItemCopyMatching((__bridge CFDictionaryRef)request,&value);
 if(s!=errSecSuccess){if(error)*error=[NSError errorWithDomain:NSOSStatusErrorDomain code:s userInfo:nil];return nil;}
 NSData *data=CFBridgingRelease(value);
 if(![data isKindOfClass:NSData.class] || data.length==0 || data.length>65536){if(error)*error=Err(@"Invalid credential bundle");return nil;}
 return data;
}
NSString *NEXProfileState(void) {
 NSError *error=nil;NSData *data=NEXLoadCredential(&error);
 if(data)return @"ready";
 return ([error.domain isEqualToString:NSOSStatusErrorDomain]&&error.code==errSecItemNotFound)?@"missing":@"unavailable";
}
NSURL *NEXPrivateRoot(NSString *leaf,NSError **error) {
 // Both app and extension have their own private container. Never use a
 // caller-supplied external path or a shared plaintext App Group directory.
 if(![@[@"enrollment",@"runtime"] containsObject:leaf]){if(error)*error=Err(@"Invalid private root");return nil;}
 NSFileManager *fm=NSFileManager.defaultManager;
 NSURL *base=[fm URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
 if(!base){if(error)*error=Err(@"Application support unavailable");return nil;}
 NSURL *parent=[base URLByAppendingPathComponent:@"NetworkEX" isDirectory:YES];
 NSDictionary *attrs=@{NSFilePosixPermissions:@0700,NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication};
 if(![fm createDirectoryAtURL:parent withIntermediateDirectories:YES attributes:attrs error:error])return nil;
 if(![fm setAttributes:attrs ofItemAtPath:parent.path error:error] ||
    ![parent setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:error])return nil;
 NSURL *root=[parent URLByAppendingPathComponent:leaf isDirectory:YES];
 // Caller serializes lifecycle; delete only the fixed staging/runtime folder.
 if([fm fileExistsAtPath:root.path] && ![fm removeItemAtURL:root error:error])return nil;
 if(![fm createDirectoryAtURL:root withIntermediateDirectories:NO attributes:attrs error:error])return nil;
 if(![root setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:error])return nil;
 return root;
}
BOOL NEXProtectTree(NSURL *root,NSError **error) {
 NSFileManager *fm=NSFileManager.defaultManager;
 __block NSError *walkError=nil;
 NSDirectoryEnumerator *en=[fm enumeratorAtURL:root includingPropertiesForKeys:@[NSURLIsDirectoryKey,NSURLIsSymbolicLinkKey] options:0 errorHandler:^BOOL(NSURL *url,NSError *e){walkError=e;return NO;}];
 for(NSURL *url in en){
  NSNumber *link=nil,*dir=nil;
  if(![url getResourceValue:&link forKey:NSURLIsSymbolicLinkKey error:error]||link.boolValue){if(error && !*error)*error=Err(@"Unexpected symbolic link");return NO;}
  if(![url getResourceValue:&dir forKey:NSURLIsDirectoryKey error:error])return NO;
  if(![fm setAttributes:@{NSFilePosixPermissions:dir.boolValue?@0700:@0600,NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication} ofItemAtPath:url.path error:error])return NO;
 }
 if(walkError){if(error)*error=walkError;return NO;}return YES;
}
NSString *NEXEnroll(NSString *server,NSString *name,NSString *invite,NSString *ca) {
 @synchronized(NSBundle.mainBundle) {
  if(![NEXProfileState() isEqualToString:@"missing"])return @"A profile already exists or Keychain is unavailable";
  NSError *error=nil;NSURL *root=NEXPrivateRoot(@"enrollment",&error);if(!root)return error.localizedDescription;
  NSString *result=nil;
  @try {
   (void)MobileEnroll(root.path,server,name,invite,ca,&error);
   if(!error && !NEXProtectTree(root,&error)){}
   NSData *data=error?nil:MobileExportProfile(root.path,&error);
   if(data && !error){
    NSMutableDictionary *q=[Query(&error) mutableCopy];
    if(q){
     q[(__bridge id)kSecValueData]=data;
     q[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
     OSStatus s=SecItemAdd((__bridge CFDictionaryRef)q,NULL);
     if(s!=errSecSuccess)error=[NSError errorWithDomain:NSOSStatusErrorDomain code:s userInfo:nil];
    }
   }
   if(error||!data)result=error.localizedDescription?:@"Enrollment credential unavailable";
  } @finally {
   NSError *cleanup=nil;
   if(![NSFileManager.defaultManager removeItemAtURL:root error:&cleanup] && !result) result=@"Identity saved; protected enrollment staging cleanup failed";
  }
  return result;
 }
}
NSString *NEXForget(void) {
 @synchronized(NSBundle.mainBundle) {
  NSError *error=nil;NSDictionary *q=Query(&error);if(!q)return error.localizedDescription;
  OSStatus s=SecItemDelete((__bridge CFDictionaryRef)q);
  return (s==errSecSuccess||s==errSecItemNotFound)?nil:[NSError errorWithDomain:NSOSStatusErrorDomain code:s userInfo:nil].localizedDescription;
 }
}
