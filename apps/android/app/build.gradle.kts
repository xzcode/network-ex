plugins { id("com.android.application") }
android {
 namespace = "com.xzcode.networkex"
 compileSdk = 35
 defaultConfig {
  applicationId = "com.xzcode.networkex"
  minSdk = 26
  targetSdk = 35
  versionCode = 800
  versionName = "0.8.0-dev-m8"
 }
 compileOptions {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
 }
 buildTypes { release { isMinifyEnabled = false } }
}
dependencies { implementation(files("libs/network-ex-mobile.aar")) }
tasks.matching { it.name == "preBuild" }.configureEach {
 doFirst { require(file("libs/network-ex-mobile.aar").isFile) { "Build the Go mobile AAR first (scripts/build-android.sh)." } }
}
