package com.xzcode.networkex;

import android.content.Context;
import android.system.Os;
import java.io.File;

final class ProfileStore {
    private ProfileStore() {}
    static String root(Context c) throws Exception {
        File dir = new File(c.getNoBackupFilesDir(), "network-ex");
        if (!dir.isDirectory() && !dir.mkdir()) throw new IllegalStateException("Cannot create private state");
        Os.chmod(dir.getAbsolutePath(), 0700);
        return dir.getCanonicalPath();
    }
}
