package com.example.mwachasu.smartspot;

/**
 * Created by mwachasu on 3/25/2018.
 */

public abstract class MyOnStartTetheringCallback {
    /**
     * Called when tethering has been successfully started.
     */
    public abstract void onTetheringStarted();

    /**
     * Called when starting tethering failed.
     */
    public abstract void onTetheringFailed();

}