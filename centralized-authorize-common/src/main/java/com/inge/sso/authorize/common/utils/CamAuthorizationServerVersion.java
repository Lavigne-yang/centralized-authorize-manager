package com.inge.sso.authorize.common.utils;

/**
 * @author lavyoung1325
 * @since  1.0.0
 */
public final class CamAuthorizationServerVersion {

    private static final int MAJOR = 1;
    private static final int MINOR = 0;
    private static final int PATCH = 0;

    /**
     * 全局统一授权服务序列化UID
     * Global Serialization value for Cam Authorization Server classes.
     */
    public static final long SERIAL_VERSION_UID = getVersion().hashCode();

    public static String getVersion() {
        return MAJOR + "." + MINOR + "." + PATCH;
    }
}
