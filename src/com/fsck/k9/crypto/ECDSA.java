package com.fsck.k9.crypto;

import android.app.Activity;
import android.app.Fragment;
import android.content.ActivityNotFoundException;
import android.content.ContentUris;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.widget.Toast;

import com.fsck.k9.R;
import com.fsck.k9.activity.MessageCompose;
import com.fsck.k9.crypto.dalva.revariscipher.Revaris;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mail.internet.SHA1;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by user on 4/24/2016.
 */
public class ECDSA{
    public static final String NAME = "ecdsa";

    private static final String mApgPackageName = "org.thialfihar.android.apg";
    private static final int mMinRequiredVersion = 16;

    public static final String AUTHORITY = "org.thialfihar.android.apg.provider";
    public static final Uri CONTENT_URI_SECRET_KEY_RING_BY_KEY_ID =
            Uri.parse("content://" + AUTHORITY + "/key_rings/secret/key_id/");
    public static final Uri CONTENT_URI_SECRET_KEY_RING_BY_EMAILS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/secret/emails/");

    public static final Uri CONTENT_URI_PUBLIC_KEY_RING_BY_KEY_ID =
            Uri.parse("content://" + AUTHORITY + "/key_rings/public/key_id/");
    public static final Uri CONTENT_URI_PUBLIC_KEY_RING_BY_EMAILS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/public/emails/");

    public static class Intent {
        public static final String SELECT_PUBLIC_KEYS = "org.thialfihar.android.apg.intent.SELECT_PUBLIC_KEYS";
        public static final String SELECT_SECRET_KEY = "org.thialfihar.android.apg.intent.SELECT_SECRET_KEY";
    }

    public static final String EXTRA_TEXT = "text";
    public static final String EXTRA_DATA = "data";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_DECRYPTED_MESSAGE = "decryptedMessage";
    public static String EXTRA_ENCRYPTED_MESSAGE = "encryptedMessage";
    public static final String EXTRA_SIGNATURE = "signature";
    public static final String EXTRA_SIGNATURE_KEY_ID = "signatureKeyId";
    public static final String EXTRA_SIGNATURE_USER_ID = "signatureUserId";
    public static final String EXTRA_SIGNATURE_SUCCESS = "signatureSuccess";
    public static final String EXTRA_SIGNATURE_UNKNOWN = "signatureUnknown";
    public static final String EXTRA_USER_ID = "userId";
    public static final String EXTRA_KEY_ID = "keyId";
    public static final String EXTRA_ENCRYPTION_KEY_IDS = "encryptionKeyIds";
    public static final String EXTRA_SELECTION = "selection";
    public static final String EXTRA_MESSAGE = "message";
    public static final String EXTRA_INTENT_VERSION = "intentVersion";

    public static final String INTENT_VERSION = "1";

    // Note: The support package only allows us to use the lower 16 bits of a request code.
    public static final int DECRYPT_MESSAGE = 0x0000A001;
    public static final int ENCRYPT_MESSAGE = 0x0000A002;
    public static final int SELECT_PUBLIC_KEYS = 0x0000A003;
    public static final int SELECT_SECRET_KEY = 0x0000A004;
    public static Pattern ECDSA_MESSAGE =
            Pattern.compile(".*?(-----BEGIN MESSAGE-----.*?-----END MESSAGE-----).*",
                    Pattern.DOTALL);

    public static Pattern ECDSA_SIGNED_MESSAGE =
            Pattern.compile(".*?(-----BEGIN SIGNED MESSAGE-----.*?-----BEGIN DIGITAL SIGNATURE-----.*?-----END DIGITAL SIGNATURE-----).*",
                    Pattern.DOTALL);


    public boolean selectSecretKey(Activity activity, ECDSAData ecdsaData) {
        android.content.Intent intent = new android.content.Intent(Intent.SELECT_SECRET_KEY);
        intent.putExtra(EXTRA_INTENT_VERSION, INTENT_VERSION);
        try {
            activity.startActivityForResult(intent, ECDSA.SELECT_SECRET_KEY);
            return true;
        } catch (ActivityNotFoundException e) {
            Toast.makeText(activity,
                    R.string.error_activity_not_found,
                    Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    public boolean selectEncryptionKeys(Activity activity, String emails, ECDSAData ecdsaData) {
        android.content.Intent intent = new android.content.Intent(Apg.Intent.SELECT_PUBLIC_KEYS);
        intent.putExtra(EXTRA_INTENT_VERSION, INTENT_VERSION);
        long[] initialKeyIds = null;
        if (!ecdsaData.hasEncryptionKeys()) {
            List<Long> keyIds = new ArrayList<Long>();
            if (ecdsaData.hasSignatureKey()) {
                keyIds.add(ecdsaData.getSignatureKeyId());
            }

            try {
                Uri contentUri = Uri.withAppendedPath(
                        ECDSA.CONTENT_URI_PUBLIC_KEY_RING_BY_EMAILS,
                        emails);
                Cursor c = activity.getContentResolver().query(contentUri,
                        new String[] { "master_key_id" },
                        null, null, null);
                if (c != null) {
                    while (c.moveToNext()) {
                        keyIds.add(c.getLong(0));
                    }
                }

                if (c != null) {
                    c.close();
                }
            } catch (SecurityException e) {
                Toast.makeText(activity,
                        activity.getResources().getString(R.string.insufficient_apg_permissions),
                        Toast.LENGTH_LONG).show();
            }
            if (!keyIds.isEmpty()) {
                initialKeyIds = new long[keyIds.size()];
                for (int i = 0, size = keyIds.size(); i < size; ++i) {
                    initialKeyIds[i] = keyIds.get(i);
                }
            }
        } else {
            initialKeyIds = ecdsaData.getEncryptionKeys();
        }
        intent.putExtra(Apg.EXTRA_SELECTION, initialKeyIds);
        try {
            activity.startActivityForResult(intent, Apg.SELECT_PUBLIC_KEYS);
            return true;
        } catch (ActivityNotFoundException e) {
            Toast.makeText(activity,
                    R.string.error_activity_not_found,
                    Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    public long[] getSecretKeyIdsFromEmail(Context context, String email) {
        long ids[] = null;
        try {
            Uri contentUri = Uri.withAppendedPath(ECDSA.CONTENT_URI_SECRET_KEY_RING_BY_EMAILS,
                    email);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[] { "master_key_id" },
                    null, null, null);
            if (c != null && c.getCount() > 0) {
                ids = new long[c.getCount()];
                while (c.moveToNext()) {
                    ids[c.getPosition()] = c.getLong(0);
                }
            }

            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }

        return ids;
    }

    /**
     * Get public key ids based on a given email.
     *
     * @param context
     * @param email The email in question.
     * @return key ids
     */
    public long[] getPublicKeyIdsFromEmail(Context context, String email) {
        long ids[] = null;
        try {
            Uri contentUri = Uri.withAppendedPath(ECDSA.CONTENT_URI_PUBLIC_KEY_RING_BY_EMAILS, email);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[] { "master_key_id" }, null, null, null);
            if (c != null && c.getCount() > 0) {
                ids = new long[c.getCount()];
                while (c.moveToNext()) {
                    ids[c.getPosition()] = c.getLong(0);
                }
            }

            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }

        return ids;
    }

    /**
     * Find out if a given email has a secret key.
     *
     * @param context
     * @param email The email in question.
     * @return true if there is a secret key for this email.
     */
    public boolean hasSecretKeyForEmail(Context context, String email) {
        try {
            Uri contentUri = Uri.withAppendedPath(ECDSA.CONTENT_URI_SECRET_KEY_RING_BY_EMAILS, email);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[] { "master_key_id" }, null, null, null);
            if (c != null && c.getCount() > 0) {
                c.close();
                return true;
            }
            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }
        return false;
    }

    /**
     * Find out if a given email has a public key.
     *
     * @param context
     * @param email The email in question.
     * @return true if there is a public key for this email.
     */
    public boolean hasPublicKeyForEmail(Context context, String email) {
        try {
            Uri contentUri = Uri.withAppendedPath(ECDSA.CONTENT_URI_PUBLIC_KEY_RING_BY_EMAILS, email);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[] { "master_key_id" }, null, null, null);
            if (c != null && c.getCount() > 0) {
                c.close();
                return true;
            }
            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }
        return false;
    }

    /**
     * Get the user id based on the key id.
     *
     * @param context
     * @param keyId
     * @return user id
     */
    public String getUserId(Context context, long keyId) {
        String userId = null;
        try {
            Uri contentUri = ContentUris.withAppendedId(
                    ECDSA.CONTENT_URI_SECRET_KEY_RING_BY_KEY_ID,
                    keyId);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[] { "user_id" },
                    null, null, null);
            if (c != null && c.moveToFirst()) {
                userId = c.getString(0);
            }

            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }

        if (userId == null) {
            userId = context.getString(R.string.unknown_crypto_signature_user_id);
        }
        return userId;
    }

    /**
     * Start the encrypt activity.
     *
     * @param data
     * @param ecdsaData
     * @return success or failure
     */
    public boolean encrypt(String data, ECDSAData ecdsaData) {
        try {
            byte dataEncrypted[] = Revaris.RevarisEncrypt(data.getBytes(), String.valueOf(ecdsaData.getEncryptionKey()));
            ecdsaData.setEncryptedData(dataEncrypted.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * Start the decrypt activity.
     *
     * @param data
     * @param ecdsaData
     * @return success or failure
     */
    public boolean decrypt(String data, ECDSAData ecdsaData) {
        if (data == null) {
            return false;
        }
        try {
            byte dataEncrypted[] = Revaris.RevarisDecrypt(data.getBytes(), String.valueOf(ecdsaData.getEncryptionKeys()));
            ecdsaData.setSignatureUserId(ECDSA.EXTRA_SIGNATURE_USER_ID);
            ecdsaData.setSignatureKeyId(Long.parseLong(ECDSA.EXTRA_SIGNATURE_KEY_ID));
            ecdsaData.setSignatureSuccess(true);
            ecdsaData.setSignatureUnknown(true);

            ecdsaData.setDecryptedData(dataEncrypted.toString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Start the encrypt activity.
     *
     * @param data
     * @param ecdsaData
     * @return success or failure
     */
    public boolean sign(String data, ECDSAData ecdsaData) {
        try {
            String md = SHA1.hashString(data);
            String encrypted = null;//TODO encrypt with pgpData
            ecdsaData.setSignatureResult(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * Start the decrypt activity.
     *
     * @param data
     * @param ecdsaData
     * @return success or failure
     */
    public boolean verify(String data, ECDSAData ecdsaData) {
        if (data == null) {
            return false;
        }
        try {
            String decrypt = null;//TODO encrypt with public key ecdsa data
            String md = SHA1.hashString(data);
            return decrypt.equals(md);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Start the encrypt activity.
     *
     * @param data
     * @param key
     * @return success or failure
     */
    public String encrypt(String data, String key) {
        String e = null;
        try {
            byte dataEncrypted[] = Revaris.RevarisEncrypt(data.getBytes(), key);
            e = dataEncrypted.toString();
        } catch (Exception ec) {
            ec.printStackTrace();
        }
        return e;
    }

    /**
     * Start the decrypt activity.
     *
     * @param data
     * @param key
     * @return success or failure
     */
    public String decrypt(String data, String key) {
        String e = null;
        if(data != null)
            try {
                byte dataDecrypted[] = Revaris.RevarisDecrypt(data.getBytes(), key);
                e = dataDecrypted.toString();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        return e;
    }

    /**
     * Start the encrypt activity.
     *
     * @param data
     * @param secretKey
     * @return success or failure
     */
    public String sign(String data, String secretKey) {
        String e = null;
        try {
            String md = SHA1.hashString(data);
            String encrypted = null;//TODO encrypt with pgpData
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return e;
    }

    /**
     * Start the decrypt activity.
     *
     * @param message
     * @return success or failure
     */
    public boolean verify(Message message) {
        if(isSigned(message))
            try {
                String decrypt = null;//TODO encrypt with public key ecdsa data
                String md = SHA1.hashString(message.getBody().toString());
                return decrypt.equals(md);
            } catch (Exception e) {
                return false;
            }
        else return false;
    }

    public boolean isEncrypted(Message message) {
        String data = null;
        try {
            Part part = MimeUtility.findFirstPartByMimeType(message, "text/plain");
            if (part == null) {
                part = MimeUtility.findFirstPartByMimeType(message, "text/html");
            }
            if (part != null) {
                data = MimeUtility.getTextFromPart(part);
            }
        } catch (MessagingException e) {
            // guess not...
            // TODO: maybe log this?
        }

        if (data == null) {
            return false;
        }

        Matcher matcher = ECDSA_MESSAGE.matcher(data);
        return !matcher.matches();
    }

    public boolean isSigned(Message message) {
        String data = null;
        try {
            Part part = MimeUtility.findFirstPartByMimeType(message, "text/plain");
            if (part == null) {
                part = MimeUtility.findFirstPartByMimeType(message, "text/html");
            }
            if (part != null) {
                data = MimeUtility.getTextFromPart(part);
            }
        } catch (MessagingException e) {
            // guess not...
            // TODO: maybe log this?
        }

        if (data == null) {
            return false;
        }

        Matcher matcher = ECDSA_SIGNED_MESSAGE.matcher(data);
        return matcher.matches();
    }

    /**
     * Get the name of the provider.
     *
     * @return provider name
     */
    public String getName() {
        return NAME;
    }

    /**
     * Test the APG installation.
     *
     * @return success or failure
     */
    public boolean test(Context context){

        try {
            // try out one content provider to check permissions
            Uri contentUri = ContentUris.withAppendedId(
                    ECDSA.CONTENT_URI_SECRET_KEY_RING_BY_KEY_ID,
                    12345);
            Cursor c = context.getContentResolver().query(contentUri,
                    new String[]{"user_id"},
                    null, null, null);
            if (c != null) {
                c.close();
            }
        } catch (SecurityException e) {
            // if there was a problem, then let the user know, this will not stop K9/APG from
            // working, but some features won't be available, so we can still return "true"
            Toast.makeText(context,
                    context.getResources().getString(R.string.insufficient_apg_permissions),
                    Toast.LENGTH_LONG).show();
        }

        return true;
    }
}
