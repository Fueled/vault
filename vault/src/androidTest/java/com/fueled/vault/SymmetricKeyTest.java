package com.fueled.vault;

import android.os.Build;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.SecretKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
public class SymmetricKeyTest extends BaseContextTest implements BaseKeyTest {

    @Test
    @Override
    public void shouldBeAbleToGenerateDefaultKeyIsNotNull() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        assertThat(secretKey, is(notNullValue()));
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
    }

    @Test
    @Override
    public void shouldBeAbleToGenerateKeyIsNotNull() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(new KeyProperties.Builder()
                .setAlias(Companion.getKEY_ALIAS_SYMMETRIC())
                .setPassword(Companion.getKEY_PASSWORD())
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("CBC")
                .setEncryptionPaddings("PKCS7Padding")
                .build());
        assertThat(secretKey, is(notNullValue()));
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
    }

    @Test
    @Override
    public void shouldBeAbleToGenerateKeyHasWrongType() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(new KeyProperties.Builder()
                .setAlias(Companion.getKEY_ALIAS_SYMMETRIC())
                .setPassword(Companion.getKEY_PASSWORD())
                .setKeySize(256)
                .setKeyType("no-such-key-type")
                .setBlockModes("CBC")
                .setEncryptionPaddings("PKCS7Padding")
                .build());

        assertThat(secretKey, is(nullValue()));
    }

    @Test
    @Override
    public void shouldBeAbleToGenerateKeyHasNoBlockModes() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(new KeyProperties.Builder()
                .setAlias(Companion.getKEY_ALIAS_SYMMETRIC())
                .setPassword(Companion.getKEY_PASSWORD())
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("no-such-block-modes")
                .setEncryptionPaddings("PKCS7Padding")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(secretKey, is(notNullValue()));
            vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
        } else {
            assertThat(secretKey, is(nullValue()));
        }
    }

    @Test
    @Override
    public void shouldBeAbleToGenerateKeyHasNoEncryptionPaddings() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(new KeyProperties.Builder()
                .setAlias(Companion.getKEY_ALIAS_SYMMETRIC())
                .setPassword(Companion.getKEY_PASSWORD())
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("CBC")
                .setEncryptionPaddings("no-such-encryption-paddings")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(secretKey, is(notNullValue()));
            vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
        } else {
            assertThat(secretKey, is(nullValue()));
        }
    }

    @Test
    @Override
    public void shouldBeAbleToGetKeyIsNotNull() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        SecretKey symmetricKey = vault.getSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        assertThat(symmetricKey, is(notNullValue()));

        vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        symmetricKey = vault.getSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        assertThat(symmetricKey, is(notNullValue()));

        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
    }

    @Test
    @Override
    public void shouldBeAbleToCheckHasKeyIsTrue() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        assertThat(vault.hasKey(Companion.getKEY_ALIAS_SYMMETRIC()), is(true));
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
    }

    @Test
    @Override
    public void shouldBeAbleToCheckHasKeyIsFalse() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        assertThat(vault.hasKey(Companion.getKEY_ALIAS_SYMMETRIC()), is(false));
    }

    @Test
    @Override
    public void shouldBeAbleToDeleteKey() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
        assertThat(vault.hasKey(Companion.getKEY_ALIAS_SYMMETRIC()), is(false));

        // make sure that new instance of vault also doesn't contains the key
        vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        assertThat(vault.hasKey(Companion.getKEY_ALIAS_SYMMETRIC()), is(false));
    }

    @Test
    @Override
    public void shouldBeAbleToEncryptSmallData() {
        encryptDataIsValid(Companion.getSMALL_DATA());
    }

    @Test
    @Override
    public void shouldBeAbleToEncryptLargeData() {
        encryptDataIsValid(Companion.getLARGE_DATA());
    }

    @Test
    @Override
    public void shouldBeAbleToCheckInValidEncryptData() {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        SecretKey secretKey2 = vault.generateSymmetricKey("secret-key-2", Companion.getKEY_PASSWORD());
        Crypto crypto = new Crypto(Options.INSTANCE.getTRANSFORMATION_SYMMETRIC());
        String encrypt = crypto.encrypt(Companion.getLARGE_DATA(), secretKey);
        String decrypt = crypto.decrypt(encrypt, secretKey2);
        assertThat(Companion.getLARGE_DATA(), is(not(decrypt)));
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
        vault.deleteKey("secret-key-2");
    }

    private void encryptDataIsValid(String data) {
        Vault vault = new Vault(getContext(), Companion.getSTORE_NAME(), Companion.getSTORE_PASSWORD());
        SecretKey secretKey = vault.generateSymmetricKey(Companion.getKEY_ALIAS_SYMMETRIC(), Companion.getKEY_PASSWORD());
        Crypto crypto = new Crypto(Options.INSTANCE.getTRANSFORMATION_SYMMETRIC());
        String encrypt = crypto.encrypt(data, secretKey);
        String decrypt = crypto.decrypt(encrypt, secretKey);
        assertThat(data, is(decrypt));
        vault.deleteKey(Companion.getKEY_ALIAS_SYMMETRIC());
    }
}
