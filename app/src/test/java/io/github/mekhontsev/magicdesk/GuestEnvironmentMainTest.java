package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import org.junit.Test;

public class GuestEnvironmentMainTest {
    @Test public void dnsCheckNeedsNoLibraryOrAndroidNetworkForExplicitChoices() throws Exception {
        for (String policy : new String[]{"preserve", "192.0.2.1", "192.0.2.1,2001:db8::1"})
            assertTrue(GuestEnvironmentMain.checkDns(new String[]{"dns", "--check", policy}));
    }

    @Test public void dnsCheckRejectsInvalidAddressesAndArguments() {
        for (String policy : new String[]{"", "example.org", "999.0.0.1", "192.0.2.1,", "1.2.3.4,1.2.3.5,1.2.3.6,1.2.3.7"})
            assertThrows(IllegalArgumentException.class,
                    () -> GuestEnvironmentMain.checkDns(new String[]{"dns", "--check", policy}));
        assertThrows(IllegalArgumentException.class,
                () -> GuestEnvironmentMain.checkDns(new String[]{"dns", "--check"}));
        assertThrows(IllegalArgumentException.class,
                () -> GuestEnvironmentMain.checkDns(new String[]{"dns", "--check", "preserve", "--replace"}));
    }

    @Test public void otherCommandsContinueToTheEnvironmentLibrary() throws Exception {
        assertFalse(GuestEnvironmentMain.checkDns(new String[]{"dns", "work", "preserve"}));
        assertFalse(GuestEnvironmentMain.checkDns(new String[]{"list"}));
    }
}
