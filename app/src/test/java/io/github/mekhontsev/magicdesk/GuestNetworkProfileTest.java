package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class GuestNetworkProfileTest {
    @Test public void nativeDefaultDoesNotChangeArguments() {
        assertEquals(List.of(), GuestNetworkProfile.HOST.arguments());
        var plan = new GuestLaunchPlan(new GuestEnvironment("/store", "/tmp", ""), "/", List.of("/bin/sh"));
        assertEquals(GuestNetworkProfile.HOST, plan.network());
        assertFalse(plan.arguments().contains("--network"));
    }

    @Test public void everyLaunchAdapterGetsTheSameNetworkArguments() {
        var profile = new GuestNetworkProfile(GuestNetworkProfile.Mode.BRIDGE,
                List.of("127.0.0.1:8080:80/tcp", "5353:53/udp"), List.of("192.0.2.53"));
        var expected = List.of("--network", "bridge", "-p", "127.0.0.1:8080:80/tcp", "-p", "5353:53/udp", "--dns", "192.0.2.53");
        assertEquals(expected, profile.arguments());
        for (boolean image : List.of(false, true)) {
            var plan = new GuestLaunchPlan(new GuestEnvironment("/store", "/tmp", "", image),
                    "/", List.of("/bin/sh"), false, profile);
            var args = plan.arguments();
            assertEquals(expected, args.subList(args.indexOf("--network"), args.indexOf("--")));
            assertTrue(GuestGraphicalConnection.invocation(plan, GraphicalProtocol.WAYLAND).contains("'--network' 'bridge'"));
        }
    }

    @Test public void policyIsImmutableAndIncompatibleOptionsFailEarly() {
        var ports = new ArrayList<>(List.of("8080:80"));
        var profile = new GuestNetworkProfile(GuestNetworkProfile.Mode.BRIDGE, ports, List.of());
        ports.clear();
        assertEquals(List.of("8080:80"), profile.publications());
        for (var mode : List.of(GuestNetworkProfile.Mode.HOST, GuestNetworkProfile.Mode.NONE, GuestNetworkProfile.Mode.ROUTED))
            assertThrows(IllegalArgumentException.class, () -> new GuestNetworkProfile(mode, List.of("8080:80"), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new GuestNetworkProfile(GuestNetworkProfile.Mode.NONE, List.of(), List.of("192.0.2.1")));
        assertThrows(IllegalArgumentException.class, () -> new GuestNetworkProfile(GuestNetworkProfile.Mode.BRIDGE, List.of("x\0"), List.of()));
    }
}
