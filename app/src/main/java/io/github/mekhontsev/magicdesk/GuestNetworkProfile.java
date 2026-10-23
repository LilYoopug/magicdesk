package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Per-launch arguments only. Native Shroot owns parsing, preparation and lifetime. */
public record GuestNetworkProfile(Mode mode, List<String> publications, List<String> dns, Addressing addressing) {
    public enum Mode { HOST, NONE, BRIDGE, ROUTED }
    public record Addressing(List<String> subnets, String ip, String ip6, List<String> gateways) {
        public static final Addressing DEFAULT = new Addressing(List.of(), "", "", List.of());
        public Addressing {
            subnets = List.copyOf(subnets);
            gateways = List.copyOf(gateways);
            Objects.requireNonNull(ip);
            Objects.requireNonNull(ip6);
            if (subnets.size() > 2 || gateways.size() > 2) throw new IllegalArgumentException("Too many address families");
            for (var values : List.of(subnets, gateways)) for (var value : values) validateArgument(value);
            if (!ip.isEmpty()) validateArgument(ip);
            if (!ip6.isEmpty()) validateArgument(ip6);
        }
        private void appendTo(List<String> out) {
            for (var subnet : subnets) out.addAll(List.of("--subnet", subnet));
            if (!ip.isEmpty()) out.addAll(List.of("--ip", ip));
            if (!ip6.isEmpty()) out.addAll(List.of("--ip6", ip6));
            for (var gateway : gateways) out.addAll(List.of("--gateway", gateway));
        }
    }
    public static final GuestNetworkProfile HOST = new GuestNetworkProfile(Mode.HOST, List.of(), List.of());

    public GuestNetworkProfile(Mode mode, List<String> publications, List<String> dns) {
        this(mode, publications, dns, Addressing.DEFAULT);
    }

    public GuestNetworkProfile {
        Objects.requireNonNull(mode, "network mode");
        Objects.requireNonNull(addressing, "network addressing");
        publications = List.copyOf(publications);
        dns = List.copyOf(dns);
        if (publications.size() > 128 || dns.size() > 3
                || (!publications.isEmpty() || !addressing.equals(Addressing.DEFAULT)) && mode != Mode.BRIDGE
                || !dns.isEmpty() && mode == Mode.NONE)
            throw new IllegalArgumentException("Incompatible network options");
        for (var values : List.of(publications, dns)) for (String value : values) validateArgument(value);
    }

    private static void validateArgument(String value) {
        if (value.isEmpty() || value.length() > 128 || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Invalid network argument");
    }

    public List<String> arguments() {
        if (equals(HOST)) return List.of();
        var result = new ArrayList<String>();
        result.add("--network");
        result.add(mode.name().toLowerCase(java.util.Locale.ROOT));
        for (String port : publications) result.addAll(List.of("-p", port));
        for (String server : dns) result.addAll(List.of("--dns", server));
        addressing.appendTo(result);
        return List.copyOf(result);
    }
}
