package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Per-launch arguments only. Native Shroot owns parsing, preparation and lifetime. */
public record GuestNetworkProfile(Mode mode, List<String> publications, List<String> dns) {
    public enum Mode { HOST, NONE, BRIDGE, ROUTED }
    public static final GuestNetworkProfile HOST = new GuestNetworkProfile(Mode.HOST, List.of(), List.of());

    public GuestNetworkProfile {
        Objects.requireNonNull(mode, "network mode");
        publications = List.copyOf(publications);
        dns = List.copyOf(dns);
        if (publications.size() > 128 || dns.size() > 3
                || !publications.isEmpty() && mode != Mode.BRIDGE || !dns.isEmpty() && mode == Mode.NONE)
            throw new IllegalArgumentException("Incompatible network options");
        for (var values : List.of(publications, dns)) for (String value : values)
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
        return List.copyOf(result);
    }
}
