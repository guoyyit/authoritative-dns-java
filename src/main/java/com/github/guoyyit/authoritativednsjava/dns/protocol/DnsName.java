package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Immutable domain name as a list of labels (root = empty list).
 * Comparison is case-insensitive per RFC 1035 section 3.1.
 */
public final class DnsName implements Comparable<DnsName> {

    private static final DnsName ROOT = new DnsName(List.of());

    private final List<String> labels;
    private final String dotted;

    private DnsName(List<String> labels) {
        this.labels = labels;
        this.dotted = labels.isEmpty() ? "." : String.join(".", labels) + ".";
    }

    /** Parses a dotted name such as "www.example.com." (trailing dot optional). */
    public static DnsName of(String dotted) {
        if (dotted == null || dotted.isBlank() || dotted.equals(".")) {
            return ROOT;
        }
        String s = dotted.endsWith(".") ? dotted.substring(0, dotted.length() - 1) : dotted;
        List<String> parts = new ArrayList<>();
        for (String label : s.split("\\.")) {
            if (label.isEmpty()) {
                throw new IllegalArgumentException("empty label in name: " + dotted);
            }
            if (label.length() > 63) {
                throw new IllegalArgumentException("label too long in name: " + dotted);
            }
            parts.add(label.toLowerCase(Locale.ROOT));
        }
        return new DnsName(Collections.unmodifiableList(parts));
    }

    public static DnsName ofLabels(List<String> labels) {
        if (labels == null || labels.isEmpty()) {
            return ROOT;
        }
        List<String> parts = new ArrayList<>(labels.size());
        for (String label : labels) {
            parts.add(label.toLowerCase(Locale.ROOT));
        }
        return new DnsName(Collections.unmodifiableList(parts));
    }

    public static DnsName root() {
        return ROOT;
    }

    public List<String> labels() {
        return labels;
    }

    /** True if this name equals or is below {@code ancestor}. */
    public boolean isSubdomainOf(DnsName ancestor) {
        if (ancestor.labels.size() > labels.size()) {
            return false;
        }
        int offset = labels.size() - ancestor.labels.size();
        for (int i = 0; i < ancestor.labels.size(); i++) {
            if (!labels.get(offset + i).equals(ancestor.labels.get(i))) {
                return false;
            }
        }
        return true;
    }

    /** The parent name, or null for the root. */
    public DnsName parent() {
        if (labels.isEmpty()) {
            return null;
        }
        return new DnsName(Collections.unmodifiableList(labels.subList(1, labels.size())));
    }

    @Override
    public String toString() {
        return dotted;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof DnsName other && labels.equals(other.labels);
    }

    @Override
    public int hashCode() {
        return labels.hashCode();
    }

    /**
     * Canonical DNS ordering: compare from the root-most label right-to-left,
     * and a name with fewer labels sorts before the longer subdomain.
     */
    @Override
    public int compareTo(DnsName other) {
        int i = labels.size() - 1;
        int j = other.labels.size() - 1;
        while (i >= 0 && j >= 0) {
            int c = labels.get(i).compareTo(other.labels.get(j));
            if (c != 0) {
                return c;
            }
            i--;
            j--;
        }
        return Integer.compare(labels.size(), other.labels.size());
    }
}
