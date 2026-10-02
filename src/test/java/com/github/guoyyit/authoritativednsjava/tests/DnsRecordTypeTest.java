package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Type-code parsing: every digit of the RFC 3597 {@code TYPEnnn} form is
 * significant, the full 16-bit range is supported, and malformed or
 * out-of-range input is rejected instead of being truncated or remapped.
 */
class DnsRecordTypeTest {

    @Test
    void wellKnownNamesRoundTrip() {
        assertEquals(DnsRecordType.A, DnsRecordType.parse("A"));
        assertEquals(DnsRecordType.AAAA, DnsRecordType.parse("AAAA"));
        assertEquals(DnsRecordType.ANY, DnsRecordType.parse("ANY"));
        assertEquals("A", DnsRecordType.name(DnsRecordType.A));
        assertEquals("AAAA", DnsRecordType.name(DnsRecordType.AAAA));
    }

    @Test
    void singleDigitTypeCodeKeepsItsValue() {
        // Regression: "TYPE9" used to blow up (empty substring) on load.
        assertEquals(9, DnsRecordType.parse("TYPE9"));
        assertEquals("TYPE9", DnsRecordType.name(9));
        assertEquals(9, DnsRecordType.parse(DnsRecordType.name(9)));
    }

    @Test
    void multiDigitTypeCodeIsNotTruncated() {
        // Regression: "TYPE99" used to come back as 9 (first digit dropped).
        assertEquals(99, DnsRecordType.parse("TYPE99"));
        assertEquals("TYPE99", DnsRecordType.name(99));
        assertEquals(99, DnsRecordType.parse(DnsRecordType.name(99)));
        assertEquals(1234, DnsRecordType.parse("TYPE1234"));
        assertEquals(65280, DnsRecordType.parse("TYPE65280"));
    }

    @Test
    void boundaryTypeCodesAreSupported() {
        assertEquals(0, DnsRecordType.parse("TYPE0"));
        assertEquals(65535, DnsRecordType.parse("TYPE65535"));
        assertEquals("TYPE65535", DnsRecordType.name(65535));
        assertEquals(65535, DnsRecordType.parse(DnsRecordType.name(65535)));
    }

    @Test
    void typeKeywordIsCaseInsensitive() {
        assertEquals(99, DnsRecordType.parse("type99"));
        assertEquals(99, DnsRecordType.parse("Type99"));
    }

    @Test
    void malformedTypeFormsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse(null));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse(""));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPEabc"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE9x"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE-1"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE 9"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("bogus"));
    }

    @Test
    void outOfRangeTypeCodesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE65536"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE70000"));
        assertThrows(IllegalArgumentException.class,
                () -> DnsRecordType.parse("TYPE99999999999999999999"));
    }

    @Test
    void rejectionMessagesAreDistinguishable() {
        IllegalArgumentException malformed = assertThrows(IllegalArgumentException.class,
                () -> DnsRecordType.parse("TYPEabc"));
        IllegalArgumentException outOfRange = assertThrows(IllegalArgumentException.class,
                () -> DnsRecordType.parse("TYPE65536"));
        org.junit.jupiter.api.Assertions.assertTrue(
                malformed.getMessage().contains("invalid type code"));
        org.junit.jupiter.api.Assertions.assertTrue(
                outOfRange.getMessage().contains("out of range"));
    }
}
