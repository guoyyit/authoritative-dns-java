package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Type-code parsing: exact TYPEnnn handling, boundaries, and rejection of bad input. */
class DnsRecordTypeTest {

    @Test
    void knownNamesParseToTheirCodes() {
        assertEquals(DnsRecordType.A, DnsRecordType.parse("A"));
        assertEquals(DnsRecordType.AAAA, DnsRecordType.parse("AAAA"));
        assertEquals(DnsRecordType.TXT, DnsRecordType.parse("TXT"));
        assertEquals(DnsRecordType.AXFR, DnsRecordType.parse("AXFR"));
        assertEquals(DnsRecordType.ANY, DnsRecordType.parse("ANY"));
    }

    @Test
    void singleDigitTypeCodeIsParsedExactly() {
        assertEquals(9, DnsRecordType.parse("TYPE9"));
        assertEquals(0, DnsRecordType.parse("TYPE0"));
    }

    @Test
    void multiDigitTypeCodeIsParsedExactly() {
        assertEquals(99, DnsRecordType.parse("TYPE99"));
        assertEquals(123, DnsRecordType.parse("TYPE123"));
        assertEquals(65535, DnsRecordType.parse("TYPE65535"));
    }

    @Test
    void typeKeywordIsCaseInsensitive() {
        assertEquals(99, DnsRecordType.parse("type99"));
        assertEquals(9, DnsRecordType.parse("Type9"));
    }

    @Test
    void nameIsTheExactInverseOfParse() {
        for (int code : new int[]{0, 9, 99, 123, 1024, 65535}) {
            assertEquals(code, DnsRecordType.parse(DnsRecordType.name(code)));
            assertEquals("TYPE" + code, DnsRecordType.name(code));
        }
        // Known types keep their mnemonic names.
        assertEquals("A", DnsRecordType.name(DnsRecordType.A));
        assertEquals("AAAA", DnsRecordType.name(DnsRecordType.AAAA));
    }

    @Test
    void outOfRangeTypeCodesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE65536"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE99999"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE-1"));
    }

    @Test
    void malformedTypeRepresentationsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE12x"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE 9"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("TYPE+9"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("99"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse("BOGUS"));
        assertThrows(IllegalArgumentException.class, () -> DnsRecordType.parse(""));
    }
}
