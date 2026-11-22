package com.cantalay.authgateway.account;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpTest {

    @Test
    void ipv6AddressesShareTheirSlash64() {
        assertThat(ClientIp.rateKey("2001:db8:1:2::1")).isEqualTo(ClientIp.rateKey("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assertThat(ClientIp.rateKey("2001:db8:1:2::1")).isEqualTo("2001:db8:1:2::/64");
        assertThat(ClientIp.rateKey("[2001:db8:1:3::1]")).isEqualTo("2001:db8:1:3::/64");
        assertThat(ClientIp.rateKey("fe80::1%eth0")).isEqualTo("fe80:0:0:0::/64");
        assertThat(ClientIp.rateKey("2001:db8:1:2::1")).isNotEqualTo(ClientIp.rateKey("2001:db8:1:3::1"));
    }

    @Test
    void ipv4AndJunkStayAsTheyAre() {
        assertThat(ClientIp.rateKey("203.0.113.9")).isEqualTo("203.0.113.9");
        assertThat(ClientIp.rateKey("::ffff:203.0.113.9")).isEqualTo("203.0.113.9");
        assertThat(ClientIp.rateKey("not-an-ip.example.com")).isEqualTo("not-an-ip.example.com"); // never resolved
        assertThat(ClientIp.rateKey("zz::zz")).isEqualTo("zz::zz");
        assertThat(ClientIp.rateKey(null)).isEqualTo("unknown");
    }
}
