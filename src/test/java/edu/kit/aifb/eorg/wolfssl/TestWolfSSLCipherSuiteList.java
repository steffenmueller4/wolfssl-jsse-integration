package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

public class TestWolfSSLCipherSuiteList {

	@Test
	public void testWolfSSLCipherSuiteList1() {
		String[] s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("HC128-MD5");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_HC_128_MD5" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("HC128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_HC_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("HC128-B2B256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_HC_128_B2B256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES128-B2B256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_128_CBC_B2B256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES256-B2B256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_256_CBC_B2B256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("RABBIT-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_RABBIT_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("NTRU-RC4-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_NTRU_RSA_WITH_RC4_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("NTRU-DES-CBC3-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("NTRU-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_NTRU_RSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("NTRU-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_NTRU_RSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES128-CCM-8");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_128_CCM_8" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES256-CCM-8");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_256_CCM_8" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES128-CCM-8");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES256-CCM-8");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-RC4-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_RC4_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-DES-CBC3-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-RC4-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-DES-CBC3-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES256-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_256_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES256-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-RC4-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_RC4_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-DES-CBC3-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-RC4-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-DES-CBC3-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES128-GCM-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES256-GCM-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("CAMELLIA128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CAMELLIA128-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("CAMELLIA256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CAMELLIA256-SHA");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("CAMELLIA128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CAMELLIA128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("CAMELLIA256-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CAMELLIA256-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES128-SHA256");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-AES256-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-AES256-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-RSA-AES256-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDH-ECDSA-AES256-SHA384");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-RSA-CHACHA20-POLY1305");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("ECDHE-ECDSA-CHACHA20-POLY1305");
		assertTrue(Arrays.equals(s, new String[] { "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" }));

		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CHACHA20-POLY1305");
		assertTrue(Arrays.equals(s, new String[] { "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" }));
	}
	
	@Test
	public void testWolfSSLCipherSuiteList2() {
		String s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA"});
		assertTrue("AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA" });
		assertTrue("AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_128_CBC_SHA" });
		assertTrue("DHE-RSA-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_256_CBC_SHA" });
		assertTrue("DHE-RSA-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_HC_128_MD5" });
		assertTrue("HC128-MD5".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_HC_128_SHA" });
		assertTrue("HC128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_HC_128_B2B256" });
		assertTrue("HC128-B2B256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_128_CBC_B2B256" });
		assertTrue("AES128-B2B256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_256_CBC_B2B256" });
		assertTrue("AES256-B2B256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_RABBIT_SHA" });
		assertTrue("RABBIT-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_NTRU_RSA_WITH_RC4_128_SHA" });
		assertTrue("NTRU-RC4-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA" });
		assertTrue("NTRU-DES-CBC3-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_NTRU_RSA_WITH_AES_128_CBC_SHA" });
		assertTrue("NTRU-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_NTRU_RSA_WITH_AES_256_CBC_SHA" });
		assertTrue("NTRU-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_128_CCM_8" });
		assertTrue("AES128-CCM-8".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_256_CCM_8" });
		assertTrue("AES256-CCM-8".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" });
		assertTrue("ECDHE-ECDSA-AES128-CCM-8".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" });
		assertTrue("ECDHE-ECDSA-AES256-CCM-8".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" });
		assertTrue("ECDHE-RSA-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" });
		assertTrue("ECDHE-RSA-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" });
		assertTrue("ECDHE-ECDSA-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" });
		assertTrue("ECDHE-ECDSA-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{  "TLS_ECDHE_RSA_WITH_RC4_128_SHA" });
		assertTrue("ECDHE-RSA-RC4-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" });
		assertTrue("ECDHE-RSA-DES-CBC3-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" });
		assertTrue("ECDHE-ECDSA-RC4-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{  "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" });
		assertTrue("ECDHE-ECDSA-DES-CBC3-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA256" });
		assertTrue("AES256-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("DHE-RSA-AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" });
		assertTrue("DHE-RSA-AES256-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" });
		assertTrue("ECDH-RSA-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" });
		assertTrue("ECDH-RSA-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" });
		assertTrue("ECDH-ECDSA-AES128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" });
		assertTrue("ECDH-ECDSA-AES256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_RSA_WITH_RC4_128_SHA" });
		assertTrue("ECDH-RSA-RC4-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" });
		assertTrue("ECDH-RSA-DES-CBC3-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_ECDSA_WITH_RC4_128_SHA" });
		assertTrue("ECDH-ECDSA-RC4-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" });
		assertTrue("ECDH-ECDSA-DES-CBC3-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("DHE-RSA-AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("DHE-RSA-AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("ECDHE-RSA-AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("ECDHE-RSA-AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("ECDHE-ECDSA-AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("ECDHE-ECDSA-AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("ECDH-RSA-AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("ECDH-RSA-AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" });
		assertTrue("ECDH-ECDSA-AES128-GCM-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" });
		assertTrue("ECDH-ECDSA-AES256-GCM-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" });
		assertTrue("CAMELLIA128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" });
		assertTrue("DHE-RSA-CAMELLIA128-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" });
		assertTrue("CAMELLIA256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" });
		assertTrue("DHE-RSA-CAMELLIA256-SHA".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" });
		assertTrue("CAMELLIA128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" });
		assertTrue("DHE-RSA-CAMELLIA128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" });
		assertTrue("CAMELLIA256-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" });
		assertTrue("DHE-RSA-CAMELLIA256-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{ "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("ECDHE-RSA-AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("ECDHE-ECDSA-AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("ECDH-RSA-AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" });
		assertTrue("ECDH-ECDSA-AES128-SHA256".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" });
		assertTrue("ECDHE-RSA-AES256-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" });
		assertTrue("ECDHE-ECDSA-AES256-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" });
		assertTrue("ECDH-RSA-AES256-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" });
		assertTrue("ECDH-ECDSA-AES256-SHA384".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" });
		assertTrue("ECDHE-RSA-CHACHA20-POLY1305".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" });
		assertTrue("ECDHE-ECDSA-CHACHA20-POLY1305".equals(s));

		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" });
		assertTrue("DHE-RSA-CHACHA20-POLY1305".equals(s));
	}

	@Test
	public void testConcatenation1(){
		String s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"});
		assertTrue("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305".equals(s));
		
		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"});
		assertTrue("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305".equals(s));
		
		s = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"});
		assertTrue("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDH-ECDSA-AES256-SHA384".equals(s));
	}
	
	@Test
	public void testConcatenation2(){
		String[] s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305");
		assertTrue(Arrays.equals(s, new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"}));
		
		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
		assertTrue(Arrays.equals(s, new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}));
		
		s = WolfSSLCipherSuiteList.getJavaCipherSuiteList("DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDH-ECDSA-AES256-SHA384");
		assertTrue(Arrays.equals(s, new String[]{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"}));
	}
}
