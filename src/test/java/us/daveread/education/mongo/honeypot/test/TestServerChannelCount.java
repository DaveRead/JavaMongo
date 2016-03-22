package us.daveread.education.mongo.honeypot.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import us.daveread.education.mongo.honeypot.ServerChannelCount;

/**
 * Unit tests for the ServerChannelCount class.
 * @author readda
 */
public class TestServerChannelCount {
  /**
   * The test instance.
   */
  private ServerChannelCount scc;

  /**
   * Setup the test instance
   */
  @Before
  public void setup() {
    scc = new ServerChannelCount("2,BB", 321);
  }

  /**
   * Tests the server IP mask getter.
   */
  @Test
  public void testServerIpMask() {
    assertEquals(2, scc.getServerIpMask());
  }

  /**
   * Tests the channel getter.
   */
  @Test
  public void testChannel() {
    assertEquals("BB", scc.getChannel());
  }

  /**
   * Tests the attack count getter.
   */
  @Test
  public void testAttackCount() {
    assertEquals(321, scc.getAttackCount());
  }

  /**
   * Test the comparison operation with different servers.
   */
  @Test
  public void testCompareToDiffServer() {
    ServerChannelCount scc2 = new ServerChannelCount("4,BB", 1);

    assertTrue("Incorrect comparison result, server comes later ",
      scc.compareTo(scc2) < 0);
  }

  /**
   * Test the comparison operation with same servers and different channels.
   */
  @Test
  public void testCompareToDiffChannel() {
    ServerChannelCount scc2 = new ServerChannelCount("2,AA", 1);

    assertTrue("Incorrect comparison result, channel comes earlier",
      scc.compareTo(scc2) > 0);
  }

  /**
   * Test the comparison operation with same servers and channels.
   */
  @Test
  public void testCompareToSame() {
    ServerChannelCount scc2 = new ServerChannelCount("2,BB", 1);

    assertEquals(0, scc.compareTo(scc2));
  }

  /**
   * Force the Comparable bridge method to be executed so that code coverage is
   * complete. See: https://sourceforge.net/p/cobertura/bugs/92/
   */
  @Test
  public void testForceBridgeMethodCall() {
    Comparable<ServerChannelCount> scc2 = scc;
    assertEquals(0, scc2.compareTo(scc));
  }

}
