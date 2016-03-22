package us.daveread.education.mongo.honeypot.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import us.daveread.education.mongo.honeypot.CountryCount;

/**
 * Unit tests for the CountryCount class.
 * @author readda
 */
public class TestCountryCount {
  /**
   * The test instance
   */
  private CountryCount cc;

  /**
   * Setup the test instance.
   */
  @Before
  public void setup() {
    cc = new CountryCount("AA", 123);
  }

  /**
   * Tests the attack count getter.
   */
  @Test
  public void testAttackCount() {
    assertEquals(123, cc.getAttackCount());
  }

  /**
   * Tests the country code getter.
   */
  @Test
  public void testCountryCode() {
    assertEquals("AA", cc.getCountryCode());
  }

  /**
   * Test the comparison operation with different values
   */
  @Test
  public void testCompareToDifferent() {
    CountryCount cc2 = new CountryCount("ZZ", 100);

    assertTrue("Incorrect comparison result", cc.compareTo(cc2) > 0);
  }

  /**
   * Test the comparison operation with equivalent values
   */
  @Test
  public void testCompareToSame() {
    CountryCount cc2 = new CountryCount("ZZ", 123);

    assertEquals(0, cc.compareTo(cc2));
  }

  /**
   * Force the Comparable bridge method to be executed so that code coverage is
   * complete. See: https://sourceforge.net/p/cobertura/bugs/92/
   */
  @Test
  public void testForceBridgeMethodCall() {
    Comparable<CountryCount> cc2 = cc;
    assertEquals(0, cc2.compareTo(cc));
  }
}
