package us.daveread.education.mongo.honeypot.test;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import us.daveread.education.mongo.honeypot.BasicStatistics;

/**
 * Unit tests for the BasicStatistics class. At this point it simply run the
 * main method, expecting the database to be available.
 * @author readda
 */
public class TestBasicStatistics {
  /**
   * Execute the static main () method
   */
  @Test
  public void testMain() {
    BasicStatistics.main(new String[0]);
    assertTrue("Incorrect main method result", true);
  }
}
