package us.daveread.education.mongo.honeypot;

/**
 * A Javabean for storing country code and attack counts.
 * <p>
 * Copyright (C) 2016 David S. Read
 * <p>
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/
 * @author readda
 */
public class CountryCount implements Comparable<CountryCount> {
  /**
   * The country code.
   */
  private String countryCode;

  /**
   * The number of attacks associated with the country.
   */
  private int attackCount;

  /**
   * Create the instance.
   * @param countryCode
   *          The country code
   * @param attackCount
   *          The number of attacks
   * @see #setCountryCode(String)
   * @see #setAttackCount(int)
   */
  public CountryCount(String countryCode, int attackCount) {
    setCountryCode(countryCode);
    setAttackCount(attackCount);
  }

  /**
   * Get the country code.
   * @return The country code
   */
  public String getCountryCode() {
    return countryCode;
  }

  /**
   * Set the country code.
   * @param countryCode
   *          The country code
   */
  public void setCountryCode(String countryCode) {
    this.countryCode = countryCode;
  }

  /**
   * Get the number of attacks.
   * @return The number of attacks
   */
  public int getAttackCount() {
    return attackCount;
  }

  /**
   * Set the number of attacks.
   * @param attackCount
   *          The number of attacks
   */
  public void setAttackCount(int attackCount) {
    this.attackCount = attackCount;
  }

  @Override
  public int compareTo(CountryCount o) {
    return getAttackCount() - o.getAttackCount();
  }
}
