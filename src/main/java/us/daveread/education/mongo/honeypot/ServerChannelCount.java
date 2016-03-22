package us.daveread.education.mongo.honeypot;

/**
 * A Javabean for storing server IP mask value, channel (sensor) type and attack
 * counts.
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
public class ServerChannelCount implements Comparable<ServerChannelCount> {
  /**
   * The server IP mask value
   */
  private int serverIpMask;

  /**
   * The channel (sensor) type
   */
  private String channel;

  /**
   * The number of attacks associated with the server and channel.
   */
  private int attackCount;

  /**
   * Create the instance.
   * @param serverAndChannel
   *          The server IP mask value and channel name separated by a comma
   * @param attackCount
   *          The number of attacks
   * @see #setServerIpMask(int)
   * @see #setChannel(String)
   * @see #setAttackCount(int)
   */
  public ServerChannelCount(String serverAndChannel, int attackCount) {
    String[] parsed = serverAndChannel.split(",");
    setServerIpMask(Integer.parseInt(parsed[0]));
    setChannel(parsed[1]);
    setAttackCount(attackCount);
  }

  /**
   * Get the server IP mask value.
   * @return The server IP mask value
   */
  public int getServerIpMask() {
    return serverIpMask;
  }

  /**
   * Set the server IP mask value.
   * @param serverIpMask
   *          The server IP mask value
   */
  public void setServerIpMask(int serverIpMask) {
    this.serverIpMask = serverIpMask;
  }

  /**
   * Get the channel (sensor) type.
   * @return The channel type
   */
  public String getChannel() {
    return channel;
  }

  /**
   * Set the channel (sensor) type.
   * @param channel
   *          The channel type
   */
  public void setChannel(String channel) {
    this.channel = channel;
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
  public int compareTo(ServerChannelCount o) {
    int diff = getServerIpMask() - o.getServerIpMask();
    if (diff == 0) {
      diff = getChannel().compareTo(o.getChannel());
    }

    return diff;
  }
}
