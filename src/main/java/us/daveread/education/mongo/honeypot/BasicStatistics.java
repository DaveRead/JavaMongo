package us.daveread.education.mongo.honeypot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import org.bson.Document;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.ServerAddress;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

/**
 * Calculate basic statistics from the honeypot data. This class demonstrates
 * basic Java-MongoDB interactions including retrieving documents directly as
 * well as using the aggregation framework to use MongoDB's summarization
 * capabilities.
 * <p>
 * This program is intended to demonstrate the use of MongoDB within a Java
 * program.
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
 * <p>
 * For information on MongoDB: https://www.mongodb.com/
 * @author readda
 * @version 01.00.00
 */
public class BasicStatistics {
  /**
   * The logger
   */
  private static final Logger LOG = Logger.getLogger(BasicStatistics.class);

  /**
   * The MongoDB server
   */
  private static final String MONGO_DB_IP = "localhost";

  /**
   * The MongoDB port
   */
  private static final int MONGO_DB_PORT = 27017;

  /**
   * The database containing the honeypot-related collections.
   */
  private static final String HONEYPOT_DATABASE = "infuzitDemo";

  /**
   * The collection containing the raw anonymized honeypot data.
   */
  private static final String HONEYPOT_COLLECTION = "honeypotData";

  /**
   * The maximum number of documents to display when reporting results.
   */
  private static final int NUMBER_OF_ITEMS_TO_DISPLAY = 10;

  /**
   * The Mongo client instance - our connection to the server.
   */
  private MongoClient mongoClient;

  /**
   * The Mongo database instance - our access to a specific database.
   */

  private MongoDatabase mongoDatabase;

  /**
   * The total number of attacks in the collection. Each document represents
   * one attack.
   */
  private long totalAttacks;

  /**
   * The total number of countries represented in the attack data.
   */
  private int totalAttackingCountries;

  /**
   * Create the instance. This will populate the aggregate count of documents
   * (attacks) and countries.
   * @see #totalAttacks
   * @see #computeAttackCountryCount()
   */
  public BasicStatistics() {
    LOG.info("Connecting to server: " + MONGO_DB_IP + ":" + MONGO_DB_PORT
      + " and database: " + HONEYPOT_DATABASE);

    /**
     * Set a short timeout for connecting so that we don't wait the default 30
     * seconds to detect a problem.
     */
    MongoClientOptions.Builder optionsBuilder =
      new MongoClientOptions.Builder();
    optionsBuilder.serverSelectionTimeout(2000);

    MongoClientOptions options = optionsBuilder.build();

    /**
     * Create the MongoClient instance.
     */
    mongoClient =
      new MongoClient(new ServerAddress(MONGO_DB_IP, MONGO_DB_PORT), options);

    /**
     * Create the MongoDatabase instance.
     */
    mongoDatabase = mongoClient.getDatabase(HONEYPOT_DATABASE);

    /**
     * Get the MongoCollection instance which provides read and write access
     * (bed on permissions) to a specific collection in the database.
     */
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);

    /**
     * Get the count of documents in the collection. If the collection cannot be
     * accessed an exception will the thrown.
     */
    try {
      totalAttacks = collection.count();
    } catch (Throwable throwable) {
      LOG.fatal("Unable to connect to the MongoDB instance at " + MONGO_DB_IP
        + ":" + MONGO_DB_PORT, throwable);
      throw new IllegalStateException(
        "Unable to connect to the MongoDB instance at " + MONGO_DB_IP + ":"
          + MONGO_DB_PORT + ". Are you sure it is running?",
        throwable);
    }

    /**
     * If no documents were retrieved then apparently the demo collection was
     * not loaded into the database.
     */
    if (totalAttacks == 0) {
      throw new IllegalStateException(
        "Unable to load documents from the collection " + HONEYPOT_COLLECTION
          + " in the database " + HONEYPOT_DATABASE
          + ". Are you sure it was loaded?");
    }

    computeAttackCountryCount();
  }

  /**
   * Get a Mongo collection instance.
   * @param collection
   *          The name of the collection
   * @return The Mongo collection instance
   */
  private MongoCollection<Document> accessCollection(String collection) {
    return mongoDatabase.getCollection(collection);
  }

  /**
   * Calculate the number of countries found in the honeypot attack data and
   * set the attribute.
   * @see #totalAttackingCountries
   */
  private void computeAttackCountryCount() {
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);

    Map<String, String> attackCountries = new HashMap<>();
    List<Document> attacks = collection.find()
      .projection(new Document("_id", 0).append("client_country_code", 1))
      .into(new ArrayList<Document>());
    for (Document attack : attacks) {
      String countryCode = attack.getString("client_country_code");
      if (attackCountries.get(countryCode) == null) {
        attackCountries.put(countryCode, countryCode);
      }
    }
    totalAttackingCountries = attackCountries.size();

  }

  /**
   * Report the overall statistics on the console.
   * @see #totalAttacks
   * @see #totalAttackingCountries
   */
  private void overallStats() {
    printHeader("Overall Statistics");
    System.out.println("Total Attacks: " + totalAttacks);
    System.out.println("Total Attacking Countries: " + totalAttackingCountries);
  }

  /**
   * Summarize the count of attacks by country. This method queries the
   * collection for all attack documents and then uses a Map to aggregate the
   * data. The resulting Map is then used to populate an array of CountryCode
   * instances which is then sorted in order to find the top attacking
   * countries.
   * <p>
   * Compare this to the countryBreakdownAggregation which produces the same
   * report but uses MongoDB's aggregation framework.
   * @see #countryBreakdownAggregation()
   */
  private void countryBreakdownCoded() {
    Map<String, Integer> attacksByCountry = new HashMap<>();
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);

    /**
     * Retrieve the client_country_code from each document. The find()
     * method returns an iterable which will iterate through all the
     * documents. The projection() is then used to limit the retrieved
     * fields to just the one with the client system's country code.
     */
    FindIterable<Document> attacks = collection.find()
      .projection(new Document("_id", 0).append("client_country_code", 1));

    /**
     * Iterate through all the documents and keep a count of matches by
     * country code.
     */
    for (Document attack : attacks) {
      String countryCode = attack.getString("client_country_code");
      Integer attackCount = attacksByCountry.get(countryCode);
      if (attackCount == null) {
        attackCount = 0;
      }
      attackCount++;
      attacksByCountry.put(countryCode, attackCount);
    }

    /**
     * Create an array to house the resulting country codes and counts.
     */
    List<CountryCount> countryAttackCount = new ArrayList<>();

    /**
     * Populate the array with country codes and counts from the map.
     */
    for (String countryCode : attacksByCountry.keySet()) {
      countryAttackCount
        .add(new CountryCount(countryCode, attacksByCountry.get(countryCode)));
    }

    /**
     * Sort the resulting array (note that CountryCount implements
     * Comparable). The sort is then reversed to put the largest number
     * first.
     */
    Collections.sort(countryAttackCount);
    Collections.reverse(countryAttackCount);

    /**
     * Report the top country codes with their associated attack counts.
     */
    int limit = Math.min(totalAttackingCountries, NUMBER_OF_ITEMS_TO_DISPLAY);
    printHeader(
      "Top " + limit + " Attack Countries (using Java coded aggregation)");
    for (int index = 0; index < limit; ++index) {
      int numAttacks = countryAttackCount.get(index).getAttackCount();
      System.out.println("  " + countryAttackCount.get(index).getCountryCode()
        + ": " + numAttacks + " ("
        + (int) ((numAttacks * 100) / (double) totalAttacks) + "%)");
    }
  }

  /**
   * Summarize the number of attacks recorded by each honeypot server and
   * channel (sensor). This method queries the collection for all attack
   * documents and then uses a Map to aggregate the data. The resulting Map is
   * then used to populate an array of ServerChannelCount instances which is
   * then sorted in order to present the servers and channels in order.
   * <p>
   * Compare this to the honeypotBreakdownAggregation which produces the same
   * report but uses MongoDB's aggregation framework.
   * @see #honeypotBreakdownAggregation()
   */
  private void honeypotBreakdownCoded() {
    Map<String, Integer> attacksByServerAndChannel = new HashMap<>();
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);

    /**
     * Retrieve the server_ip_mask (in the payload subdocument) and channel
     * from each document. The find() method returns an iterable which will
     * iterate through all the documents. The projection() is then used to
     * limit the retrieved fields to just the server_ip_mask and channel.
     */
    FindIterable<Document> attacks = collection.find()
      .projection(new Document("_id", 0).append("payload.server_ip_mask", 1)
        .append("channel", 1));

    /**
     * Iterate through all the documents and keep a count of matches by
     * server and channel.
     */
    for (Document attack : attacks) {
      Document payload = (Document) attack.get("payload");
      String serverAndChannel = payload.getInteger("server_ip_mask") + ","
        + attack.getString("channel");
      Integer attackCount = attacksByServerAndChannel.get(serverAndChannel);
      if (attackCount == null) {
        attackCount = 0;
      }
      attackCount++;
      attacksByServerAndChannel.put(serverAndChannel, attackCount);
    }

    /**
     * Create an array to house the resulting servers, channels and counts.
     */
    List<ServerChannelCount> serverChannelAttackCount = new ArrayList<>();

    /**
     * Populate the array with server and channel as well as the counts from
     * the map.
     */
    for (String countryCode : attacksByServerAndChannel.keySet()) {
      serverChannelAttackCount
        .add(new ServerChannelCount(countryCode,
          attacksByServerAndChannel.get(countryCode)));
    }

    /**
     * Sort the resulting array (note that ServerChannelCount implements
     * Comparable).
     */
    Collections.sort(serverChannelAttackCount);

    /**
     * Report the attack counts for each server and channel.
     */
    printHeader(
      "Attack Counts for Servers and Channels (using Java coded aggregation)");
    for (ServerChannelCount serverChannel : serverChannelAttackCount) {
      int numAttacks = serverChannel.getAttackCount();
      System.out.println("  Server:" + serverChannel.getServerIpMask()
        + " Channel:" + serverChannel.getChannel()
        + " Attack Count:" + numAttacks + " ("
        + (int) ((numAttacks * 100) / (double) totalAttacks) + "%)");
    }
  }

  /**
   * Summarize the count of attacks by country. This method uses MongoDB's
   * aggregation framework to summarize the data. It then retrieves the
   * resulting documents and displays them.
   * <p>
   * Compare this to the countryBreakdownCoded which produces the same report
   * but reads the raw documents and then uses Java code to produce the
   * summary.
   * <p>
   * Note that this method creates a aggregation pipeline matching the
   * following JSON (which can be used in the Mongo client directly):
   * 
   * <pre>
   * # summarize country 
   * db.honeypotData.aggregate( [ 
   *  { "$group": { "_id": "$client_country_code" , "hits": { "$sum": 1 } } }, 
   *  { "$sort": { "hits":-1} } 
   * ])
   * </pre>
   * 
   * @see #countryBreakdownCoded()
   */
  private void countryBreakdownAggregation() {
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);
    List<Document> aggregationPipeline = new ArrayList<>();
    Document operation;

    /**
     * Group the data on country code. Count the number of documents in each
     * group.
     */
    operation = new Document("$group",
      new Document("_id", "$client_country_code").append("attacks",
        new Document("$sum", 1)));
    aggregationPipeline.add(operation);

    /**
     * Sort the data on count of attacks, descending.
     */
    operation = new Document("$sort", new Document("attacks", -1));
    aggregationPipeline.add(operation);

    /**
     * Get the iterable for the pipeline result.
     */
    AggregateIterable<Document> attacks =
      collection.aggregate(aggregationPipeline);

    /**
     * Report the top country codes with their associated attack counts.
     */
    int limit = Math.min(totalAttackingCountries, NUMBER_OF_ITEMS_TO_DISPLAY);
    printHeader(
      "Top " + limit + " Attack Countries (using aggregation pipeline)");
    int count = 0;
    for (Document attack : attacks) {
      int numAttacks = attack.getInteger("attacks");
      System.out.println("  " + attack.get("_id") + ": " + numAttacks + " ("
        + (int) ((numAttacks * 100) / (double) totalAttacks) + "%)");
      ++count;
      if (count >= limit) {
        break;
      }
    }
  }

  /**
   * Summarize the number of attacks recorded by each honeypot server and
   * channel (sensor). This method uses MongoDB's aggregation framework to
   * summarize the data. It then retrieves the resulting documents and
   * displays them.
   * <p>
   * Compare this to the honeypotBreakdownCoded which produces the same report
   * but reads the raw documents and then uses Java code to produce the
   * summary.
   * <p>
   * Note that this method creates a aggregation pipeline matching the
   * following JSON (which can be used in the Mongo client directly):
   * 
   * <pre>
   * # summarize server and channel 
   * db.honeypotData.aggregate( [ 
   *  { "$group": { "_id": { "server_ip_mask" : "$payload.server_ip_mask" , 
   *   "channel" : "$channel" }, "attacks": { "$sum": 1 } } }, 
   *  { "$project": { "server_ip_mask" : "$_id.server_ip_mask", 
   *   "channel" : "$_id.channel", "attacks" : "$attacks" } }, 
   *  { "$sort": { "_id.server_ip_mask":1, "_id.channel":1} } 
   * ])
   * </pre>
   * 
   * @see #honeypotBreakdownAggregation()
   */
  private void honeypotBreakdownAggregation() {
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);
    List<Document> aggregationPipeline = new ArrayList<>();
    Document operation;

    /**
     * Group by server IP mask value and channel. Count the number of
     * documents in each group.
     */
    operation = new Document("$group",
      new Document("_id",
        new Document("server_ip_mask", "$payload.server_ip_mask")
          .append("channel", "$channel"))
            .append("attacks", new Document("$sum", 1)));
    aggregationPipeline.add(operation);

    /**
     * Project the attributes to extract them from the _id.
     */
    operation = new Document("$project",
      new Document("server_ip_mask", "$_id.server_ip_mask")
        .append("channel", "$_id.channel").append("attacks", 1));
    aggregationPipeline.add(operation);

    /**
     * Sort the data based on server IP mask value and channel.
     */
    operation = new Document("$sort",
      new Document("_id.server_ip_mask", 1).append("_id.channel", 1));
    aggregationPipeline.add(operation);

    /**
     * Get the iterable for the pipeline result.
     */
    AggregateIterable<Document> attacks =
      collection.aggregate(aggregationPipeline);

    /**
     * Report the attack counts for each server and channel.
     */
    printHeader(
      "Attack Counts for Servers and Channels (using aggregation pipeline)");
    for (Document attack : attacks) {
      int numAttacks = attack.getInteger("attacks");
      System.out
        .println("  Server:" + attack.getInteger("server_ip_mask") + " Channel:"
          + attack.getString("channel") + " Attack Count:" + numAttacks + " ("
          + (int) ((numAttacks * 100) / (double) totalAttacks) + "%)");
    }
  }

  /**
   * Summarize the number of attacks from each client. This method uses
   * MongoDB's aggregation framework to summarize the data. It then retrieves
   * the resulting documents and displays them.
   * <p>
   * Note that this method creates a aggregation pipeline matching the
   * following JSON (which can be used in the Mongo client directly):
   * 
   * <pre>
   * # summarize most active IPs and their countries
   * db.honeypotData.aggregate( [ 
   *  { "$group": { "_id": { "client_ip_mask" : "$payload.client_ip_mask" , 
   *   "client_country_code" : "$client_country_code" }, "attacks": { "$sum": 1 } } }, 
   *  { "$project": { "client_ip_mask" : "$_id.client_ip_mask", 
   *   "client_country_code" : "$_id.client_country_code", "attacks" : "$attacks" } }, 
   *  { "$sort": {"attacks":-1} } 
   * ])
   * </pre>
   */
  private void mostActiveIps() {
    MongoCollection<Document> collection =
      accessCollection(HONEYPOT_COLLECTION);
    List<Document> aggregationPipeline = new ArrayList<>();
    Document operation;

    /**
     * Group by client IP mask value and country code (expect a given IP to
     * always map the the same country). Count the number of documents in
     * each group.
     */
    operation = new Document("$group",
      new Document("_id",
        new Document("client_ip_mask", "$payload.client_ip_mask")
          .append("client_country_code", "$client_country_code")).append(
            "attacks",
            new Document("$sum", 1)));
    aggregationPipeline.add(operation);

    /**
     * Project the attributes to extract them from the _id.
     */
    operation = new Document("$project",
      new Document("client_ip_mask", "$_id.client_ip_mask")
        .append("client_country_code", "$_id.client_country_code")
        .append("attacks", "$attacks"));
    aggregationPipeline.add(operation);

    /**
     * Sort the data based on number of attacks, descending.
     */
    operation = new Document("$sort", new Document("attacks", -1));
    aggregationPipeline.add(operation);

    /**
     * Get the iterable for the pipeline result.
     */
    AggregateIterable<Document> attacks =
      collection.aggregate(aggregationPipeline);

    /**
     * Report the attack counts for top attacking clients.
     */
    int limit = Math.min(totalAttackingCountries, NUMBER_OF_ITEMS_TO_DISPLAY);
    printHeader(
      "Top " + limit + " Attacking Client IPs (using aggregation pipeline)");
    int count = 0;
    for (Document attack : attacks) {
      int numAttacks = attack.getInteger("attacks");
      System.out
        .println("  Client:" + attack.getInteger("client_ip_mask") + " Country:"
          + attack.getString("client_country_code") + " Attack Count:"
          + numAttacks + " ("
          + (int) ((numAttacks * 100) / (double) totalAttacks) + "%)");
      ++count;
      if (count >= limit) {
        break;
      }
    }
  }

  /**
   * Print a message on the console underlined with equal signs.
   * @param message
   *          The text the print on the console
   */
  private void printHeader(String message) {
    System.out.println(message);
    for (int index = 0; index < message.length(); ++index) {
      System.out.print("=");
    }
    System.out.println();
  }

  /**
   * Create the instance and call the different summarization methods.
   * @param args
   *          Command line arguments - not used
   */
  public static void main(String[] args) {
    BasicStatistics attackStats = new BasicStatistics();
    attackStats.overallStats();
    System.out.println();
    attackStats.countryBreakdownCoded();
    System.out.println();
    attackStats.countryBreakdownAggregation();
    System.out.println();
    attackStats.honeypotBreakdownCoded();
    System.out.println();
    attackStats.honeypotBreakdownAggregation();
    System.out.println();
    attackStats.mostActiveIps();
  }
}
