/* 
 * Copyright 2010...2015 Colin Crist
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package org.messageforge.fixutil.bin2fix;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.BufferUnderflowException;
import java.nio.MappedByteBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.log4j.Logger;
import org.jnetpcap.app.IpReassembler;
import org.jnetpcap.app.IpReassembler.IpReassemblyPayloadHander;
import org.messageforge.fixutil.NIOFIXFileReader;

import quickfix.ConfigError;
import quickfix.DataDictionary;
import quickfix.FieldMap;
import quickfix.FieldNotFound;
import quickfix.Message;
import quickfix.field.ClOrdID;
import quickfix.field.MsgType;
import quickfix.field.SenderCompID;
import quickfix.field.TargetCompID;
import au.com.bytecode.opencsv.CSVWriter;

/**
 * A utility to read FIX messages from either a file of raw messages or a pcap
 * file containing a single TCP/IP conversation.
 * 
 * @author colincrist@messageforge.org
 *
 */
public class BinaryToFIX {
	private static final Logger log = Logger.getLogger(BinaryToFIX.class);
	private final File file;
	private final CSVWriter writer;
	private final List<String> fields;
	private final List<String> msgTypes;
	private final List<String> compIDs;
	private final boolean isPcap;
	private final DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd-HH:mm:ss.SSS");
	private final Map<String, Map<String, Long>> times = new HashMap<String, Map<String, Long>>();
	private DataDictionary sessionDict;
	private DataDictionary appDict;
	private final boolean appOnly;
	private String filter;
	private TimeUnit latencyTU = TimeUnit.MICROSECONDS;

	public BinaryToFIX(File file, boolean isPcap, CSVWriter writer, List<String> fields, List<String> msgTypes, List<String> compIDs, boolean appOnly,
			DataDictionary sessionDict, DataDictionary appDict, String filter, TimeUnit latencyTU) throws ConfigError {
		this.file = file;
		this.writer = writer;
		this.fields = fields;
		this.msgTypes = msgTypes;
		this.compIDs = compIDs;
		this.isPcap = isPcap;
		this.appOnly = appOnly;
		this.sessionDict = sessionDict;
		this.appDict = appDict;
		this.filter = filter;
		this.latencyTU = latencyTU;
	}

	public static void main(String[] args) {
		final Options options = new Options();

		options.addOption("pcap", false, "Indicates this is a pcap file and needs reassembly");
		options.addOption("dir", true, "Directory (all files will be parsed");
		options.addOption("in", true, "Input file");
		options.addOption("out", true, "Output file");
		options.addOption("fields", true, "Fields (comma separated). Use \"Bytes\" to display the raw message");
		options.addOption("msgTypes", true, "Filter message types (comma separated)");
		options.addOption("compIDs", true, "Filter Sender/TargetCompIDs (comma separated)");
		options.addOption("appOnly", false, "Filter session messages");
		options.addOption("sessionDict", true, "Session dictionary (or both if pre FIX5.0)");
		options.addOption("appDict", true, "Application dictionary");
		options.addOption("filter", true, "Packet filter");
		options.addOption("millis", false, "Convert latency to milliseconds");

		final CommandLineParser parser = new PosixParser();

		try {
			final CommandLine line = parser.parse(options, args);

			if (line.hasOption("fields")) {

			} else if (!line.hasOption("appDict")) {
				error(options);
			}

			final OutputStream ostream = line.hasOption("out") ? new FileOutputStream(new File(line.getOptionValue("out"))) : System.out;
			final List<String> msgTypes = line.hasOption("msgTypes") ? Arrays.asList(line.getOptionValue("msgTypes").split(",")) : null;
			final List<String> compIDs = line.hasOption("compIDs") ? Arrays.asList(line.getOptionValue("compIDs").split(",")) : null;
			final boolean isPcap = line.hasOption("pcap");
			final boolean appOnly = line.hasOption("appOnly");
			final List<String> fields = new ArrayList<String>(Arrays.asList(line.getOptionValue("fields").split(",")));
			final DataDictionary appDict = new DataDictionary(new FileInputStream(line.getOptionValue("appDict")));
			final DataDictionary sessionDict = new DataDictionary(new FileInputStream(line.getOptionValue("sessionDict")));
			final String filter = line.hasOption("filter") ? line.getOptionValue("filter") : null;
			final TimeUnit latencyTU = line.hasOption("millis") ? TimeUnit.MILLISECONDS : TimeUnit.MICROSECONDS;

			if (isPcap) {
				fields.add(0, "Capture Timestamp");
				fields.add(1, "Capture Micros");
				fields.add(2, "Latency");
			}

			final CSVWriter writer = new CSVWriter(new OutputStreamWriter(ostream));
			writer.writeNext(fields.toArray(new String[fields.size()]));

			if (line.hasOption("dir")) {
				final File dir = new File(line.getOptionValue("dir"));
				for (File file : dir.listFiles()) {
					if (file.isFile()) {
						log.info("processing file " + file.getName());
						new BinaryToFIX(file, isPcap, writer, fields, msgTypes, compIDs, appOnly, sessionDict, appDict, filter, latencyTU).run();
					}
				}
			} else if (line.hasOption("in")) {
				new BinaryToFIX(new File(line.getOptionValue("in")), isPcap, writer, fields, msgTypes, compIDs, appOnly, sessionDict, appDict, filter,
						latencyTU).run();
			} else {
				error(options);
			}

			writer.flush();
			writer.close();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
		}
	}

	private final String getSafeFieldValue(final FieldMap message, final int tag) {
		String s = null;
		try {
			s = message.getString(tag);
		} catch (FieldNotFound e) {
			// log.error(e.getMessage(), e);
		}
		return s == null ? "" : s;
	}

	private final void process(final long timestampInMicro, final Message message) throws FieldNotFound {
		if (msgTypes != null && !msgTypes.contains(message.getHeader().getString(MsgType.FIELD))) {
			return;
		}

		if (compIDs != null
				&& (!compIDs.contains(message.getHeader().getString(SenderCompID.FIELD)) || !compIDs
						.contains(message.getHeader().getString(TargetCompID.FIELD)))) {
			return;
		}

		final ArrayList<String> line = new ArrayList<String>();

		if (timestampInMicro > 0) {
			line.add(dateFormat.format(new Date(timestampInMicro / 1000)));
			line.add(new Long(timestampInMicro).toString());
			checkLatency(timestampInMicro, message, line);
		}

		final int startIndex = timestampInMicro > 0 ? 3 : 0;

		for (int i = startIndex; i < fields.size(); i++) {
			final String field = fields.get(i);

			if (field.equalsIgnoreCase("bytes")) {
				line.add(message.toString());
			} else {
				int tag = appDict.getFieldTag(field);
				if (tag == -1) {
					tag = sessionDict.getFieldTag(field);
				}
				if (sessionDict.isHeaderField(tag)) {
					line.add(getSafeFieldValue(message.getHeader(), tag));
				} else if (sessionDict.isTrailerField(tag)) {
					line.add(getSafeFieldValue(message.getTrailer(), tag));
				} else {
					line.add(getSafeFieldValue(message, tag));
				}
			}
		}

		writer.writeNext(line.toArray(new String[line.size()]));
	}

	private final void checkLatency(final long captureTime, final Message message, final ArrayList<String> line) throws FieldNotFound {
		try {
			final String senderCompID = message.getHeader().getString(SenderCompID.FIELD);
			final String targetCompID = message.getHeader().getString(TargetCompID.FIELD);
			final String msgType = message.getHeader().getString(MsgType.FIELD);

			if (!times.containsKey(senderCompID)) {
				times.put(senderCompID, new HashMap<String, Long>());
			}

			if (!times.containsKey(targetCompID)) {
				times.put(targetCompID, new HashMap<String, Long>());
			}

			if (msgType.equals(MsgType.ORDER_SINGLE)) {
				final String clOrdID = message.getString(ClOrdID.FIELD);
				times.get(senderCompID).put(clOrdID, captureTime);
				line.add("");
			} else if (msgType.equals(MsgType.ORDER_CANCEL_REPLACE_REQUEST)) {
				String clOrdID = message.getString(ClOrdID.FIELD);
				times.get(senderCompID).put(clOrdID, captureTime);
				line.add("");
			} else if (msgType.equals(MsgType.EXECUTION_REPORT)) {
				final String clOrdID = message.getString(ClOrdID.FIELD);
				Long orderTime = times.get(targetCompID).get(clOrdID);

				if (orderTime != null) {
					if (latencyTU.equals(TimeUnit.MILLISECONDS)) {
						line.add(Long.toString((captureTime - orderTime.longValue()) / 1000));
					} else {
						line.add(Long.toString(captureTime - orderTime.longValue()));
					}
					times.get(targetCompID).remove(clOrdID);
				} else {
					line.add("");
				}
			} else {
				line.add("");
			}
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
		}
	}

	public static byte[] concat(byte[] first, byte[] second) {

		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	private void run() {
		try {
			if (isPcap) {
				IpReassembler.reassemble(file, new IpReassemblyPayloadHander() {
					byte[] lastBlock;

					@Override
					public void nextBlock(long timestampInMicro, byte[] block) {
						try {
							// If we've still got the back end of the last
							// packet then add it to the front
							// of this data to stick a FIX message thats been
							// fragmented back together.

							if (lastBlock != null) {
								block = concat(lastBlock, block);
							}

							try (NIOFIXFileReader reader = new NIOFIXFileReader(MappedByteBuffer.wrap(block), appDict, sessionDict)) {
								Message message = null;
								while ((message = reader.readMessage()) != null) {
									if (appOnly && !message.isApp()) {
										// Skip
									} else {
										process(timestampInMicro, message);
									}
								}
							}
							lastBlock = null;
						} catch (BufferTruncatedException ex) {
							// We ran out of buffer part way through a message
							// to keep whatever part of the FIX message
							// we've got so we can add it to the next one.

							lastBlock = Arrays.copyOf(block, ex.getStartOfMessageOffset());
						} catch (BufferUnderflowException ex) {
							lastBlock = null;
							// End of packet.
						} catch (Throwable t) {
							lastBlock = null;
							log.error(t.getMessage(), t);
						}
					}
				}, filter);
			} else {
				final FileInputStream istream = new FileInputStream(file);
				try (NIOFIXFileReader reader = new NIOFIXFileReader(istream, appDict, sessionDict)) {
					Message message = null;
					while ((message = reader.read()) != null) {
						if (appOnly && !message.isApp()) {
							// Skip
						} else {
							process(-1, message);
						}
					}
				}
			}
		} catch (Throwable e) {
			log.error(e.getMessage(), e);
		}
	}

	private static void error(final Options options) {
		new HelpFormatter().printHelp(BinaryToFIX.class.getName(), options);
		System.exit(1);
	}
}
