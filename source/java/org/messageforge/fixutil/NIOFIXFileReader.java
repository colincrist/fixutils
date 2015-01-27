/* Copyright 2003,2004,2005...2015 Colin Crist
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

package org.messageforge.fixutil;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.messageforge.fixutil.bin2fix.BufferTruncatedException;

import quickfix.DataDictionary;
import quickfix.InvalidMessage;
import quickfix.Message;

/**
 * Reads QuickFIX messages from either a file or a ByteByffer using NIO and mmap.
 * 
 * @author colincrist@hermesjms.com
 * @author colincrist@messageforge.org
 */

public class NIOFIXFileReader implements Runnable, FIXMessageReader, AutoCloseable {
	private static final Logger log = Logger.getLogger(NIOFIXFileReader.class);
	private static byte[] START_OF_MESSAGE = new byte[] { '8', '=', 'F', 'I', 'X' };
	private FileInputStream istream;
	private ByteBuffer parseBuffer;
	private ByteBuffer readBuffer;
	private final Object lock = new Object();
	private int position = 0;
	private int mappedStart;
	private boolean tail = false;

	private final BlockingQueue<Message> messages = new ArrayBlockingQueue<Message>(8192);
	private DataDictionary appDataDictionary;
	private final DataDictionary sessionDataDictionary;

	public NIOFIXFileReader(FileInputStream istream, DataDictionary appDataDictionary, DataDictionary sessionDataDictionary) throws IOException {
		this.istream = istream;
		this.appDataDictionary = appDataDictionary;
		this.sessionDataDictionary = sessionDataDictionary;
		map();

		new Thread(this).start();
	}

	public NIOFIXFileReader(FileInputStream istream, DataDictionary sessionDataDictionary) throws IOException {
		this.istream = istream;
		this.sessionDataDictionary = sessionDataDictionary;
		this.tail = true;
		map();

		new Thread(this).start();
	}

	public NIOFIXFileReader(ByteBuffer parseBuffer, DataDictionary appDataDictionary, DataDictionary sessionDataDictionary) throws IOException {
		this.parseBuffer = parseBuffer;
		this.readBuffer = parseBuffer.duplicate();
		this.appDataDictionary = appDataDictionary;
		this.sessionDataDictionary = sessionDataDictionary;
		this.tail = false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see tp.fix.io.FIXMessageReader#read()
	 */
	@Override
	public Message read() throws IOException {
		return read(-1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see tp.fix.io.FIXMessageReader#read(long)
	 */
	@Override
	public Message read(final long timeout) {
		try {
			Message rval = messages.poll(100, TimeUnit.MILLISECONDS);

			while (rval == null && istream.getChannel().isOpen()) {
				rval = messages.poll(100, TimeUnit.MILLISECONDS);
			}

			return rval;
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			return null;
		}
	}

	public byte[] getBytes(int offset, int length) {
		synchronized (lock) {
			byte[] bytes = new byte[length];
			readBuffer.position(offset);
			readBuffer.get(bytes);
			return bytes;
		}
	}

	private void waitAndRemap() throws InterruptedException, IOException {
		Thread.sleep(500);

		map();
	}

	/**
	 * If this reader is being used on a file then a thread runs this to parse all 
	 * the messages it can find, if its tailing the file it will remap any new data 
	 * found and parse that. 
	 */
	@Override
	public void run() {
		try {
			while (istream.getChannel().isOpen()) {
				try {
					final Message m = readMessage();

					if (m != null) {
						messages.put(m);
					}
				} catch (InvalidMessage ex) {
					log.error(ex.getMessage(), ex);
				} catch (BufferUnderflowException ex) {
					if (tail) {
						waitAndRemap();
					} else {
						istream.close();
					}
				} catch (IllegalArgumentException ex) {
					if (tail) {
						waitAndRemap();
					} else {
						istream.close();
					}
				} catch (ArrayIndexOutOfBoundsException ex) {
					log.info(ex.getMessage());
				}
			}

			log.debug("channel closed");

		} catch (Throwable ex) {
			log.error(ex.getMessage(), ex);
		}
	}

	/**
	 * The guts of trying to pull apart a FIX message from the buffer and then use QuickFIX to parse it.
	 * 
	 * @return
	 * @throws BufferUnderflowException
	 * @throws InterruptedException
	 * @throws IOException
	 * @throws InvalidMessage
	 * @throws BufferTruncatedException
	 */
	public Message readMessage() throws BufferUnderflowException, InterruptedException, IOException, InvalidMessage, BufferTruncatedException {
		parseBuffer.position(position);

		byte b;
		int startOfMessageIndex = 0;

		while (startOfMessageIndex < START_OF_MESSAGE.length) {
			b = parseBuffer.get();

			if (START_OF_MESSAGE[startOfMessageIndex] == b) {
				startOfMessageIndex++;
			} else {
				startOfMessageIndex = 0;
			}
		}

		int startOfMessageOffset = parseBuffer.position() - START_OF_MESSAGE.length;

		//
		// Found a message, scan for the next tag.

		byte[] protocolAsBytes = new byte[12];
		int protocolAsBytesIndex = 0;

		while ((b = parseBuffer.get()) != '\1') {
			protocolAsBytes[protocolAsBytesIndex++] = b;
		}

		protocolAsBytes[protocolAsBytesIndex++] = '\0';
		b = parseBuffer.get();

		if (b != '9') {
			position = parseBuffer.position();

			throw new RuntimeException("Tag 9 does not follow tag 8");
		}

		parseBuffer.get();

		byte[] messageLengthBuffer = new byte[16];
		int messageLengthBufferOffset = 0;

		while ((b = parseBuffer.get()) != '\1') {
			messageLengthBuffer[messageLengthBufferOffset++] = b;
		}

		messageLengthBuffer[messageLengthBufferOffset++] = '\1';

		final String s = new String(messageLengthBuffer).trim();
		final int fixLength = Integer.parseInt(s);

		// Looks like we've only got part of a FIX message in this buffer, indicate in the
		// exception where we last saw a start of message so the caller can handle it.
		
		if (parseBuffer.position() + fixLength > parseBuffer.capacity()) {
			throw new BufferTruncatedException(startOfMessageOffset) ;
		}
		
		parseBuffer.position(parseBuffer.position() + fixLength);
		
		// Scan over the last tag

		while ((b = parseBuffer.get()) != '\1') {

		}

		final int messageLength = parseBuffer.position() - startOfMessageOffset;
		position = parseBuffer.position();

		protocolAsBytes[protocolAsBytesIndex++] = '\0';
		byte[] message = getBytes(startOfMessageOffset, messageLength);

		Message fix = new Message();
		if (appDataDictionary != null) {
			fix.fromString(new String(message), sessionDataDictionary, appDataDictionary, false);
		} else {
			fix.fromString(new String(message), sessionDataDictionary, false);
		}
		return fix;
	}

	private void map() throws IOException {
		synchronized (lock) {
			FileChannel channel = istream.getChannel();

			if (channel.isOpen()) {
				if (parseBuffer == null || channel.size() > mappedStart) {
					if (parseBuffer != null && parseBuffer instanceof MappedByteBuffer) {
						clean((MappedByteBuffer) parseBuffer);
					}

					if (readBuffer != null && parseBuffer instanceof MappedByteBuffer) {
						clean((MappedByteBuffer) readBuffer);
					}

					// log.debug("mapping in FIX file, mappedStart=" +
					// mappedStart +
					// " channel.size()=" + channel.size());

					mappedStart += position;

					parseBuffer = channel.map(FileChannel.MapMode.READ_ONLY, mappedStart, channel.size() - mappedStart);
					readBuffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

					position = 0;
				}
			}
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private final void clean(final MappedByteBuffer buffer) {
//		AccessController.doPrivileged(new PrivilegedAction() {
//			public Object run() {
//				try {
//					Method getCleanerMethod = buffer.getClass().getMethod("cleaner", new Class[0]);
//					getCleanerMethod.setAccessible(true);
//					sun.misc.Cleaner cleaner = (sun.misc.Cleaner) getCleanerMethod.invoke(buffer, new Object[0]);
//					cleaner.clean();
//				} catch (Exception e) {
//					log.error(e.getMessage(), e);
//				}
//				return null;
//			}
//		});
	}

	public void release() {
		synchronized (lock) {
			if (readBuffer != null) {
				if (readBuffer instanceof MappedByteBuffer) {
					clean((MappedByteBuffer) readBuffer);
				}
				readBuffer = null;
			}
		}
	}

	@Override
	protected void finalize() throws Throwable {
		release();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see tp.fix.io.FIXMessageReader#close()
	 */
	@Override
	public void close() throws IOException {
		synchronized (lock) {

			if (istream != null) {
				istream.getChannel().close();
				istream.close();

				if (parseBuffer != null) {
					if (parseBuffer instanceof MappedByteBuffer) {
						clean((MappedByteBuffer) parseBuffer);
					}
				}

				parseBuffer = null;
			}
		}
	}
}
