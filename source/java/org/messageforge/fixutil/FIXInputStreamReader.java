/* 
 * Copyright 2003,2004,2005...2015 Colin Crist
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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.log4j.Logger;

import quickfix.DataDictionary;
import quickfix.InvalidMessage;
import quickfix.Message;

/**
 * Reads QuickFIX messages from an InputStream. Very inefficient compared to NIOFIXFileReader
 * if the InputStream is a file.
 * 
 * @author colincrist@hermesjms.com
 * @author colincrist@messageforge.org
 */

public class FIXInputStreamReader implements Runnable, FIXMessageReader {
	private static final Logger log = Logger.getLogger(FIXInputStreamReader.class);

	private final ConcurrentLinkedQueue<Message> messages = new ConcurrentLinkedQueue<Message>();
	private final int maxMessageBuffer = 1024 * 512;
	private final byte[] messageBuffer;
	private int messageBufferIndex = 0;
	private final byte[] startOfMessage = new byte[] { '8', '=', 'F', 'I', 'X' };
	private boolean keepRunning = true;
	private boolean eofReached = false;
	private final boolean tail = true;
	private final InputStream istream;
	private final DataDictionary appDataDictionary;
	private final DataDictionary sessionDataDictionary;

	public FIXInputStreamReader(InputStream istream, DataDictionary sessionDataDictionary, DataDictionary appDataDictionary) {
		super();
		this.istream = istream;
		this.messageBuffer = new byte[maxMessageBuffer];
		this.appDataDictionary = appDataDictionary;
		this.sessionDataDictionary = sessionDataDictionary;

		new Thread(this, "FIXSniffer").start();
	}

	public FIXInputStreamReader(InputStream istream, DataDictionary sessionDataDictionary) {
		this(istream, null, sessionDataDictionary);
	}

	public void release() {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hermes.fix.FIXReader#close()
	 */
	@Override
	public void close() {
		keepRunning = false;
		eofReached = true;

		try {
			istream.close();
		} catch (IOException ex) {
			log.error(ex.getMessage(), ex);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hermes.fix.FIXReader#read()
	 */
	@Override
	public Message read() throws IOException {
		return read(-1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hermes.fix.FIXReader#read(long)
	 */
	@Override
	public Message read(final long timeout) throws IOException {
		synchronized (messages) {
			while (messages.size() == 0) {
				checkEOF();

				try {
					if (timeout == -1) {
						messages.wait();
					} else if (timeout == 0) {
						return null;
					} else {
						messages.wait(timeout);
					}
				} catch (InterruptedException e) {
					// NOP
				}
			}

			checkEOF();

			if (messages.size() > 0) {
				return messages.poll();
			} else {
				return null;
			}
		}
	}

	protected void checkEOF() throws EOFException {
		synchronized (messages) {
			if (messages.size() == 0 && eofReached) {
				throw new EOFException("EOF");
			}
		}
	}

	@Override
	public void run() {
		try {
			while (keepRunning) {
				try {
					Message message = readMessage();

					if (message != null) {
						synchronized (messages) {
							messages.add(message);

							if (messages.size() == 1) {
								messages.notifyAll();
							}
						}
					}
				} catch (EOFException ex) {
					if (!tail) {
						return;
					}
				} catch (Exception ex) {
					log.warn(ex.getMessage(), ex);
				}

			}
		} catch (Throwable ex) {
			log.error(ex.getMessage(), ex);
		} finally {
			eofReached = true;

			synchronized (messages) {
				messages.notifyAll();
			}
		}
	}

	byte readByte(InputStream istream, byte[] bytes, int offset, int length) throws IOException {
		int i = istream.read(bytes, offset, length);

		if (i == -1) {
			if (!tail) {
				eofReached = true;
			}
			throw new EOFException("EOF");

		} else {
			return (byte) i;
		}
	}

	byte readByte(InputStream istream) throws IOException {
		int i = istream.read();

		if (i == -1) {
			if (!tail) {
				eofReached = true;
			}
			throw new EOFException("EOF");
		} else {
			return (byte) i;
		}
	}

	private Message readMessage() throws IOException, InvalidMessage {
		// checkEOF();

		byte b;

		// Arrays.fill(messageBuffer, (byte) 0);

		while (messageBufferIndex < startOfMessage.length) {
			b = readByte(istream);

			if (startOfMessage[messageBufferIndex] == b) {
				messageBuffer[messageBufferIndex++] = b;
			} else {
				messageBufferIndex = 0;
			}
		}

		//
		// Found a message, scan for the next tag.

		while ((b = readByte(istream)) != '\1') {
			messageBuffer[messageBufferIndex++] = b;
		}

		messageBuffer[messageBufferIndex] = '\0';
		String protocol = new String(messageBuffer, 0, messageBufferIndex).split("=")[1];
		messageBuffer[messageBufferIndex++] = '\1';

		b = readByte(istream);

		if (b != '9') {
			throw new IOException("Tag 9 does not follow tag 8");
		}

		messageBuffer[messageBufferIndex++] = b;
		messageBuffer[messageBufferIndex++] = (byte) istream.read();

		byte[] messageLengthBuffer = new byte[16];
		int messageLengthBufferOffset = 0;

		while ((b = readByte(istream)) != '\1') {
			messageBuffer[messageBufferIndex++] = b;
			messageLengthBuffer[messageLengthBufferOffset++] = b;
		}

		messageLengthBuffer[messageLengthBufferOffset++] = '\1';
		messageBuffer[messageBufferIndex++] = '\1';

		final String s = new String(messageLengthBuffer).trim();
		final int messageLength = Integer.parseInt(s);

		if (messageLength > maxMessageBuffer) {
			throw new IOException("BodyLength is too big, " + messageLength + " > " + maxMessageBuffer);
		}

		readByte(istream, messageBuffer, messageBufferIndex, messageLength);

		messageBufferIndex += messageLength;

		/*
		 * for (int i = 0; i < messageLength; i++) {
		 * messageBuffer[messageBufferIndex++] = readByte(istream); }
		 */

		// Scan over the last tag
		while ((b = readByte(istream)) != '\1') {
			messageBuffer[messageBufferIndex++] = b;
		}

		messageBuffer[messageBufferIndex++] = '\1';

		final byte[] rval = new byte[messageBufferIndex];
		System.arraycopy(messageBuffer, 0, rval, 0, messageBufferIndex);

		messageBufferIndex = 0;

		Message fix = new Message();
		if (appDataDictionary != null) {
			fix.fromString(new String(rval), sessionDataDictionary, appDataDictionary, false);
		} else {
			fix.fromString(new String(rval), sessionDataDictionary, false);
		}
		return fix;
	}

}
