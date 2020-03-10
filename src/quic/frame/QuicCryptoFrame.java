package quic.frame;

import quic.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Iterator;

/**
 * Represents a QUIC CRYPTO frame. A CRYPTO frame carries information regarding
 * the TLS handshake. CRYPTO frames are similar to STREAM frames, but:
 * <ul>
 *     <li>They have no stream ID</li>
 *     <li>They do not carry certain markers available to the STREAM
 *     frame</li>
 * </ul>
 * CRYPTO packets can be carried in an Initial, Handshake, or short header
 * packet.
 *
 * @version 1.1
 */
public class QuicCryptoFrame extends QuicFrame {
    /**
     * Variable-length integer specifying the byte offset in the stream for
     * the data in this CRYPTO frame
     */
    private long offset;
    /**
     * The message data
     */
    private byte[] data;

    /**
     * Value constructor for the QUICCryptoFrame class. Specifies the byte
     * offset and the length
     *
     * @param offset the byte offset of the data
     * @param data the message data
     */
    public QuicCryptoFrame(long offset, byte[] data) {
        this.setOffset(offset);
        this.setData(data);
    }

    @Override
    public byte[] encode() throws IOException {
        ByteArrayOutputStream bufferOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(bufferOutputStream);

        try {
            objectOutputStream.writeObject(Util.hexStringToByteArray("6",1));
            objectOutputStream.writeObject(Util.generateVariableLengthInteger((long)this.getOffset()));
            objectOutputStream.writeObject(Util.generateVariableLengthInteger((long)this.getData().length));
            objectOutputStream.writeObject(this.getData());
            objectOutputStream.flush();

        } catch (IOException e) {

            e.printStackTrace();
        }

        byte [] data = bufferOutputStream.toByteArray();

        return data;
    }

    /**
     * Getter for the byte offset in the stream.
     *
     * @return the offset
     */
    public long getOffset() {
        return this.offset;
    }

    /**
     * Setter for the byte offset in the stream
     *
     * @param offset the offset to set
     */
    public void setOffset(long offset) {
        this.offset = offset;
    }

    /**
     * Getter for the message data
     *
     * @return the data
     */
    public byte[] getData() {
        return this.data;
    }

    /**
     * Setter for the message data
     *
     * @param data the data to set
     */
    public void setData(byte[] data) {
        this.data = data;
    }
}
