package quic.packet;

import org.junit.jupiter.api.*;
import quic.frame.QuicAckFrame;
import quic.frame.QuicCryptoFrame;
import quic.frame.QuicFrame;
import quic.frame.QuicStreamFrame;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * Tests for the QuicZeroRTTPacket class
 *
 * @author Denton Wood
 */
public class QuicZeroRTTPacketTest {
    public static final Charset CHARSET = StandardCharsets.UTF_8;

    public static Stream<byte[]> getValidConnectionIds() {
        return Stream.of(new byte[0], "a".getBytes(CHARSET), "abc".getBytes(CHARSET), "#$%^&*".getBytes(CHARSET), "0".getBytes(CHARSET), "287340932".getBytes(CHARSET), "1234567890".getBytes(CHARSET));
    }

    public static Stream<byte[]> getInvalidConnectionIds() {
        return Stream.of(new byte[21], "asdfgasdfsa;lkjdfghjklhjkl".getBytes(CHARSET), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(CHARSET), "DYFUGHIJH34567890DTYUIKslerj".getBytes(CHARSET));
    }

    public static Stream<Long> getValidPacketNumbers() {
        return Stream.of(0L, 1L, 27L, Long.MAX_VALUE);
    }

    public static Stream<Long> getInvalidPacketNumbers() {
        return Stream.of(-1L, -27L, Long.MIN_VALUE);
    }

    public static int CURRENT_VERSION = 25;

    public static Stream<Integer> getValidVersions() {
        return Stream.of(0, 1, 23, 24, 25, 26, Integer.MAX_VALUE);
    }

    public static Stream<Integer> getInvalidVersions() {
        return Stream.of(-1, -62, Integer.MIN_VALUE);
    }

    public static int BASE_HEADER_BYTE = 208;

    @Nested
    public class ConstructorTest {
        @TestFactory
        public Stream<DynamicTest> testValid() {
            return getValidConnectionIds().flatMap(dcId -> getValidPacketNumbers()
                    .flatMap(packetNumber -> getValidVersions().flatMap(version ->
                            getValidConnectionIds().map(scId -> dynamicTest(
                                    "dcid = " + dcId + ", packet # = " + packetNumber + ", version = "
                                            + version + ", scid = " + scId, () -> {
                                        QuicZeroRTTPacket packet = new QuicZeroRTTPacket(dcId, packetNumber, version, scId);
                                        assertEquals(dcId, packet.getDcID());
                                        assertEquals(packetNumber, packet.getPacketNumber());
                                        assertEquals((long)version, packet.getVersion());
                                        assertEquals(scId, packet.getScID());
                                        assertEquals(0, packet.getFrames().size());
                                    })))));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidDestinationId() {
            return getInvalidConnectionIds().map(dcId -> dynamicTest("dcId = " + dcId, () -> {
                assertThrows(IllegalArgumentException.class, () -> {
                    QuicZeroRTTPacket packet = new QuicZeroRTTPacket(dcId, 1, CURRENT_VERSION, "a".getBytes(CHARSET));
                });
            }));
        }

        @Test
        public void testNullDestinationId() {
            assertThrows(NullPointerException.class, () -> {
                QuicZeroRTTPacket packet = new QuicZeroRTTPacket(null, 1, CURRENT_VERSION, "a".getBytes(CHARSET));
            });
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidSourceId() {
            return getInvalidConnectionIds().map(scId -> dynamicTest("scId = " + scId, () -> {
                assertThrows(IllegalArgumentException.class, () -> {
                    QuicZeroRTTPacket packet = new QuicZeroRTTPacket("a".getBytes(CHARSET), 1, CURRENT_VERSION, scId);
                });
            }));
        }

        @Test
        public void testNullSourceId() {
            assertThrows(NullPointerException.class, () -> {
                QuicZeroRTTPacket packet = new QuicZeroRTTPacket("a".getBytes(CHARSET), 1, CURRENT_VERSION, null);
            });
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidPacketNumber() {
            return getInvalidPacketNumbers().map(packetNum -> dynamicTest("packetNum = " + packetNum, () -> {
                assertThrows(IllegalArgumentException.class, () -> {
                    QuicZeroRTTPacket packet = new QuicZeroRTTPacket("a".getBytes(CHARSET), packetNum, CURRENT_VERSION, "b".getBytes(CHARSET));
                });
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidVersion() {
            return getInvalidVersions().map(version -> dynamicTest("version = " + version, () -> {
                assertThrows(IllegalArgumentException.class, () -> {
                    QuicZeroRTTPacket packet = new QuicZeroRTTPacket("a".getBytes(CHARSET), 1, version, "b".getBytes(CHARSET));
                });
            }));
        }
    }

    @Nested
    public class GettersAndSettersTest {
        private QuicZeroRTTPacket packet;

        @BeforeEach
        public void init() {
            this.packet = new QuicZeroRTTPacket("a".getBytes(CHARSET), 0, 0, "b".getBytes(CHARSET));
        }

        @TestFactory
        public Stream<DynamicTest> testValidDestinationIds() {
            return getValidConnectionIds().map(dcId -> dynamicTest("dcId = " + dcId, () -> {
                packet.setDcID(dcId);
                assertEquals(dcId, packet.getDcID());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidDestinationIds() {
            return getInvalidConnectionIds().map(dcId -> dynamicTest("dcId = " + dcId, () -> {
                assertThrows(IllegalArgumentException.class, () -> packet.setDcID(dcId));
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testValidSourceIds() {
            return getValidConnectionIds().map(scId -> dynamicTest("scId = " + scId, () -> {
                packet.setScID(scId);
                assertEquals(scId, packet.getScID());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidSourceIds() {
            return getInvalidConnectionIds().map(scId -> dynamicTest("scId = " + scId, () -> {
                assertThrows(IllegalArgumentException.class, () -> packet.setScID(scId));
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testValidVersions() {
            return getValidVersions().map(version -> dynamicTest("version = " + version, () -> {
                packet.setVersion(version);
                assertEquals((long)version, packet.getVersion());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidVersions() {
            return getInvalidVersions().map(version -> dynamicTest("version = " + version, () -> {
                assertThrows(IllegalArgumentException.class, () -> packet.setVersion(version));
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testValidPacketNumbers() {
            return getValidPacketNumbers().map(packetNum -> dynamicTest("packet # = " + packetNum, () -> {
                packet.setPacketNumber(packetNum);
                assertEquals(packetNum, packet.getPacketNumber());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidPacketNumbers() {
            return getInvalidPacketNumbers().map(packetNum -> dynamicTest("packet # = " + packetNum, () -> {
                assertThrows(IllegalArgumentException.class, () -> packet.setPacketNumber(packetNum));
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testAddingPackets() {
            return Stream.of(1, 3, 17, 27, 1004).map(numFrames -> dynamicTest("num frames = " + numFrames, () -> {
                Set<QuicFrame> frameList = new HashSet<>();
                for (int i = 0; i < numFrames; i++) {
                    QuicFrame frame = null;
                    if (i % 3 == 0) {
                        frame = new QuicAckFrame(i, i, i, i);
                    } else if (i % 3 == 1) {
                        frame = new QuicCryptoFrame(i, "data".getBytes());
                    } else {
                        frame = new QuicStreamFrame(i, i, false, "data".getBytes());
                    }
                    frameList.add(frame);
                    packet.addFrame(frame);
                }
                assertEquals(frameList, packet.getFrames());
            }));
        }
    }

    public byte[] writeBytes(int headerByte, int version, int dcIdLen, int dcId, int scIdLen,
                             int scId, int len, long packetNum) {
        ByteArrayOutputStream encoding = new ByteArrayOutputStream();
        // Write header byte (packet number of 0)
        encoding.write(headerByte);

        // Write all four version bytes
        encoding.write(version >> 24);
        encoding.write(version >> 16);
        encoding.write(version >> 8);
        encoding.write(version);

        // Write source and destination IDs
        encoding.write(dcIdLen);
        encoding.write(dcId);
        encoding.write(scIdLen);
        encoding.write(scId);

        // Write length of packet using variable-length encoding
        encoding.write(len);

        // Write the packet number using variable-length encoding (0 bytes)
        encoding.write((int) packetNum);

        return encoding.toByteArray();
    }

    @Nested
    public class EncodeTest {
        @TestFactory
        public Stream<DynamicTest> testValidVersions() {
            return getValidVersions().map(version -> dynamicTest("version = " + version, () -> {
                QuicZeroRTTPacket packet = new QuicZeroRTTPacket("1".getBytes(CHARSET), 1, version, "1".getBytes(CHARSET));
                byte[] encoding = writeBytes(BASE_HEADER_BYTE, version, 1, 1, 1, 1, 1, 1);
                assertEquals(encoding, packet.encode());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testWithFrames() {
            return Stream.of(0, 1, 3, 5, 7, 10).map(numFrames -> dynamicTest("num frames = " + numFrames, () -> {
                QuicZeroRTTPacket packet = new QuicZeroRTTPacket("1".getBytes(CHARSET), 1, CURRENT_VERSION, "1".getBytes(CHARSET));
                for (int i = 0; i < numFrames; i++) {
                    QuicFrame frame = null;
                    if (i % 3 == 0) {
                        frame = new QuicAckFrame(i, i, i, i);
                    } else if (i % 3 == 1) {
                        frame = new QuicCryptoFrame(i, "data".getBytes());
                    } else {
                        frame = new QuicStreamFrame(i, i, false, "data".getBytes());
                    }
                    packet.addFrame(frame);
                }
                Set<QuicFrame> frameSet = packet.getFrames();
                ByteArrayOutputStream frameEncoding = new ByteArrayOutputStream();
                for (QuicFrame frame: frameSet) {
                    frameEncoding.write(frame.encode());
                }
                byte[] encodedFrames = frameEncoding.toByteArray();
                int length = encodedFrames.length * Byte.SIZE + 1;
                // Length uses variable-length encoding
                if (length > 16383 && length < 1073741823) {
                    // Add 10 to first byte of integer
                    length += Math.pow(2, 31);
                } else if (length > 63 && length < 16383) {
                    length += Math.pow(2, 15);
                }
                ByteArrayOutputStream encoding = new ByteArrayOutputStream();
                encoding.write(writeBytes(BASE_HEADER_BYTE, CURRENT_VERSION, 1, 1, 1, 1, length, 1));
                encoding.write(encodedFrames);
                assertEquals(encoding.toByteArray(), packet.encode());
            }));
        }

        @Test
        public void testLongIds() throws IOException {
            QuicZeroRTTPacket packet = new QuicZeroRTTPacket("aaaaaaaaaa".getBytes(CHARSET), 27, CURRENT_VERSION, "8888888888".getBytes(CHARSET));
            ByteArrayOutputStream encoding = new ByteArrayOutputStream();
            encoding.write(BASE_HEADER_BYTE);
            encoding.write(CURRENT_VERSION);
            encoding.write(20);
            for (int i = 0; i < 20; i++) {
                // 10101010 (aa)
                encoding.write(172);
            }
            encoding.write(20);
            for (int i = 0; i < 20; i++) {
                // 10001000 (88)
                encoding.write(144);
            }
            encoding.write(1);
            encoding.write(27);
            assertEquals(encoding.toByteArray(), packet.encode());
        }

        @TestFactory
        public Stream<DynamicTest> testPacketNumbersWithHeader() {
            return Stream.of(1, 2, 3).map(exponent -> dynamicTest("exponent = " + exponent, () -> {
                long packetNum = (long) Math.pow(256, exponent);
                QuicZeroRTTPacket packet = new QuicZeroRTTPacket("1".getBytes(CHARSET), packetNum, CURRENT_VERSION, "1".getBytes(CHARSET));
                byte[] encoding = writeBytes(BASE_HEADER_BYTE + exponent, CURRENT_VERSION, 1, 1, 1, 1, exponent + 1, packetNum);
                assertEquals(encoding, packet.encode());
            }));
        }
    }

    @Nested
    public class DecodeTest {
        @TestFactory
        public Stream<DynamicTest> testValidVersions() {
            return getValidVersions().map(version -> dynamicTest("version = " + version, () -> {
                byte[] encoding = writeBytes(BASE_HEADER_BYTE, version, 1, 1, 1, 1, 1, 1);
                QuicZeroRTTPacket packet = (QuicZeroRTTPacket) QuicPacket.decode(encoding);
                assertEquals("1", packet.getDcID());
                assertEquals("1", packet.getScID());
                assertEquals(1, packet.getPacketNumber());
                assertEquals((long)version, packet.getVersion());
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidHeaderBytes() {
            return Stream.of(0, 100, 223, 228, 255).map(headerByte -> dynamicTest("headerByte = " + headerByte, () -> {
                assertThrows(IOException.class, () -> {
                    byte[] encoding = writeBytes(headerByte, CURRENT_VERSION, 1, 1, 1, 1, 1, 1);
                    QuicPacket packet = QuicPacket.decode(encoding);
                });
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidVersions() {
            return getInvalidVersions().map(version -> dynamicTest("version = " + version, () -> {
                assertThrows(IOException.class, () -> {
                    byte[] encoding = writeBytes(BASE_HEADER_BYTE, version, 1, 1, 1, 1, 1, 1);
                    QuicPacket packet = QuicPacket.decode(encoding);
                });
            }));
        }

        @TestFactory
        public Stream<DynamicTest> testRandomStrings() {
            return Stream.of("", "abc123", "1234567890", "this is a long random string").map(str -> dynamicTest("str = " + str, () -> {
                assertThrows(IOException.class, () -> {
                    byte[] encoding = str.getBytes(CHARSET);
                    QuicPacket packet = QuicPacket.decode(encoding);
                });
            }));
        }
    }

    @TestFactory
    public Stream<DynamicTest> testEqualsAndHashcode() {
        return getValidConnectionIds().flatMap(dcId -> getValidPacketNumbers()
                .flatMap(packetNumber -> getValidVersions().flatMap(version ->
                        getValidConnectionIds().map(scId -> dynamicTest(
                                "dcid = " + dcId + ", packet # = " + packetNumber + ", version = "
                                        + version + ", scid = " + scId, () -> {
                                    QuicZeroRTTPacket packet1 = new QuicZeroRTTPacket(dcId, packetNumber, version, scId);
                                    QuicZeroRTTPacket packet2 = new QuicZeroRTTPacket(dcId, packetNumber, version, scId);
                                    assertEquals(packet1, packet2);
                                    assertEquals(packet1.hashCode(), packet2.hashCode());
                                })))));
    }

    @TestFactory
    public Stream<DynamicTest> testToString() {
        return getValidConnectionIds().flatMap(dcId -> getValidPacketNumbers()
                .flatMap(packetNumber -> getValidVersions().flatMap(version ->
                        getValidConnectionIds().map(scId -> dynamicTest(
                                "dcid = " + dcId + ", packet # = " + packetNumber + ", version = "
                                        + version + ", scid = " + scId, () -> {
                                    QuicZeroRTTPacket packet = new QuicZeroRTTPacket(dcId, packetNumber, version, scId);
                                    assertEquals("QuicZeroRTTPacket{version=" + version + ", scID=" + Arrays.toString(scId) + ", dcID=" + Arrays.toString(dcId) + ", packetNumber=" + packetNumber + ", frames=[]}", packet.toString());
                                })))));
    }
}