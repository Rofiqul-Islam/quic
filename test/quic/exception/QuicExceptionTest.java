package quic.exception;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestFactory;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

public class QuicExceptionTest {
    // QUIC error codes range from 0x0 to 0x1FF (8191), not including 0xC, 0xE, and 0xF
    Stream<Integer> getValidErrorCodes() {
        return Stream.of(0, 1, 11, 13, 16, 234, 8191);
    }

    Stream<Integer> getInvalidErrorCodes() {
        return Stream.of(-1, 12, 14, 15, 8192, Integer.MIN_VALUE, Integer.MAX_VALUE);
    }

    // The valid QUIC frame types range from 0x0 to 0x1E (30)
    Stream<Integer> getValidFrameTypes() {
        return Stream.of(0, 1, 3, 23, 30);
    }

    Stream<Integer> getInvalidFrameTypes() {
        return Stream.of(-1, 31, 234634, Integer.MIN_VALUE, Integer.MAX_VALUE);
    }

    Stream<String> getValidMessages() {
        return Stream.of(null, "", "e", "error", "this is an error message", "$pec!@l čh@rĀct#rs");
    }

    @Nested
    public class ConstructorTest {
        @TestFactory
        public Stream<DynamicTest> testValidQuicErrors() {
            return getValidErrorCodes().flatMap(errorCode -> getValidFrameTypes()
                    .flatMap(frameType -> getValidMessages().map(message ->
                            dynamicTest("error code: " + errorCode + ", frame type = " +
                                    frameType + ", message = " + message, () -> {
                                QuicException frame =
                                        new QuicException(errorCode, frameType, message);
                                assertEquals(errorCode, frame.getErrorCode());
                                assertEquals(frameType, frame.getFrameType());
                                assertEquals(message, frame.getMessage());
                            }))));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidErrorCode() {
            return getInvalidErrorCodes().map(errorCode ->
                    dynamicTest("error code: " + errorCode, () -> {
                        assertThrows(IllegalArgumentException.class, () -> {
                            QuicException frame = new QuicException(errorCode, 0, "message");
                        });
                    }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidFrameType() {
            return getInvalidFrameTypes().map(frameType ->
                    dynamicTest("frame type: " + frameType, () -> {
                        assertThrows(IllegalArgumentException.class, () -> {
                            QuicException frame = new QuicException(0, frameType, "message");
                        });
                    }));
        }
    }

    @Nested
    public class GettersAndSettersTest {
        private QuicException frame;

        @BeforeEach
        public void init() {
            this.frame = new QuicException(0, 0, "message");
        }

        @TestFactory
        public Stream<DynamicTest> testValidQuicErrorCodes() {
            return getValidErrorCodes().map(errorCode -> dynamicTest("error code: " + errorCode,
                    () -> {
                        this.frame.setErrorCode(errorCode);
                        assertEquals(errorCode, this.frame.getErrorCode());
                    }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidQuicErrorCodes() {
            return getInvalidErrorCodes().map(errorCode -> dynamicTest("error code: " + errorCode,
                    () -> {
                        this.frame.setErrorCode(errorCode);
                        assertEquals(errorCode, this.frame.getErrorCode());
                    }));
        }

        @TestFactory
        public Stream<DynamicTest> testValidFrameTypes() {
            return getValidFrameTypes().map(frameType -> dynamicTest("frame type: " + frameType,
                    () -> {
                        this.frame.setFrameType(frameType);
                        assertEquals(frameType, this.frame.getFrameType());
                    }));
        }

        @TestFactory
        public Stream<DynamicTest> testInvalidFrameTypes() {
            return getInvalidFrameTypes().map(frameType -> dynamicTest("frame type: " + frameType,
                    () -> {
                        this.frame.setFrameType(frameType);
                        assertEquals(frameType, this.frame.getFrameType());
                    }));
        }

        @TestFactory
        public Stream<DynamicTest> testValidMessages() {
            return getValidMessages().map(message -> dynamicTest("message: " + message,
                    () -> {
                        this.frame.setMessage(message);
                        assertEquals(message, this.frame.getMessage());
                    }));
        }
    }

    @TestFactory
    public Stream<DynamicTest> testEqualsAndHashcode() {
        return getValidErrorCodes().flatMap(errorCode -> getValidFrameTypes().flatMap(frameType ->
                        getValidMessages().map(message -> dynamicTest("code: "
                                + errorCode + ", frame type: " + frameType + ", message: " + message, () -> {
                            QuicException frame1 = new QuicException(errorCode, frameType, message);
                            QuicException frame2 = new QuicException(errorCode, frameType, message);
                            assertEquals(frame1, frame2);
                            assertEquals(frame1.hashCode(), frame2.hashCode());
                        }))));
    }

    @TestFactory
    public Stream<DynamicTest> testToString() {
        return getValidErrorCodes()
                .flatMap(errorCode -> getValidFrameTypes().flatMap(frameType ->
                        getValidMessages().map(message -> dynamicTest("code: "
                                + errorCode + ", frame type: " + frameType + ", message: " + message, () -> {
                            QuicException frame = new QuicException(errorCode, frameType, message);
                            assertEquals("QuicException: [code: " + errorCode + ", frameType: " + frameType + ", message: " + message, frame.toString());
                        }))));
    }
}
