package kz.ncanode.dto.ocsp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;

/**
 * @author Admin on 02.10.2023
 * @project NCANode
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class OcspWrapper {
    private boolean isOk;
    private byte[] response;
    private String report;

    @Override
    public String toString() {
        return "OCSPWrapper{" +
                "isOk=" + isOk +
                ", response=" + Arrays.toString(response) +
                ", report='" + report + '\'' +
                '}';
    }
}
