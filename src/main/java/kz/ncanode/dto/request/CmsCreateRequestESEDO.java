package kz.ncanode.dto.request;

import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * @author Admin on 29.09.2023
 * @project NCANode
 */
@Data
public class CmsCreateRequestESEDO {

    private String data;

    @NotNull
    private SignerRequest signer;

    private boolean withTsp = true;

    private boolean withOcsp = true;
    @NotEmpty
    private String signFileNames;

    private TsaPolicy tsaPolicy;

    private boolean detached = true;
}
