package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.*;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.ocsp.OCSPException;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.ncanode.dto.cms.CmsSignerInfo;
import kz.ncanode.dto.ocsp.OcspWrapper;
import kz.ncanode.dto.request.CmsCreateRequest;
import kz.ncanode.dto.request.CmsCreateRequestESEDO;
import kz.ncanode.dto.request.SignerRequest;
import kz.ncanode.dto.response.CmsDataResponse;
import kz.ncanode.dto.response.CmsResponse;
import kz.ncanode.dto.response.CmsVerificationResponse;
import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.dto.tsp.TspInfo;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class CmsService {
    public static final String OID_SIGNED_FILE_NAMES = "1.2.840.113549.1.9.77";
    public static final String OID_DN_NAME = "1.3.6.1.4.1.6801.2.8";

    private final KalkanWrapper kalkanWrapper;
    private final TspService tspService;
    private final  CertificateService certificateService;


    /**
     * Создает подписанный CMS
     *
     * @param cmsCreateRequest
     * @return
     */
    public CmsResponse create(CmsCreateRequest cmsCreateRequest) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            val data = Base64.getDecoder().decode(cmsCreateRequest.getData());

            CMSProcessable cmsData = new CMSProcessableByteArray(data);
            List<X509Certificate> certificates = new ArrayList<>();

            addSignersToCmsGenerator(generator, data, certificates, cmsCreateRequest.getSigners());

            CertStore chainStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                    // если происходит повторная подпись, сертификаты могут дублироваться.
                    // добавим в chainStore только уникальные сертификаты.
                    certificates
                ),
                KalkanProvider.PROVIDER_NAME
            );

            generator.addCertificatesAndCRLs(chainStore);
            CMSSignedData signed = generator.generate(cmsData, !cmsCreateRequest.isDetached(), KalkanProvider.PROVIDER_NAME);

            // TSP
            if (cmsCreateRequest.isWithTsp()) {
                String useTsaPolicy = Optional.ofNullable(cmsCreateRequest.getTsaPolicy()).map(TsaPolicy::getPolicyId)
                    .orElse(TsaPolicy.TSA_GOST_POLICY.getPolicyId());

                SignerInformationStore signerStore = signed.getSignerInfos();
                List<SignerInformation> signers = new ArrayList<>();

                int i = 0;

                for (Object signer : signerStore.getSigners()) {
                    X509Certificate cert = certificates.get(i++);
                    signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, useTsaPolicy));
                }

                signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(signers));
            }

            return CmsResponse.builder()
                .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                .build();
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }
    public CmsResponse create(CmsCreateRequestESEDO cmsCreateRequestESEDO) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            val data = Base64.getDecoder().decode(cmsCreateRequestESEDO.getData());

            CMSProcessable cmsData = new CMSProcessableByteArray(data);
            X509Certificate certificate;

            //addSignersToCmsGeneratorESEDO(generator, data, certificate, cmsCreateRequestESEDO.getSigner());
            List<SignerRequest> signerAlone = new ArrayList<>();
            signerAlone.add(cmsCreateRequestESEDO.getSigner());
            KeyStoreWrapper ks = kalkanWrapper.read(signerAlone).get(0);
            CertificateWrapper cert = ks.getCertificate();
            val privateKey = ks.getPrivateKey();
            certificate = cert.getX509Certificate();
            OcspWrapper ocspWrapper = certificateService.getOcsp(certificate);
            if(ocspWrapper.isOk()) {


                ASN1EncodableVector attr = new ASN1EncodableVector();
                MessageDigest messageDigest = MessageDigest.getInstance("GOST3411", KalkanProvider.PROVIDER_NAME);
                messageDigest.reset();

                byte[] hash = messageDigest.digest(data);
                attr.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new DERSet(new DEROctetString(hash))));
                Date currentDate = new Date();
                Attribute signTimeAttribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new DERSet(new DERGeneralizedTime(currentDate)));
                attr.add(signTimeAttribute);

                if (cmsCreateRequestESEDO.getSignFileNames() != null) {
                    attr.add(new Attribute(new DERObjectIdentifier(OID_SIGNED_FILE_NAMES), new DERSet(new DERUTF8String(cmsCreateRequestESEDO.getSignFileNames()))));
                }
                if (ocspWrapper.getResponse() != null) {
                    attr.add(new Attribute(OCSPObjectIdentifiers.id_pkix_ocsp_basic, new DERSet(new DEROctetString(ocspWrapper.getResponse()))));
                }
                attr.add(new Attribute(new DERObjectIdentifier(OID_DN_NAME), new DERSet(new X509Name(certificate.getSubjectDN().getName()))));
                attr.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType, new DERSet(PKCSObjectIdentifiers.data)));
                String descStr = "ESEDO";
                byte[] descr = descStr.getBytes(StandardCharsets.UTF_8);

                attr.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingDescription, new DERSet(new DERPrintableString(descr))));
                AttributeTable attributeTable = new AttributeTable(attr);
                CertStore chainStore = CertStore.getInstance(
                    "Collection",
                    new CollectionCertStoreParameters(
                        // если происходит повторная подпись, сертификаты могут дублироваться.
                        // добавим в chainStore только уникальные сертификаты.
                        Arrays.asList(certificate)
                    ),
                    KalkanProvider.PROVIDER_NAME
                );
                generator.addSigner(privateKey, certificate, Util.getDigestAlgorithmOidBYSignAlgorithmOidESEDO(certificate.getSigAlgOID()),attributeTable, null);
                generator.addCertificatesAndCRLs(chainStore);
                CMSSignedData signed = generator.generate(cmsData, !cmsCreateRequestESEDO.isDetached(), KalkanProvider.PROVIDER_NAME);

                // TSP
                if (cmsCreateRequestESEDO.isWithTsp()) {
                    String useTsaPolicy = Optional.ofNullable(cmsCreateRequestESEDO.getTsaPolicy()).map(TsaPolicy::getPolicyId)
                        .orElse(TsaPolicy.TSA_GOST_POLICY.getPolicyId());

                    SignerInformationStore signerStore = signed.getSignerInfos();
                    Collection ss = signerStore.getSigners();
                    SignerInformation si = (SignerInformation) ss.iterator().next();

                    si = tspService.addTspToSigner( si, certificate, useTsaPolicy);
                    ss.clear();
                    ss.add(si);

                    signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(ss));
                }

                return CmsResponse.builder()
                    .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                    .build();
            }else{
                throw new OCSPException(ocspWrapper.getReport());
            }
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Добавляет подписи уже в существующий CMS
     *
     * @param cmsCreateRequest
     * @return
     */
    public CmsResponse addSigners(CmsCreateRequest cmsCreateRequest) {
        try {
            if (cmsCreateRequest.getCms() == null || cmsCreateRequest.getCms().isEmpty()) {
                throw new ClientException("CMS argument not specified");
            }

            val decodedCms = Base64.getDecoder().decode(cmsCreateRequest.getCms());

            var cms = new CMSSignedData(decodedCms);
            byte[] decodedData = null;

            if (cms.getSignedContent() == null) {
                if (cmsCreateRequest.getData() == null || cmsCreateRequest.getData().isEmpty()) {
                    throw new ClientException("Data must be specifieed for detached CMS");
                }

                decodedData = Base64.getDecoder().decode(cmsCreateRequest.getData());

                cms = new CMSSignedData(new CMSProcessableByteArray(decodedData), decodedCms);
            } else {
                try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                    cms.getSignedContent().write(out);
                    decodedData = out.toByteArray();
                }
            }

            CMSProcessable cmsData = new CMSProcessableByteArray(decodedData);

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSigners(cms.getSignerInfos());

            val certificates = getCertificatesFromCmsSignedData(cms);

            addSignersToCmsGenerator(generator, decodedData, certificates, cmsCreateRequest.getSigners());

            CertStore chainStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                    certificates.stream().distinct().collect(Collectors.toList())
                ),
                KalkanProvider.PROVIDER_NAME
            );
            generator.addCertificatesAndCRLs(chainStore);
            CMSSignedData signed = generator.generate(cmsData, !cmsCreateRequest.isDetached(), KalkanProvider.PROVIDER_NAME);

            // TSP
            if (cmsCreateRequest.isWithTsp()) {
                String useTsaPolicy = Optional.ofNullable(cmsCreateRequest.getTsaPolicy()).map(TsaPolicy::getPolicyId)
                    .orElse(TsaPolicy.TSA_GOST_POLICY.getPolicyId());

                SignerInformationStore signerStore = signed.getSignerInfos();
                List<SignerInformation> signers = new ArrayList<>();

                int i = 0;

                for (Object signer : signerStore.getSigners()) {
                    X509Certificate cert = certificates.get(i++);
                    signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, useTsaPolicy));
                }

                signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(signers));
            }

            return CmsResponse.builder()
                .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                .build();
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Проверяет подписанный CMS
     *
     * @param signedCms
     * @param detachedData
     * @param checkOcsp
     * @param checkCrl
     * @return
     */
    public CmsVerificationResponse verify(String signedCms, String detachedData, boolean checkOcsp, boolean checkCrl) {
        try {
            CMSSignedData cms = new CMSSignedData(Base64.getDecoder().decode(signedCms.getBytes(StandardCharsets.UTF_8)));

            if (detachedData != null && cms.getSignedContent() == null) {
                cms = new CMSSignedData(new CMSProcessableByteArray(Base64.getDecoder().decode(detachedData)),
                    Base64.getDecoder().decode(signedCms));
            }

            CertStore certStore = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            val signerIt = cms.getSignerInfos().getSigners().iterator();

            final List<CmsSignerInfo> signers = new ArrayList<>();

            boolean valid = true;

            val currentDate = certificateService.getCurrentDate();

            while (signerIt.hasNext()) {
                var signerInfoBuilder = CmsSignerInfo.builder();

                var signer = (SignerInformation) signerIt.next();
                X509CertSelector signerConstraints = signer.getSID();
                var certCollection = certStore.getCertificates(signerConstraints);

                var certIt = certCollection.iterator();

                while (certIt.hasNext()) {
                    CertificateWrapper cert = new CertificateWrapper((X509Certificate) certIt.next());

                    certificateService.attachValidationData(cert, checkOcsp, checkCrl);

                    if (!signer.verify(cert.getPublicKey(), KalkanProvider.PROVIDER_NAME) || !cert.isValid(currentDate, checkOcsp, checkCrl)) {
                        valid = false;
                    }

                    signerInfoBuilder.certificate(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl));
                }

                // TSP Checking
                if (signer.getUnsignedAttributes() != null) {
                    var attrs = signer.getUnsignedAttributes().toHashtable();

                    if (attrs.containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
                        Attribute attr = (Attribute) attrs.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);


                        if (attr.getAttrValues().size() != 1) {
                            throw new Exception("Too many TSP tokens");
                        }

                        CMSSignedData tspCms = new CMSSignedData(attr.getAttrValues().getObjectAt(0).getDERObject().getEncoded());
                        TimeStampTokenInfo tspi = tspService.info(tspCms).orElseThrow();

                        try {
                            TspInfo tspInfo = TspInfo.builder()
                                .serialNumber(new String(Hex.encode(tspi.getSerialNumber().toByteArray())))
                                .genTime(tspi.getGenTime())
                                .policy(tspi.getPolicy())
                                .tsa(Optional.ofNullable(tspi.getTsa()).map(Object::toString).orElse(null))
                                .tspHashAlgorithm(KalkanUtil.getHashingAlgorithmByOID(tspi.getMessageImprintAlgOID()))
                                .hash(new String(Hex.encode(tspi.getMessageImprintDigest())))
                                .build();

                            signerInfoBuilder.tsp(tspInfo);
                        } catch (Exception e) {
                            log.warn(e.getMessage(), e);
                        }

                    }
                }

                signers.add(signerInfoBuilder.build());
            }

            return CmsVerificationResponse.builder()
                .valid(valid)
                .signers(signers)
                .build();
        } catch (Exception e) {
            throw new ClientException(e.getMessage(), e);
        }
    }

    /**
     * Извлекает данные из CMS если они есть
     *
     * @param signedCms
     * @return
     */
    public CmsDataResponse extract(String signedCms) {
        try {
            val cms = new CMSSignedData(Base64.getDecoder().decode(signedCms));

            if (cms.getSignedContent() == null) {
                throw new ClientException("CMS doesn't have signed content");
            }

            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                cms.getSignedContent().write(out);
                return CmsDataResponse.builder()
                    .data(Base64.getEncoder().encodeToString(out.toByteArray()))
                    .build();
            }
        } catch (CMSException|IOException e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    private List<X509Certificate> getCertificatesFromCmsSignedData(CMSSignedData cms) throws
        NoSuchAlgorithmException,
        NoSuchProviderException,
        CMSException,
        CertStoreException
    {
        List<X509Certificate> certs = new ArrayList<>();
        SignerInformationStore signers = cms.getSignerInfos();
        CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);

        for (var signerObj : signers.getSigners()) {
            SignerInformation signer = (SignerInformation) signerObj;
            X509CertSelector signerConstraints = signer.getSID();
            Collection<? extends Certificate> certCollection = clientCerts.getCertificates(signerConstraints);

            for (Certificate certificate : certCollection) {
                X509Certificate cert = (X509Certificate) certificate;
                certs.add(cert);
            }
        }

        return certs;
    }

    private void addSignersToCmsGenerator(CMSSignedDataGenerator generator, byte[] decodedData, List<X509Certificate> certificates, List<SignerRequest> signers) {
        try {
            for (KeyStoreWrapper ks : kalkanWrapper.read(signers)) {
                CertificateWrapper cert = ks.getCertificate();
                val privateKey = ks.getPrivateKey();

                Signature sig = Signature.getInstance(cert.getX509Certificate().getSigAlgName(), kalkanWrapper.getKalkanProvider());
                sig.initSign(privateKey);
                sig.update(decodedData);

                generator.addSigner(privateKey, cert.getX509Certificate(), Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getX509Certificate().getSigAlgOID()));
                certificates.add(cert.getX509Certificate());
            }
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }
    private void addSignersToCmsGeneratorESEDO(CMSSignedDataGenerator generator, byte[] decodedData, X509Certificate certificate, SignerRequest signer) {
        try {


        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }
}
