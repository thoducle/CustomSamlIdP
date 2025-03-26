using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

public class SamlAssertionGenerator
{
    public static string GenerateSamlResponse(
        string userEmail,
        string entityId,
        string destinationUrl,
        string certPath,
        string certPassword,
        string accountNumber)
    {
        string responseId = "_" + Guid.NewGuid().ToString();
        string assertionId = "_" + Guid.NewGuid().ToString();
        string issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        string samlAssertion = $@"
        <saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='{assertionId}' IssueInstant='{issueInstant}' Version='2.0'>
            <saml:Issuer>{entityId}</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'>{userEmail}</saml:NameID>
                <saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>
                    <saml:SubjectConfirmationData NotOnOrAfter='{DateTime.UtcNow.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}' Recipient='{destinationUrl}' />
                </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore='{issueInstant}' NotOnOrAfter='{DateTime.UtcNow.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}'>
                <saml:AudienceRestriction>
                    <saml:Audience>{destinationUrl}</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AttributeStatement>
                <saml:Attribute Name='email'>
                    <saml:AttributeValue>{userEmail}</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name='accountNumbers'>
                    <saml:AttributeValue>{accountNumber}</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
            <saml:AuthnStatement AuthnInstant='{issueInstant}'>
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
        </saml:Assertion>";

        // 🔹 Wrap the Assertion inside a valid SAML Response
        string samlResponse = $@"
        <samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='{responseId}' Version='2.0' IssueInstant='{issueInstant}' Destination='{destinationUrl}' InResponseTo='{responseId}'>
            <saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>{entityId}</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>
            </samlp:Status>
            {samlAssertion}
        </samlp:Response>";

        // Convert to XML and sign it
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.LoadXml(samlResponse);

        return SignSamlResponse(xmlDoc, certPath, certPassword);
    }

    private static string SignSamlResponse(XmlDocument samlResponse, string certPath, string certPassword)
    {
        var cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.MachineKeySet);
        var privateKey = cert.GetRSAPrivateKey();

        var signedXml = new SignedXml(samlResponse);
        signedXml.SigningKey = privateKey;

        var reference = new Reference("");
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();

        XmlElement xmlDigitalSignature = signedXml.GetXml();
        samlResponse.DocumentElement.AppendChild(samlResponse.ImportNode(xmlDigitalSignature, true));

        return samlResponse.OuterXml;
    }
}
