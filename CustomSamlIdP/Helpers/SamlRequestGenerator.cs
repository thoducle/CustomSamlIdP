using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml;

public class SamlRequestGenerator
{
    public static string GenerateSamlRequest(string destinationUrl, string entityId)
    {
        string requestId = "_" + Guid.NewGuid().ToString();
        string issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        string samlRequest = $@"
        <samlp:AuthnRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='{requestId}' Version='2.0' IssueInstant='{issueInstant}' Destination='{destinationUrl}' ForceAuthn='false' IsPassive='false'>
            <saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>{entityId}</saml:Issuer>
            <samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' />
            <samlp:RequestedAuthnContext Comparison='exact'>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>";

        return CompressAndEncodeSamlRequest(samlRequest);
    }

    private static string CompressAndEncodeSamlRequest(string samlRequest)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(samlRequest);

        using (var output = new MemoryStream())
        {
            using (var compressor = new DeflateStream(output, CompressionMode.Compress, true))
            {
                compressor.Write(bytes, 0, bytes.Length);
            }
            return Convert.ToBase64String(output.ToArray());
        }
    }
}
