using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Threading.Tasks;
using System.Net;
using Sustainsys.Saml2.Saml2P;
using System.Security.Cryptography.X509Certificates;

[Route("Saml2")]
public class Saml2Controller : Controller
{
    [HttpPost("ProxyAcs")]
    public async Task<IActionResult> CustomAcs()
    {
        ////var samlResponseBase64 = Request.Form["SAMLResponse"];
        ////var relayState = Request.Form["RelayState"];

        ////if (string.IsNullOrEmpty(samlResponseBase64))
        ////{
        ////    return BadRequest("SAML Response is missing.");
        ////}

        ////string targetAcsUrl = "https://localhost:7191/Saml2/Acs";

        ////////return Redirect($"{targetAcsUrl}?SAMLResponse={Uri.EscapeDataString(samlResponseBase64)}");

        ////// Build a simple HTML form that auto-submits
        ////string htmlForm = $@"
        ////<html>
        ////    <body onload='document.forms[0].submit();'>
        ////        <form action='{targetAcsUrl}' method='post'>
        ////            <input type='hidden' name='SAMLResponse' value='{samlResponseBase64}' />
        ////            <input type='hidden' name='RelayState' value='{relayState}' />
        ////            <noscript><input type='submit' value='Continue'></noscript>
        ////        </form>
        ////    </body>
        ////</html>";

        ////return Content(htmlForm, "text/html");
        ///

        var samlResponseBase64 = Request.Form["SAMLResponse"];
        var relayState = Request.Form["RelayState"];

        if (string.IsNullOrEmpty(samlResponseBase64))
        {
            return BadRequest("SAML Response is missing.");
        }

        // 1. Decode the SAML Response
        string samlXml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponseBase64));

        // 2. Modify the SAML Assertion to add a custom claim
        string modifiedSamlXml = AddCustomClaimToSAMLResponse(samlXml, "accountNumbers123", "123456,789012");

        // 3. Re-encode the modified XML
        string newSamlResponseBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(modifiedSamlXml));

        // 4. Forward the modified response to the final ACS
        string targetAcsUrl = "https://localhost:7191/Saml2/Acs";

        string htmlForm = $@"
        <html>
            <body onload='document.forms[0].submit();'>
                <form action='{targetAcsUrl}' method='post'>
                    <input type='hidden' name='SAMLResponse' value='{newSamlResponseBase64}' />
                    <input type='hidden' name='RelayState' value='{relayState}' />
                    <noscript><input type='submit' value='Continue'></noscript>
                </form>
            </body>
        </html>";

        return Content(htmlForm, "text/html");

        //try
        //{
        //    // 1. Extract the SAML Response from the HTTP POST request
        //    var samlResponseBase64 = Request.Form["SAMLResponse"];
        //    if (string.IsNullOrEmpty(samlResponseBase64))
        //    {
        //        return BadRequest("SAML Response is missing.");
        //    }

        //    // 2. Decode the Base64 response
        //    var samlXml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponseBase64));

        //    // 3. Load SAML XML into an XmlDocument
        //    var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        //    xmlDoc.LoadXml(samlXml);

        //    // 4. Validate the SAML Response (Signature, Conditions, etc.)
        //    if (!ValidateSamlResponse(xmlDoc))
        //    {
        //        return BadRequest("Invalid SAML Response.");
        //    }

        //    // 5. Extract user claims
        //    var claims = ExtractUserClaims(xmlDoc);

        //    // 6. Authenticate the user in the app
        //    var claimsIdentity = new System.Security.Claims.ClaimsIdentity(claims, "SAML");
        //    var claimsPrincipal = new System.Security.Claims.ClaimsPrincipal(claimsIdentity);

        //    await HttpContext.SignInAsync(claimsPrincipal);

        //    var destinationUrl = "https://localhost:7191/Saml2/Acs";

        //    // 7. Redirect user to the homepage after login
        //    var samlForm = $@"
        //    <html>
        //    <body onload='document.forms[0].submit();'>
        //        <form method='POST' action='{destinationUrl}'>
        //            <input type='hidden' name='SAMLResponse' value='{HtmlEncode(samlResponseBase64)}'/>
        //            <input type='submit' value='Continue' />
        //        </form>
        //    </body>
        //    </html>";

        //    return Content(samlForm, "text/html");
        //}
        //catch (Exception ex)
        //{
        //    return BadRequest($"SAML Processing Error: {ex.Message}");
        //}
    }

    public static string AddCustomClaimToSAMLResponse(string samlXml, string claimName, string claimValue)
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.LoadXml(samlXml);

        XmlNamespaceManager nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
        nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        // Find the AttributeStatement node where claims are stored
        XmlNode attributeStatement = xmlDoc.SelectSingleNode("//saml:Assertion/saml:AttributeStatement", nsManager);

        if (attributeStatement == null)
        {
            // Create AttributeStatement if it doesn't exist
            XmlNode assertionNode = xmlDoc.SelectSingleNode("//saml:Assertion", nsManager);
            if (assertionNode != null)
            {
                attributeStatement = xmlDoc.CreateElement("saml", "AttributeStatement", "urn:oasis:names:tc:SAML:2.0:assertion");
                assertionNode.AppendChild(attributeStatement);
            }
        }

        if (attributeStatement != null)
        {
            // Create new Attribute for the custom claim
            XmlElement newAttribute = xmlDoc.CreateElement("saml", "Attribute", "urn:oasis:names:tc:SAML:2.0:assertion");
            newAttribute.SetAttribute("Name", claimName);

            XmlElement attributeValue = xmlDoc.CreateElement("saml", "AttributeValue", "urn:oasis:names:tc:SAML:2.0:assertion");
            attributeValue.InnerText = claimValue;
            newAttribute.AppendChild(attributeValue);

            // Append new claim to AttributeStatement
            attributeStatement.AppendChild(newAttribute);
        }

        string certPath = "saml-sp-certificate.pfx";
        string certPassword = "your_password";

        SignSAMLResponse(xmlDoc, certPath, certPassword);

        return xmlDoc.OuterXml;
    }

    public static void SignSAMLResponse(XmlDocument samlDoc, string certificatePath, string certificatePassword)
    {
        // Load the certificate with private key
        var cert = new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.MachineKeySet);
        var rsaKey = cert.GetRSAPrivateKey();

        XmlNamespaceManager nsManager = new XmlNamespaceManager(samlDoc.NameTable);
        nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

        // Locate the Assertion element
        XmlElement assertionElement = samlDoc.SelectSingleNode("//saml:Assertion", nsManager) as XmlElement;
        if (assertionElement == null) throw new Exception("SAML Assertion not found.");

        // Ensure Assertion has an ID (Required for Reference)
        if (!assertionElement.HasAttribute("ID"))
        {
            throw new Exception("SAML Assertion is missing the ID attribute.");
        }
        string assertionId = assertionElement.GetAttribute("ID");

        // 🔴 Ensure no previous signatures exist before signing
        XmlNode oldSignatureNode = assertionElement.SelectSingleNode("ds:Signature", nsManager);
        if (oldSignatureNode != null)
        {
            assertionElement.RemoveChild(oldSignatureNode);
        }

        // Create SignedXml object
        SignedXml signedXml = new SignedXml(assertionElement);
        signedXml.SigningKey = rsaKey;

        // Reference the Assertion ID
        Reference reference = new Reference
        {
            Uri = "#" + assertionId,
            DigestMethod = SignedXml.XmlDsigSHA256Url
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());

        // Add KeyInfo with X509 Certificate
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));

        // Compute the signature
        signedXml.AddReference(reference);
        signedXml.KeyInfo = keyInfo;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.ComputeSignature();

        // 🔹 Insert the new signature **directly after the <saml:Issuer>**
        XmlElement xmlDigitalSignature = signedXml.GetXml();
        XmlNode issuerNode = assertionElement.SelectSingleNode("saml:Issuer", nsManager);
        assertionElement.InsertAfter(xmlDigitalSignature, issuerNode);
    }


    private string HtmlEncode(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

    private bool ValidateSamlResponse(XmlDocument samlResponse)
    {
        // Implement signature validation and condition checks here
        return true; // For now, assume it's valid. Implement actual verification.
    }

    private System.Collections.Generic.List<System.Security.Claims.Claim> ExtractUserClaims(XmlDocument xmlDoc)
    {
        var claims = new System.Collections.Generic.List<System.Security.Claims.Claim>();

        XmlNamespaceManager nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
        nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        var nameIdNode = xmlDoc.SelectSingleNode("//saml:Subject/saml:NameID", nsManager);
        if (nameIdNode != null)
        {
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, nameIdNode.InnerText));
        }

        var attributeNodes = xmlDoc.SelectNodes("//saml:AttributeStatement/saml:Attribute", nsManager);
        foreach (XmlNode attribute in attributeNodes)
        {
            var attributeName = attribute.Attributes["Name"].Value;
            var attributeValue = attribute.InnerText;
            claims.Add(new System.Security.Claims.Claim(attributeName, attributeValue));
        }

        return claims;
    }
}
